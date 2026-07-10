"""
lift.py — ARMv4T (ARM + Thumb) -> C static recompiler.

Ported from ngagerecomp. Reads functions.json (functions + segment bytes from
extract.py), decodes each function with Capstone, and emits one C function per
guest function operating on `nk_cpu_t` (see runtime/include/nokia_cpu.h, nokia_rt.h).

Thumb-aware (the DCT4 Series 40 firmware is Thumb): PC reads as addr+4 in Thumb
vs addr+8 in ARM, literal pools are word-aligned in Thumb, and Thumb functions are
decoded linearly by instruction size (2 or 4 bytes) rather than a fixed 4.

    py lift.py functions.json --func func_01234abc [--out out.c]
    py lift.py functions.json --addr 0x1234abc
    py lift.py functions.json --all --out generated.c
"""
import json, sys, argparse
from capstone import (Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB,
                      CS_MODE_LITTLE_ENDIAN, CS_GRP_JUMP, CS_GRP_CALL)
from capstone.arm import (ARM_OP_REG, ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC,
                          ARM_REG_LR, ARM_SFT_LSL, ARM_SFT_LSR, ARM_SFT_ASR,
                          ARM_SFT_ROR, ARM_SFT_LSL_REG, ARM_SFT_LSR_REG,
                          ARM_SFT_ASR_REG, ARM_SFT_ROR_REG)

CC = {
    1:  "nk_zf(c)", 2:  "!nk_zf(c)", 3:  "nk_cf(c)", 4:  "!nk_cf(c)",
    5:  "nk_nf(c)", 6:  "!nk_nf(c)", 7:  "nk_vf(c)", 8:  "!nk_vf(c)",
    9:  "(nk_cf(c) && !nk_zf(c))", 10: "(!nk_cf(c) || nk_zf(c))",
    11: "(nk_nf(c) == nk_vf(c))",  12: "(nk_nf(c) != nk_vf(c))",
    13: "(!nk_zf(c) && nk_nf(c) == nk_vf(c))", 14: "(nk_zf(c) || nk_nf(c) != nk_vf(c))",
}
CC_SUFFIX = {"eq","ne","cs","hs","cc","lo","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","al"}


class Unsupported(Exception):
    pass


_REG_NUM = {"sp": 13, "lr": 14, "pc": 15, "ip": 12, "fp": 11, "sl": 10, "sb": 9}


def regnum(name):
    if name in _REG_NUM: return _REG_NUM[name]
    if name and name[0] == "r":
        try: return int(name[1:])
        except ValueError: return None
    return None


class Mem:
    def __init__(self, segments):
        self.segs = [(s["start"], s["end"], bytes.fromhex(s["bytes"])) for s in segments]
    def r32(self, va):
        for start, end, data in self.segs:
            if start <= va and va + 4 <= end:
                o = va - start
                return int.from_bytes(data[o:o+4], "little")
        return None


class Lifter:
    def __init__(self, mem):
        self.mem = mem
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN); self.md.detail = True
        self.md_t = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN); self.md_t.detail = True
        self.stats = {"insns": 0, "lifted": 0, "stubbed": 0}
        self.thumb = False
        self._call_continue = set()
        self._jumptables = {}

    # PC reads: Thumb = addr+4, ARM = addr+8.
    def _pc_read(self, pc): return pc + (4 if self.thumb else 8)

    def reg(self, ins, rid, pc):
        if rid == ARM_REG_PC:
            return f"{self._pc_read(pc):#x}u"
        name = ins.reg_name(rid); n = regnum(name)
        if n is None: raise Unsupported()
        return f"c->r[{n}]"

    def src(self, ins, op, pc):
        if op.type == ARM_OP_IMM:
            return f"{op.imm & 0xffffffff:#x}u"
        if op.type == ARM_OP_REG:
            base = self.reg(ins, op.reg, pc)
            st, sv = op.shift.type, op.shift.value
            if st and sv:
                # ARM encodes LSR/ASR #32 (shift-by-32); C shifts by >= width are UB.
                if st == ARM_SFT_LSL: return f"({base} << {sv})" if sv < 32 else "0u"
                if st == ARM_SFT_LSR: return f"({base} >> {sv})" if sv < 32 else "0u"
                if st == ARM_SFT_ASR: return f"((uint32_t)((int32_t){base} >> {sv if sv < 32 else 31}))"
                if st == ARM_SFT_ROR: return f"(({base} >> {sv}) | ({base} << {32 - sv}))" if sv else base
                rs = {ARM_SFT_LSL_REG: "nk_lsl", ARM_SFT_LSR_REG: "nk_lsr",
                      ARM_SFT_ASR_REG: "nk_asr", ARM_SFT_ROR_REG: "nk_ror"}.get(st)
                if rs: return f"{rs}({base}, {self.reg(ins, sv, pc)})"
                raise Unsupported()
            return base
        raise Unsupported()

    @staticmethod
    def _guard(cc, stmt):
        return f"if ({CC[cc]}) {{ {stmt} }}" if cc else stmt

    def _reglist(self, ins, ops):
        out = [(regnum(ins.reg_name(op.reg)), ins.reg_name(op.reg)) for op in ops]
        out.sort(key=lambda x: (x[0] is None, x[0]))
        return out

    def emit(self, ins, next_addr, headset):
        self.stats["insns"] += 1
        cc = ins.cc if ins.cc in CC else None
        m = ins.mnemonic; base = m.split('.')[0]
        cmt = f"  // {m} {ins.op_str}"

        if ins.group(CS_GRP_CALL):
            op = ins.operands[0]
            setlr = f"c->r[14] = {next_addr:#x}u; "
            tgt = (f"{op.imm & 0xffffffff:#x}u" if op.type == ARM_OP_IMM
                   else self.reg(ins, op.reg, ins.address))
            self.stats["lifted"] += 1
            return "    " + self._guard(cc, f"{setlr}nk_call(c, {tgt});") + cmt

        if ins.group(CS_GRP_JUMP):
            op = ins.operands[0]
            if op.type == ARM_OP_REG:
                if op.reg == ARM_REG_LR: stmt = "return;"
                elif ins.address in self._call_continue:
                    stmt = f"nk_call(c, {self.reg(ins, op.reg, ins.address)});"
                else:
                    stmt = f"nk_call(c, {self.reg(ins, op.reg, ins.address)}); return;"
            else:
                tgt = op.imm & 0xffffffff
                stmt = (f"goto L_{tgt:08x};" if tgt in headset
                        else f"nk_call(c, {tgt:#x}u); return;")
            self.stats["lifted"] += 1
            return "    " + self._guard(cc, stmt) + cmt

        if ins.address in self._jumptables:
            idx, targets = self._jumptables[ins.address]
            cases = " ".join(f"case {i}: goto L_{t:08x};" for i, t in enumerate(targets))
            self.stats["lifted"] += 1
            return "    " + self._guard(cc, f"switch (c->r[{idx}]) {{ {cases} }}") + cmt

        if cc and len(base) > 2 and base[-2:] in CC_SUFFIX: base = base[:-2]
        if ins.update_flags and len(base) > 3 and base.endswith("s"): base = base[:-1]
        try: body = self._body(ins, base, ins)
        except (Unsupported, IndexError): body = None
        if body is None:
            self.stats["stubbed"] += 1
            return (f'    nk_unimplemented(c, {ins.address:#x}, "{m} {ins.op_str}");  /* TODO */')
        self.stats["lifted"] += 1
        return "    " + self._guard(cc, body) + cmt if cc else f"    {body}{cmt}"

    def _dab(self, ins, ops, pc):
        """(dst, a, b) for a binary op, handling Thumb 2-operand (rd = rd op rn)
        and ARM/Thumb 3-operand (rd = rn op op2) forms."""
        dst = self.reg(ins, ops[0].reg, pc)
        if len(ops) >= 3:
            return dst, self.src(ins, ops[1], pc), self.src(ins, ops[2], pc)
        return dst, self.reg(ins, ops[0].reg, pc), self.src(ins, ops[1], pc)

    # Value ops whose destination is ops[0]; PC there = computed branch or
    # misdecoded data. Not our value forms — stub (ldr-pc is handled in _mem).
    _DEST0 = {"mov","mvn","add","sub","rsb","adc","sbc","and","orr","eor","bic",
              "lsl","lsr","asr","ror","mul","mla"}

    def _body(self, ins, base, d):
        ops = d.operands; pc = ins.address
        if (base in self._DEST0 and ops and ops[0].type == ARM_OP_REG
                and ops[0].reg == ARM_REG_PC):
            raise Unsupported()
        if base == "push": return self._push(ins, ops)
        if base == "pop":  return self._pop(ins, ops)
        if base.startswith("ldm") or base.startswith("stm"): return self._ldm_stm(ins, base, ops)
        if base == "mul":
            dst, a, b = self._dab(ins, ops, pc)
            s = f"{dst} = {a} * {b};"
            if d.update_flags: s += f" nk_set_nz(c, {dst});"
            return s
        if base == "mla":
            dst = self.reg(ins, ops[0].reg, pc)
            s = (f"{dst} = {self.src(ins, ops[1], pc)} * {self.src(ins, ops[2], pc)} "
                 f"+ {self.src(ins, ops[3], pc)};")
            if d.update_flags: s += f" nk_set_nz(c, {dst});"
            return s
        if base in ("smull", "umull"):
            lo = self.reg(ins, ops[0].reg, pc); hi = self.reg(ins, ops[1].reg, pc)
            a, b = self.src(ins, ops[2], pc), self.src(ins, ops[3], pc)
            prod = (f"((int64_t)(int32_t){a} * (int64_t)(int32_t){b})" if base == "smull"
                    else f"((uint64_t){a} * (uint64_t){b})")
            return f"{{ uint64_t _p = (uint64_t){prod}; {lo} = (uint32_t)_p; {hi} = (uint32_t)(_p >> 32); }}"
        if base in ("smlal", "umlal"):
            lo = self.reg(ins, ops[0].reg, pc); hi = self.reg(ins, ops[1].reg, pc)
            a, b = self.src(ins, ops[2], pc), self.src(ins, ops[3], pc)
            prod = (f"((int64_t)(int32_t){a} * (int64_t)(int32_t){b})" if base == "smlal"
                    else f"((uint64_t){a} * (uint64_t){b})")
            return (f"{{ uint64_t _a = (uint64_t){lo} | ((uint64_t){hi} << 32); "
                    f"_a += (uint64_t){prod}; {lo} = (uint32_t)_a; {hi} = (uint32_t)(_a >> 32); }}")
        if base in ("lsl", "lsr", "asr", "ror"):
            # Thumb: `lsrs rd, rm, #imm` (3 ops) or `lsrs rd, rs` (2 ops, rd = rd sh rs).
            dst = self.reg(ins, ops[0].reg, pc)
            if len(ops) >= 3:
                srcv = self.reg(ins, ops[1].reg, pc); amt_op = ops[2]
            else:
                srcv = self.reg(ins, ops[0].reg, pc); amt_op = ops[1]
            if amt_op.type == ARM_OP_IMM:
                amt = amt_op.imm & 0xff
                if base == "lsl":   expr = f"({srcv} << {amt})" if amt < 32 else "0u"
                elif base == "lsr": expr = (f"({srcv} >> {amt})" if 0 < amt < 32 else (srcv if amt == 0 else "0u"))
                elif base == "asr": expr = f"((uint32_t)((int32_t){srcv} >> {amt if amt < 32 else 31}))"
                else:               expr = f"(({srcv} >> {amt}) | ({srcv} << {32 - amt}))" if amt else srcv
            else:
                rs = {"lsl":"nk_lsl","lsr":"nk_lsr","asr":"nk_asr","ror":"nk_ror"}[base]
                expr = f"{rs}({srcv}, {self.reg(ins, amt_op.reg, pc)})"
            s = f"{dst} = {expr};"
            if d.update_flags: s += f" nk_set_nz(c, {dst});"
            return s
        if base in ("mov", "mvn"):
            dst = self.reg(ins, ops[0].reg, pc); val = self.src(ins, ops[1], pc)
            expr = f"~({val})" if base == "mvn" else f"({val})"
            s = f"{dst} = {expr};"
            if d.update_flags: s += f" nk_set_nz(c, {dst});"
            return s
        if base in ("add", "sub", "rsb"):
            dst, a, b = self._dab(ins, ops, pc)
            if base == "rsb": a, b = b, a
            if d.update_flags:
                if base == "add": return f"{dst} = nk_add_flags(c, {a}, {b}, 0);"
                return f"{dst} = nk_sub_flags(c, {a}, {b});"
            return f"{dst} = {a} {'+' if base == 'add' else '-'} {b};"
        if base in ("adc", "sbc"):
            dst, a, b = self._dab(ins, ops, pc)
            if base == "adc": return f"{dst} = nk_add_flags(c, {a}, {b}, nk_cf(c));" if d.update_flags else f"{dst} = {a} + {b} + nk_cf(c);"
            return f"{dst} = nk_sub_flags(c, {a}, ({b}) + (1u - nk_cf(c)));" if d.update_flags else f"{dst} = {a} - {b} - (1u - nk_cf(c));"
        if base in ("and", "orr", "eor", "bic"):
            dst, a, b = self._dab(ins, ops, pc)
            cop = {"and": "&", "orr": "|", "eor": "^", "bic": "& ~"}[base]
            s = f"{dst} = {a} {cop} ({b});" if base == "bic" else f"{dst} = {a} {cop} {b};"
            if d.update_flags: s += f" nk_set_nz(c, {dst});"
            return s
        if base in ("cmp", "cmn", "tst", "teq"):
            a = self.src(ins, ops[0], pc); b = self.src(ins, ops[1], pc)
            if base == "cmp": return f"nk_sub_flags(c, {a}, {b});"
            if base == "cmn": return f"nk_add_flags(c, {a}, {b}, 0);"
            if base == "tst": return f"nk_set_nz(c, {a} & {b});"
            return f"nk_set_nz(c, {a} ^ {b});"
        if base in ("ldr", "ldrh", "ldrb", "ldrsb", "ldrsh", "str", "strh", "strb"):
            return self._mem(ins, base, d, pc)
        return None

    def _mem(self, ins, base, d, pc):
        ops = d.operands
        reg_op, mem_op = ops[0], ops[1]
        mem = mem_op.mem
        pc_dest = base.startswith("ldr") and reg_op.reg == ARM_REG_PC
        if base == "ldr" and mem.base == ARM_REG_PC and mem.index == 0 and not pc_dest:
            addr = (((pc + 4) & ~3) if self.thumb else (pc + 8)) + mem.disp
            val = self.mem.r32(addr)
            if val is not None:
                dst = self.reg(ins, reg_op.reg, pc)
                return f"{dst} = {val:#x}u;  /* literal @ {addr:#x} */"
        b = self.reg(ins, mem.base, pc)
        wb = d.writeback
        post = len(ops) >= 3
        if post:
            access = b; o3 = ops[2]
            if o3.type == ARM_OP_IMM:
                amt = o3.imm; update = f"{b} += {amt};" if amt >= 0 else f"{b} -= {-amt};"
            else:
                idx = self.reg(ins, o3.reg, pc)
                sign = "-" if getattr(o3, "subtracted", False) else "+"
                update = f"{b} {sign}= {idx};"
        else:
            addr = b
            if mem.index:
                idx = self.reg(ins, mem.index, pc)
                st, sv = mem_op.shift.type, mem_op.shift.value
                if not (st and sv) and getattr(mem, "lshift", 0): st, sv = ARM_SFT_LSL, mem.lshift
                if st and sv:
                    if st == ARM_SFT_LSL: idx = f"({idx} << {sv})"
                    elif st == ARM_SFT_LSR: idx = f"({idx} >> {sv})"
                    elif st == ARM_SFT_ASR: idx = f"((uint32_t)((int32_t){idx} >> {sv}))"
                    elif st == ARM_SFT_ROR: idx = f"(({idx} >> {sv}) | ({idx} << {32 - sv}))"
                    else: raise Unsupported()
                sign = "-" if getattr(mem_op, "subtracted", False) else "+"
                addr = f"{addr} {sign} {idx}"
            if mem.disp:
                addr = f"{addr} + {mem.disp}" if mem.disp >= 0 else f"{addr} - {-mem.disp}"
            access = addr
            update = f"{b} = {addr};" if wb else None
        sz = {"ldr":32,"str":32,"ldrh":16,"strh":16,"ldrb":8,"strb":8,"ldrsb":8,"ldrsh":16}[base]
        rfn = {32:"nk_r32",16:"nk_r16",8:"nk_r8"}[sz]
        if pc_dest:
            pre = (update + " ") if (wb and update) else ""
            return f"{pre}nk_call(c, {rfn}(c, {access})); return;"
        reg = self.reg(ins, reg_op.reg, pc)
        if base.startswith("ldr"):
            if base in ("ldrsb", "ldrsh"):
                sext = {8:"(int8_t)",16:"(int16_t)"}[sz]
                stmt = f"{reg} = (uint32_t)(int32_t){sext}{rfn}(c, {access});"
            else:
                stmt = f"{reg} = {rfn}(c, {access});"
        else:
            wfn = {32:"nk_w32",16:"nk_w16",8:"nk_w8"}[sz]
            cast = {32:"(uint32_t)",16:"(uint16_t)",8:"(uint8_t)"}[sz]
            stmt = f"{wfn}(c, {access}, {cast}{reg});"
        if wb and update: stmt = f"{stmt} {update}"
        return stmt

    def _push(self, ins, ops):
        regs = self._reglist(ins, ops); n = len(regs)
        s = [f"c->r[13] -= {4 * n};"]
        for i, (num, _) in enumerate(regs):
            s.append(f"nk_w32(c, c->r[13] + {4 * i}, c->r[{num}]);")
        return " ".join(s)

    def _pop(self, ins, ops):
        regs = self._reglist(ins, ops); n = len(regs)
        has_pc = any(num == 15 for num, _ in regs); s = []
        for i, (num, _) in enumerate(regs):
            if num == 15: s.append(f"/* pc <- [sp+{4 * i}] => return */")
            else: s.append(f"c->r[{num}] = nk_r32(c, c->r[13] + {4 * i});")
        s.append(f"c->r[13] += {4 * n};")
        if has_pc: s.append("return;")
        return " ".join(s)

    def _ldm_stm(self, ins, base, ops):
        if ops[0].reg == ARM_REG_PC:   # PC as block-transfer base = misdecoded data
            raise Unsupported()
        load = base.startswith("ldm")
        mode = base[3:5] if len(base) >= 5 else "ia"
        if mode not in ("ia","ib","da","db"): mode = "ia"
        b = self.reg(ins, ops[0].reg, ins.address)
        writeback = ins.writeback
        regs = self._reglist(ins, ops[1:]); n = len(regs)
        low = {"ia":0,"ib":4,"db":-4*n,"da":-4*n+4}[mode]
        has_pc = any(num == 15 for num, _ in regs)
        s = ["{ uint32_t _b = " + b + ";"]
        for i, (num, _) in enumerate(regs):
            off = low + 4 * i
            addr = "_b" if off == 0 else (f"_b + {off}" if off > 0 else f"_b - {-off}")
            if load:
                if num == 15: s.append(f"/* pc <- [{addr}] => return */")
                else: s.append(f"c->r[{num}] = nk_r32(c, {addr});")
            else: s.append(f"nk_w32(c, {addr}, c->r[{num}]);")
        if writeback: s.append(f"{b} = _b {'+' if low >= 0 else '-'} {4 * n};")
        s.append("}")
        if load and has_pc: s.append("return;")
        return " ".join(s)

    def lift_func(self, fn):
        code = bytes.fromhex(fn["bytes"]); start = fn["start"]
        self.thumb = fn["thumb"]
        md = self.md_t if self.thumb else self.md
        heads = fn.get("heads")
        decoded = []
        if heads:
            for h in heads:
                off = h - start
                if off < 0 or off >= len(code): continue
                ins = next(md.disasm(code[off:off+4], h), None)
                if ins is not None: decoded.append((h, ins))
        else:
            # Linear decode by instruction size (Thumb: 2 or 4 bytes; ARM: 4).
            for ins in md.disasm(code, start):
                decoded.append((ins.address, ins))
        headset = {addr for addr, _ in decoded}

        def base_mnem(ins):
            m = ins.mnemonic.split('.')[0]
            if ins.cc in CC and len(m) > 2 and m[-2:] in CC_SUFFIX: m = m[:-2]
            return m
        self._call_continue = set()
        for i in range(len(decoded) - 1):
            a = decoded[i][1]
            if (base_mnem(a) == "mov" and len(a.operands) == 2
                    and a.operands[0].type == ARM_OP_REG and a.operands[1].type == ARM_OP_REG
                    and regnum(a.reg_name(a.operands[0].reg)) == 14
                    and a.operands[1].reg == ARM_REG_PC):
                b = decoded[i + 1][1]
                if base_mnem(b) in ("bx", "blx") and b.operands and b.operands[0].type == ARM_OP_REG:
                    self._call_continue.add(b.address)

        labels = set(); self._jumptables = {}
        for addr, ins in decoded:
            if ins.group(CS_GRP_JUMP) and not ins.group(CS_GRP_CALL):
                op = ins.operands[0]
                if op.type == ARM_OP_IMM and (op.imm & 0xffffffff) in headset:
                    labels.add(op.imm & 0xffffffff)
                continue

        name = "func_%08x" % start
        lines = [
            f"/* {fn['name']}  @ {start:#010x}  ({fn['size']} bytes, "
            f"{'Thumb' if self.thumb else 'ARM'}) */",
            f"void {name}(nk_cpu_t* c) {{",
        ]
        for i, (addr, ins) in enumerate(decoded):
            if addr in labels: lines.append(f"L_{addr:08x}:;")
            next_addr = decoded[i + 1][0] if i + 1 < len(decoded) else fn["end"]
            lines.append(self.emit(ins, next_addr, headset))
        lines.append("}")
        return "\n".join(lines)


def find(funcs, addr=None, name=None):
    for f in funcs:
        if addr is not None and f["start"] == addr: return f
        if name is not None and f["name"].lower() == name.lower(): return f
    return None


def self_test():
    # Known Thumb: push {lr}; lsls r2, r5, #3; pop {pc}   (bytes 00b5 ea00 00bd)
    fn = {"name": "func_test", "start": 0x1000000, "end": 0x1000006,
          "size": 6, "thumb": True, "bytes": "00b5ea0000bd"}
    lifter = Lifter(Mem([]))
    c = lifter.lift_func(fn)
    assert "c->r[2] = (c->r[5] << 3);" in c, "Thumb LSL #imm not lifted correctly:\n" + c
    assert "c->r[13] -= 4;" in c and "return;" in c, "push/pop not lifted:\n" + c
    print("self-test OK (Thumb push / lsls #imm / pop lifted correctly)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("json", nargs="?")
    ap.add_argument("--func"); ap.add_argument("--addr"); ap.add_argument("--out")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test(); return 0
    if not args.json:
        ap.error("need a functions.json (or --self-test)")

    data = json.load(open(args.json))
    funcs, segs = data["functions"], data["segments"]
    lifter = Lifter(Mem(segs))
    header = '#include "nokia_cpu.h"\n#include "nokia_rt.h"\n'

    if args.all: targets = funcs
    elif args.func: targets = [find(funcs, name=args.func)]
    elif args.addr: targets = [find(funcs, addr=int(args.addr, 0))]
    else: ap.error("need --func, --addr, or --all")
    if not targets or targets[0] is None:
        print("function not found", file=sys.stderr); return 1

    out = [header] + [lifter.lift_func(f) for f in targets]
    text = "\n\n".join(out) + "\n"
    if args.out:
        open(args.out, "w").write(text)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(text)
    s = lifter.stats
    print(f"// funcs={len(targets)} insns={s['insns']} lifted={s['lifted']} "
          f"stubbed={s['stubbed']} ({100*s['lifted']//max(1,s['insns'])}%)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
