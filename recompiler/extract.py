#!/usr/bin/env python3
"""
extract.py — recover Thumb functions from a raw DCT4 MCU image (no IDA).

The decrypted Series 40 firmware is Thumb. This scans for function prologues
(`push {..,lr}`) that decode cleanly forward to a return (`pop {..,pc}` / `bx lr`),
and emits functions.json (functions + the whole image as one segment) for lift.py.

Heuristic, first-cut boundaries: a function runs from its `push {..,lr}` to the
first return. Good enough to lift clean leaf functions; IDA can supply
exact boundaries later via the same JSON shape.

    py extract.py 6100_mcu.bin functions.json [--base 0x1000000] [--limit N] [--max-bytes 512]
"""
import json, sys, argparse
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_REG_LR, ARM_REG_PC

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN); md.detail = True

def is_push_lr(ins):
    return ins.mnemonic == "push" and any(op.reg == ARM_REG_LR for op in ins.operands)

def is_return(ins):
    m = ins.mnemonic
    if m == "pop" and any(op.reg == ARM_REG_PC for op in ins.operands): return True
    if m == "bx" and ins.operands and ins.operands[0].reg == ARM_REG_LR: return True
    return False

def scan(data, base, max_bytes, limit):
    funcs = []
    n = len(data)
    # Candidate prologues: halfword 0xB5xx (push {..,lr}) at even offsets.
    off = 0
    while off + 1 < n:
        if data[off + 1] == 0xb5:
            fn = try_func(data, base, off, max_bytes)
            if fn:
                funcs.append(fn)
                off = fn["end"] - base            # skip past the accepted function
                if limit and len(funcs) >= limit: break
                continue
        off += 2
    return funcs

def try_func(data, base, start_off, max_bytes):
    """Decode Thumb from start_off; accept if it cleanly reaches a return."""
    addr = base + start_off
    window = data[start_off:start_off + max_bytes]
    insns = list(md.disasm(window, addr))
    if not insns or not is_push_lr(insns[0]):
        return None
    consumed = 0
    for ins in insns:
        consumed += ins.size
        if is_return(ins):
            end = addr + consumed
            return {
                "name": f"func_{addr:08x}",
                "start": addr, "end": end, "size": end - addr, "thumb": True,
                "bytes": data[start_off:start_off + (end - addr)].hex(),
            }
    return None   # no clean return within the window -> not a (leaf) function we take

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image"); ap.add_argument("out")
    ap.add_argument("--base", default="0x1000000")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--max-bytes", type=int, default=512)
    a = ap.parse_args()
    base = int(a.base, 0)
    data = open(a.image, "rb").read()
    funcs = scan(data, base, a.max_bytes, a.limit)
    out = {
        "functions": funcs,
        "segments": [{"start": base, "end": base + len(data), "bytes": data.hex()}],
    }
    json.dump(out, open(a.out, "w"))
    total = sum(f["size"] for f in funcs)
    print(f"{len(funcs)} Thumb functions, {total} bytes -> {a.out}")

if __name__ == "__main__":
    main()
