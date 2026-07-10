# Runs INSIDE idat.exe. Raw Nokia DCT4 MCU image -> functions.json, forced 32-bit ARM/Thumb.
# Launch: idat -A -a -c -Tbinary -parm -b0x100000 -Sextract_ida.py <out> 6100_mcu.bin
#   (-a skips the initial auto-analysis so we can fix bitness/Thumb first)
import json
import ida_auto, ida_funcs, ida_bytes, ida_segment, ida_name, ida_idp
import idautils, idc, ida_segregs, ida_ida

OUT = idc.ARGV[1] if len(idc.ARGV) > 1 else r"E:\ida\work\nokia6100\functions.json"

def bitness():
    for g in ("inf_get_app_bitness", "inf_is_64bit"):
        f = getattr(ida_ida, g, None)
        if f:
            try: return "%s=%s" % (g, f())
            except Exception: pass
    return "?"

print("[extract] bitness at start:", bitness())

# Force 32-bit ARM.
for setter, val in (("inf_set_app_bitness", 32), ("inf_set_64bit", False)):
    f = getattr(ida_ida, setter, None)
    if f:
        try: f(val); print("[extract] %s(%r) ok" % (setter, val))
        except Exception as e: print("[extract] %s err %s" % (setter, e))
try:
    idc.set_processor_type("arm", ida_idp.SETPROC_LOADER)
    print("[extract] set_processor_type arm ok")
except Exception as e:
    print("[extract] set_processor_type err", e)
print("[extract] bitness after force:", bitness())

seg = ida_segment.get_first_seg()
s0, s1 = seg.start_ea, seg.end_ea
print("[extract] segment %#x..%#x  bitness=%d" % (s0, s1, seg.bitness))

# Make the segment 32-bit and wipe it so Thumb decoding starts from clean bytes.
try:
    ida_segment.set_segm_addressing(seg, 1)   # 1 = 32-bit
    print("[extract] segment -> 32-bit (bitness=%d)" % ida_segment.get_first_seg().bitness)
except Exception as e:
    print("[extract] set_segm_addressing err", e)
ida_bytes.del_items(s0, ida_bytes.DELIT_SIMPLE, s1 - s0)

# Bias whole segment to Thumb (T=1).
try:
    ida_segregs.set_default_sreg_value(seg, ida_idp.str2reg("T"), 1)
    idc.split_sreg_range(s0, "T", 1, ida_segregs.SR_user)
    print("[extract] Thumb T=1 set")
except Exception as e:
    print("[extract] Thumb set err", e)

# Collect ALL Thumb prologue candidates (push {..,lr} = 0xB5xx at even offsets) from
# raw bytes FIRST, then mark them as Thumb code. Collecting up front avoids IDA's
# per-function analysis consuming later prologues before we reach them.
cands = [ea for ea in range(s0, s1 - 1, 2) if ida_bytes.get_byte(ea + 1) == 0xB5]
print("[extract] %d push-lr candidates" % len(cands))
for ea in cands:
    try: idc.split_sreg_range(ea, "T", 1, ida_segregs.SR_user)
    except Exception: pass
    idc.create_insn(ea)                      # decode as Thumb; keeps valid ones
ida_auto.auto_wait()
# Promote every candidate that decoded to a real `push` into a function.
seeded = 0
for ea in cands:
    if idc.print_insn_mnem(ea) == "PUSH" and not ida_funcs.get_func(ea):
        if ida_funcs.add_func(ea): seeded += 1
ida_auto.auto_wait()
nfuncs = len(list(idautils.Functions(s0, s1)))
print("[extract] seeded %d; funcs after analysis: %d" % (seeded, nfuncs))

funcs = []
for ea in idautils.Functions(s0, s1):
    f = ida_funcs.get_func(ea)
    if not f: continue
    size = f.end_ea - f.start_ea
    if size <= 0 or size > 0x20000: continue
    b = ida_bytes.get_bytes(f.start_ea, size)
    if not b or len(b) != size: continue
    thumb = idc.get_sreg(f.start_ea, "T") == 1
    funcs.append({"name": ida_funcs.get_func_name(ea) or ("func_%08x" % ea),
                  "start": f.start_ea, "end": f.end_ea, "size": size,
                  "thumb": bool(thumb), "bytes": b.hex()})

img = ida_bytes.get_bytes(s0, s1 - s0)
json.dump({"functions": funcs,
           "segments": [{"start": s0, "end": s1, "bytes": img.hex()}]}, open(OUT, "w"))
print("[extract] wrote %d functions -> %s" % (len(funcs), OUT))
idc.qexit(0)
