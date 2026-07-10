# recompiler/

Offline tools: Nokia DCT4 firmware → raw ARM → C.

## Pipeline (Nokia 6100, GSM DCT4)

```
NPL-2dp_..._mcu05.80.exe ──(7z + i6comp)──▶ npl2__05.800   (Nokia dp/FLS container)
        │ dct4decrypt.py (keyless)
        ▼
   6100_mcu.bin  (5.43 MB raw Thumb/ARM)
        │ extract.py            find Thumb functions
        ▼
   functions.json               functions + image bytes
        │ lift.py               ARMv4T + Thumb → C
        ▼
   generated.c ──(clang)──▶ native objects, linked against ../runtime/
```

- **`dct4decrypt.py`** — de-scramble a DCT4 MCU/PPM image (g3gg0's DCT4Crypt,
  keyless, auto-detects the CryptKey). `py dct4decrypt.py --self-test`.
- **`extract.py`** — scan the raw image for Thumb functions (`push {..,lr}` →
  clean return) → `functions.json`. IDA (`e:\ida`) can supply exact boundaries later
  via the same JSON shape.
- **`lift.py`** — the lifter (pure Python + Capstone). Decodes ARM/Thumb and emits C
  against `nk_cpu_t` (see `../runtime/include/`). Thumb-aware (PC = addr+4, 2-byte
  decode, 2-operand data-processing forms). `py lift.py --self-test`.
  `../docs/FIRMWARE-FORMAT.md`).

## What it emits

Real 6100 Thumb, lifted and runnable:

```c
void func_01250d4e(nk_cpu_t* c) {
    c->r[13] -= 8; nk_w32(c, c->r[13] + 0, c->r[0]); nk_w32(c, c->r[13] + 4, c->r[14]);  // push {r0, lr}
    c->r[2] = (c->r[5] << 3); nk_set_nz(c, c->r[2]);                                      // lsls r2, r5, #3
    c->r[0] = nk_r32(c, c->r[13] + 0); c->r[13] += 8; return;                             // pop {r0, pc}
}
```
