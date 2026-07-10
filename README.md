# nokia-recomp

**A static recompiler for classic Nokia DCT4 phone firmware — turn an early-2000s
ARM7 MCU image into a native, runnable executable. First target: the Nokia 6100.**

> Before smartphones, the Nokia you actually remember: a colour candybar with a
> spring-loaded menu, Snake, a ringtone composer, and a handful of tiny Java games.
> No OS you'd recognise — just Nokia's own **Series 40** firmware fused to an ARM7
> core. This project takes that firmware and, instead of emulating it,
> **statically recompiles it** — lifting the phone's own Thumb/ARM code to C so it
> becomes a program that runs natively. A phone, as an app.

---

## Why do this to a phone

Static recompilation (lift the original machine code to C, compile it natively,
link it against a hand-written runtime) has had a renaissance on game consoles —
N64, PS1, and our own sibling project [ngagerecomp](https://github.com/sp00nznet/ngagerecomp)
for the N-Gage. A DCT4 phone is a **great** target for it:

| Property | Nokia 6100 (DCT4) | Why it matters |
|---|---|---|
| CPU | ARM7TDMI, **ARMv4T** (Thumb + ARM), inside the UPP ASIC | Clean, fully-documented ISA. No GPU, no microcode. The easy part — and the exact ISA ngagerecomp already lifts. |
| Firmware | **Keyless-decryptable** (`dct4decrypt`) | GSM DCT4 flash scrambling is a public, reversible algorithm. We have the raw image. |
| Software | Nokia **Series 40** + MIDP-1.0 Java | The classic menu UI, Snake, the app suite — the thing worth reviving. |
| Display | 128×128 software-rendered LCD | No GPU. Pixels are just memory — the display HLE is a framebuffer → a window. |
| Radio | GSM baseband / DSP | **Stubbable.** A UI-only "phone simulator" is a legitimate first finish line. |

The work isn't the CPU — it's that a phone image expects **specific hardware at
specific addresses**, so the runtime has to answer for the display controller, the
keypad, timers, and the DSP/radio block. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## How it works

```
   npl2__05.800  (Nokia dp/FLS)          native executable
        │                                      ▲
        ▼ dct4decrypt (keyless)                │
   6100_mcu.bin  (raw Thumb/ARM)               │
        │                                      │
        ▼                                      │
   ┌──────────────────┐              ┌──────────────────────┐
   │  recompiler/     │  generated   │  runtime/            │
   │  static ARM → C  │─────C───────▶│  ARM CPU + Series 40 │
   └──────────────────┘              │  HLE (LCD, keypad,   │
                                     │  timers, radio stub) │
                                     └──────────────────────┘
```

- **`recompiler/`** — offline tools. `dct4decrypt.py` turns the firmware into a raw
  MCU image; next is the ARMv4T/Thumb→C lifter (ported from ngagerecomp).
- **`runtime/`** — ships with the recompiled phone: ARM CPU model + the Series 40
  HLE layer (MMIO trap → display / input / timers, radio stubbed).
- **`config/`** — per-target config ([`config/6100.toml`](config/6100.toml)).

## Status

**We have the real, descrambled firmware.** Honest checkboxes, no vapor:

- [x] **Firmware descrambled → raw ARM in hand** — GSM DCT4 uses Nokia's *keyless*
  flash scrambling -- no key, no password. [`recompiler/dct4decrypt.py`](recompiler/dct4decrypt.py)
  (a Python port of g3gg0's DCT4Crypt, self-tested) turns the 6100's `dp` file into a
  5.43 MB raw image. It self-identifies: `Nokia6100`, `Copyright (c) 2000 Nokia Mobile
  Phones`, `Profile/MIDP-1.0`, and the menu engine — **~31k Thumb prologues of real code.**
- [x] **Platform confirmed** — DCT4 / UPP / **ARM7TDMI (ARMv4T)**, MCU loads at
  `0x0100_0000`, Series 40 UI + MIDP Java. Same ISA as ngagerecomp → the lifter ports over.
- [x] **Lifter runs end-to-end** — [`extract.py`](recompiler/extract.py) (Thumb
  function scanner) → [`lift.py`](recompiler/lift.py) (ARMv4T **+ Thumb** → C, ported
  from ngagerecomp) → compiles clean under clang → **executes natively.** A lifted 6100
  function ran with the correct result (`r5<<3`, stack balanced); 93% of instructions
  lift. Runtime CPU model in [`runtime/`](runtime/) ([`nokia_rt.h`](runtime/include/nokia_rt.h)).
- [x] **IDA-driven extraction** — [`extract_ida.py`](recompiler/extract_ida.py) drives
  headless IDA Pro 9.1 to recover functions with **exact boundaries** (forcing raw ARM to
  32-bit Thumb, which IDA otherwise loads as AArch64). 507 functions, real multi-block
  extents, 94% of instructions lift and compile clean.
- [x] **Guest self-dispatch** — [`gen_register.py`](recompiler/gen_register.py) registers
  every lifted function at its guest address; the runtime's `nk_call` routes a guest
  address to the matching native function. Verified: a real 6100 function runs via the
  table and calls into the corpus; unlifted callees are reported by address (the bring-up
  worklist). Env aids `NK_TRACE` / `NK_MAX_CALLS` for bring-up. Fixed a Thumb-2 CBZ/CBNZ
  mislift found by the larger corpus.
- [ ] Seed the ARM reset/vector table + follow calls → full-image coverage (mixed ARM/Thumb)
- [ ] Runtime: MMIO trap layer + boot the reset vector → **first light** (boot logo)
- [ ] HLE the display controller → **Nokia boot logo on a host window** (first-light goal)
- [ ] Keypad + timers → navigable idle menu (Snake, the app list)
- [ ] Stub the radio → the phone boots to "no network" and just *runs*


## Toolchain

- **Python 3** — `dct4decrypt.py`, `unpack.py`, and (soon) the lifter.
- **IDA / Ghidra** — analysis front end for the decrypted image.
- **ngagerecomp** — the ARMv4T lifter and CPU model this project reuses.

## Legal

nokia-recomp ships **no copyrighted firmware or assets**. It is a tool. You supply
your own legally-obtained Nokia firmware. Recompiled output is a derivative of *your*
copy and is yours to run. Everything firmware-shaped is `.gitignore`d.

## Prior art & thanks

- [N64: Recompiled](https://github.com/N64Recomp/N64Recomp) — the static-recomp pattern this follows
- [ngagerecomp](https://github.com/sp00nznet/ngagerecomp) — sibling project; the ARMv4T lifter + runtime model
- [DCT4Crypt](https://github.com/g3gg0/DCT4Crypt) by g3gg0 + [retro-phone-tools](https://github.com/RobyRew/retro-phone-tools) — the DCT4 decryption algorithm
- Everyone still holding a phone that survived the 2000s. 📞
