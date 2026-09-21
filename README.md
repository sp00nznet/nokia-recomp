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
  (a Python port of [g3gg0's DCT4Crypt](https://github.com/g3gg0/DCT4Crypt), self-tested) turns the 6100's `dp` file into a
  5.43 MB raw image. It self-identifies: `Nokia6100`, `Copyright (c) 2000 Nokia Mobile
  Phones`, `Profile/MIDP-1.0`, and the menu engine — **~31k Thumb prologues of real code.**
- [x] **Platform confirmed** — DCT4 / UPP / **ARM7TDMI (ARMv4T)**, MCU loads at
  `0x0100_0000`, Series 40 UI + MIDP Java. Same ISA as ngagerecomp → the lifter ports over.
- [x] **Lifter runs end-to-end** — [`lift.py`](recompiler/lift.py) (ARMv4T **+ Thumb**
  → C, ported from ngagerecomp) + the runtime CPU model in [`runtime/`](runtime/)
  ([`nokia_rt.h`](runtime/include/nokia_rt.h)): a lifted 6100 function compiled under clang
  and **executed natively** with the correct result (`r5<<3`, stack balanced).
- [x] **IDA-driven extraction + call-graph** — [`extract_ida.py`](recompiler/extract_ida.py)
  drives headless IDA Pro 9.1 for **exact boundaries** (forcing raw ARM to 32-bit Thumb,
  which IDA otherwise loads as AArch64), then follows the BL/BLX call graph to a fixpoint:
  **603 functions, 94% of instructions lift and compile clean.**
- [x] **Guest self-dispatch** — [`gen_register.py`](recompiler/gen_register.py) registers
  every lifted function at its guest address; the runtime's `nk_call` routes a guest address
  to the matching native function. Verified: a real 6100 function runs via the table and
  calls into the corpus; unlifted callees are reported by address (the bring-up worklist).
  Env aids `NK_TRACE` / `NK_MAX_CALLS`.

**← current frontier →**

- [ ] **Coverage** — the clean call-graph reaches ~1.3% of the image; a linear sweep shows
  ~44% (2.37 MB) *decodes* as Thumb, but code and compressed data are interleaved and Thumb
  is dense, so a raw sweep over-fragments. Clean high coverage needs the **ARM reset vector**
  as the call-graph root (note: `dct4decrypt` leaves the `0x84`-byte flash header scrambled —
  that's likely where the vector table lives) — the main RE task ahead.
- [ ] Runtime: RAM + MMIO trap layer, then **boot the reset vector**
- [ ] HLE the display controller → **first light: the Nokia boot logo on a host window**
- [ ] Keypad + timers → navigable idle menu (Snake, the app list)
- [ ] Stub the radio → the phone boots to "no network" and just *runs*


## Toolchain

- **Python 3 + Capstone** — the recompiler (`dct4decrypt.py`, `extract.py`, `lift.py`,
  `gen_register.py`).
- **IDA Pro 9.1 (headless)** — exact function boundaries on the decrypted image
  (`extract_ida.py`).
- **clang** — compiles the generated C + runtime.
- **ngagerecomp** — the ARMv4T lifter and CPU model this project reuses.

## Legal

nokia-recomp ships **no copyrighted firmware or assets**. It is a tool. You supply
your own legally-obtained Nokia firmware. Recompiled output is a derivative of *your*
copy and is yours to run. Everything firmware-shaped is `.gitignore`d.

**Purpose.** This project exists for **interoperability**: to let firmware you already
own keep running on hardware you can actually buy, after the original hardware has
become unobtainable. Everything here is aimed at that -- reading the image, recovering
function boundaries, translating ARM to C, and supplying a runtime that answers what
the firmware asks for. It is also a preservation and research exercise: a DCT4 phone is
a complete, documented, self-contained computer small enough to understand end to end.

**On the descrambler.** [`recompiler/dct4decrypt.py`](recompiler/dct4decrypt.py)
reverses GSM DCT4's flash scrambling. That scrambling is **keyless** -- there is no
secret, no password and no per-device key; it is a fixed, publicly documented
transformation of the flash image, and the algorithm has been public for roughly two
decades. This file is a Python port of [g3gg0's DCT4Crypt](https://github.com/g3gg0/DCT4Crypt),
credited in full below and in the file's own header. It descrambles an image you
supply; it does not unlock a device, defeat a password, or bypass a licence check.


## Prior art & thanks

- [N64: Recompiled](https://github.com/N64Recomp/N64Recomp) — the static-recomp pattern this follows
- [ngagerecomp](https://github.com/sp00nznet/ngagerecomp) — sibling project; the ARMv4T lifter + runtime model
- [DCT4Crypt](https://github.com/g3gg0/DCT4Crypt) by g3gg0 + [retro-phone-tools](https://github.com/RobyRew/retro-phone-tools) — the DCT4 decryption algorithm
- Everyone still holding a phone that survived the 2000s. 📞
