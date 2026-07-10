# Architecture

nokia-recomp follows the proven **static recompilation** shape: do the hard
analysis *offline*, emit plain C, and link it against a small native runtime.
Nothing is interpreted at runtime — the phone's ARM code becomes the program.

This is the same pattern as N64Recomp and our sibling project
[ngagerecomp](https://github.com/sp00nznet/ngagerecomp). The difference is the
target: not a game on an OS, but the **whole phone firmware** — a bare-metal
Nokia DCT4 MCU image with no operating system underneath it to lean on.

## The pipeline (planned)

```
   6100_mcu.bin   (ARM MCU image, descrambled from the FLS)
            │
            ▼
   ┌──────────────────┐   parse flash layout (base/entry from .ldp),
   │  recompiler/     │   recover function boundaries, lift each
   │  (static ARM→C)  │──▶ ARMv4(T) instruction to portable C
   └──────────────────┘
            │  generated C
            ▼
   ┌──────────────────┐   ARM register/flag/memory model +
   │  runtime/        │   HLE for the Nokia OS: display, keypad,
   │  (nokia runtime)  │   timers, the GSM/RF stubs, flash/EEPROM
   └──────────────────┘
            │
            ▼
     native executable  (Windows / Linux / macOS)  — a runnable 6100
```

## Why a phone firmware is harder than an N-Gage game

The N-Gage pitch was "the CPU is easy, Symbian is the work." Here the CPU is
*still* easy (ARM7TDMI is one of the cleanest ISAs ever shipped), but there is
**no Symbian and no documented API surface** — just a proprietary Nokia RTOS
baked into the same image, talking straight to hardware registers. So the HLE
boundary is different:

| | N-Gage game | 6100 firmware |
|---|---|---|
| Under the code | Symbian OS (documented, EKA2L1 to crib from) | proprietary Nokia OS, no reference impl |
| API surface | DLL imports with named ordinals | none — direct MMIO to the ASIC |
| HLE target | window server, file server, EUSER | display controller, keypad, timers, RF/DSP |
| Reference oracle | EKA2L1 | a real 6100, or a low-level DCT4 emulator |

The upside: a phone's UI is tiny and software-rendered (a small mono/colour LCD),
there's no GPU, and huge parts of the image — the GSM baseband, the RF/DSP
control — can be **stubbed** for a UI-only "phone simulator" first target, exactly
like stubbing multiplayer in a game port.

## Stages

### 1. Front end — carve + disassemble the MCU image
`recompiler/dct4decrypt.py` turns the flasher's FLS container into the raw MCU
image (see [FIRMWARE-FORMAT.md](FIRMWARE-FORMAT.md)). From there: find the flash base/entry from the loader (`.ldp`), then a linear
+ recursive sweep to recover functions. IDA/Ghidra as the analysis front end,
same as ngagerecomp.

### 2. Lifter — ARMv4(T) → C
Reuse the ngagerecomp ARM lifter almost wholesale; it already lifts ARMv4T to C
against a typed CPU context. The 6100 is bare-metal, so PC-relative literal pools
and hand-written interrupt vectors matter more than in a relocatable `.app`.

### 3. Runtime — the Nokia OS HLE
The new work. A bare-metal image expects specific hardware at specific addresses.
The runtime provides:
- ARM CPU state (registers, CPSR, memory) — shared with ngagerecomp's model.
- **MMIO trap layer** — reads/writes to peripheral addresses dispatch to shims.
- **Display** — the LCD controller framebuffer → a host window.
- **Keypad / timers / RTC** — host input and clock.
- **RF / CDMA / DSP** — stubbed. No baseband; the phone runs "airplane mode" first.

The hardware the runtime must answer for is now mapped from the **RH-44 L3/L4 service
manual** — see [`HARDWARE.md`](HARDWARE.md): the UPP8Mv2.2 ASIC (ARMv4T MCU + Lead3 DSP +
CDMA "Corona"), 8 MB boot-sectored flash + 512 KB SRAM, a 96×65 colour LCD, a Jack-style
keypad, and the Jack 3.4 UI firmware. The RF/CDMA/GPS chain is stubbed for a UI-first boot.

First target milestone: boot the firmware far enough to draw the **Nokia startup
screen and idle UI** on a host window. Calls, signal, and the CDMA stack come
later (or never — a UI simulator is a legitimate finish line).
