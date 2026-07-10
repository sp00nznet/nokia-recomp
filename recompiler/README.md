# recompiler/

Offline tools. Firmware image → MCU image → C.

## What's here now


- **`dct4decrypt.py`** — de-scramble a DCT4 MCU/PPM image
  (g3gg0's DCT4Crypt; keyless, no password involved). Parses the
  FLS chunks, auto-detects the CryptKey, writes raw Thumb/ARM.
  ```
  py dct4decrypt.py npl2__05.800 -o 6100_mcu.bin
  ```

## What's coming (see docs/ARCHITECTURE.md)

- **`lift.py`** — ARMv4(T) → C lifter, ported from
  [ngagerecomp](https://github.com/sp00nznet/ngagerecomp).
- boundary recovery, register/HLE generation, image packing — same shape as the
  ngage pipeline, retargeted from a Symbian `.app` to a bare-metal MCU image.
