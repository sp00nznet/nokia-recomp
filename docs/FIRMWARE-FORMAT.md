# Nokia DCT4 firmware format
The GSM DCT4 firmware image is *scrambled*, not encrypted: a public,
keyless, reversible transform of the flash contents. There is no key to
recover and no password involved.

| | **GSM DCT4** (Nokia 6100) |
|---|---|
| Distribution | `…dp_v_…mcu….exe` → InstallShield → raw `dp`/`.fls` product files |
| Protection | Nokia flash **scrambling** — public, **keyless**, reversible |
| Get raw ARM? | **Yes.** `recompiler/dct4decrypt.py` → 5.43 MB Thumb/ARM image |

## Descrambling (`dct4decrypt`)
The 6100's `NPL-2dp_v_8.00_mcu05.80.exe` unpacks (7z + i6comp) to `npl2__05.800`
(the MCU image, Nokia `dp`/FLS container: tagged `DCT4` / `DCT4 ALGORITHM` records)
plus per-language `.80x` PPM packs. The MCU image is *scrambled*, not encrypted:
[`recompiler/dct4decrypt.py`](../recompiler/dct4decrypt.py) parses the FLS chunks,
auto-detects the 16-bit CryptKey (`0x026f` here), and de-scrambles to raw code —
which self-identifies (`Nokia6100`, `Copyright (c) 2000 Nokia Mobile Phones`,
`Profile/MIDP-1.0`, the menu engine) and is full of Thumb prologues. No secret needed.

---
