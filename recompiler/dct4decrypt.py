#!/usr/bin/env python3
"""
dct4decrypt.py — decrypt a Nokia DCT4 GSM firmware image (MCU / PPM) to raw code.

GSM DCT4 firmware uses Nokia's own flash scrambling, which is a **public, keyless,
reversible** algorithm (auto-detects the 16-bit CryptKey). This turns a `dp`/`.fls`
distribution file into the raw Thumb/ARM MCU image the recompiler lifts.

    py dct4decrypt.py npl2__05.800 6100_mcu.bin      # decrypt an MCU image
    py dct4decrypt.py --self-test                     # encode/decode round-trip

Algorithm: g3gg0's DCT4Crypt (github.com/g3gg0/DCT4Crypt), via the byte-verified
JS port in RobyRew/retro-phone-tools (MIT). This is an independent Python reimpl.
"""
import sys

MBIT = [0x1221,0xa91a,0x52a5,0x0908, 0xa918,0x1020,0xffff,0x52a1,
        0x0100,0x1220,0xad1a,0x0900, 0x1000,0x2908,0x5221,0xa908]
MADDR = [0x0fae,0x3e7f,0xc99f,0xd6f7, 0xa71b,0x14c4,0x52a5,0xcbb1,
         0x4285,0xefdf,0xdff7,0x5080, 0xee9f,0x0000,0x8432,0x5221,
         0x4084,0xa91a,0x56e7,0xb93a, 0x5b21,0xa818,0x0000,0xefdf]
MADDR_ADJ = [(0x00140,0x1000),(0x00220,0x52a1),(0x00480,0x1221),(0x00600,0xb928),
             (0x00810,0x5221),(0x00840,0x1220),(0x00900,0x2008),(0x01020,0x1221),
             (0x01080,0x0908),(0x01100,0x52a1),(0x02020,0x0100),(0x02080,0xfbbd),
             (0x04010,0xa91a),(0x04040,0xa908),(0x08008,0x2908),(0x09000,0x1000),
             (0x0a000,0xbd3a),(0x10010,0xad1a),(0x10040,0x5221),(0x10400,0x0908),
             (0x20200,0x53a5),(0x40040,0xa91a),(0x44000,0x1b20),(0x80100,0xa918),
             (0x800000,0xb908)]
TYPE_MCU, TYPE_PPM = 0, 1
FLASH_START = 0x1000000     # MCU flash base; PPM images start above this
CRYPT_START = 0x84          # first 0x84 bytes are the plaintext header
AUTO_OFFSET, AUTO_VALUE = 0x84, 0xffff   # MCU CryptKey auto-detect

EN = [0]*65536; DE = [0]*65536
for _c in range(65536):
    _nc = 0
    for _i in range(16):
        if _c & (1 << _i): _nc ^= MBIT[_i]
    DE[_nc] = _c; EN[_c] = _nc

def _address_bits(code, addr):
    addr &= 0xffffffff
    for bits, xorv in MADDR_ADJ:
        if (addr & bits) == bits: code ^= xorv
    for i in range(24):
        if addr & (1 << (i+1)): code ^= MADDR[i]
    return code & 0xffff

def _get(buf, o): return ((buf[o] << 8) | buf[o ^ 1]) & 0xffff
def _set(buf, o, code): buf[o] = (code >> 8) & 0xff; buf[o ^ 1] = code & 0xff

def decode_block(buf, addr, length, base, typ):
    for o in range(0, length*2, 2):
        if ((addr + o - FLASH_START) & 0xffffffff) >= CRYPT_START or typ == TYPE_PPM:
            code = _get(buf, o)
            code = _address_bits(code, (addr + o) & 0xffffffff)
            code = DE[code]
            _set(buf, o, (code ^ base) & 0xffff)

def encode_block(buf, addr, length, base, typ):   # inverse, for the self-test
    for o in range(0, length*2, 2):
        if ((addr + o - FLASH_START) & 0xffffffff) >= CRYPT_START or typ == TYPE_PPM:
            code = (_get(buf, o) ^ base) & 0xffff
            code = EN[code]
            code = _address_bits(code, (addr + o) & 0xffffffff)
            _set(buf, o, code)

def _word(b, p): return ((b[p]<<24)|(b[p+1]<<16)|(b[p+2]<<8)|b[p+3]) & 0xffffffff

def _chunk(b, p):
    while True:
        if p >= len(b): return None
        m = b[p]; p += 1
        if m == 0x14: break
        if m == 0x21: p += 5
        elif m == 0x20: p += 5 + ((b[p+2]<<8)|b[p+3])
    addr = _word(b, p); p += 4
    hb = b[p:p+5]; p += 5
    length = (hb[1]<<16)|(hb[2]<<8)|hb[3]
    return dict(addr=addr, data=b[p:p+length], lenHalf=length//2, nextP=p+length)

def read_flash(b):
    p = 1; p += 4 + _word(b, p)
    chunks, start, end = [], None, 0
    while True:
        c = _chunk(b, p)
        if not c: break
        p = c['nextP']
        if start is None: start = c['addr']
        chunks.append(c)
        end = max(end, c['addr'] + c['lenHalf']*2 - start)
    if start is None: raise SystemExit("no DCT4 flash chunks — not a DCT4 ROM?")
    ser = bytearray(end)
    for c in chunks:
        ser[c['addr']-start : c['addr']-start + c['lenHalf']*2] = c['data'][:c['lenHalf']*2]
    return ser, start, len(chunks)

def decrypt_rom(b, code=None):
    ser, start, nch = read_flash(b)
    typ = TYPE_PPM if start > FLASH_START else TYPE_MCU
    out = bytearray(len(ser) - (len(ser) % 2))
    addr = start & 0xffffffff; cur = 0 if code is None else code & 0xffff; first = True
    pos = 0
    while pos < len(out):
        length = min(0x2000, (len(out)-pos)//2)
        if length == 0: break
        buf = bytearray(ser[pos:pos+length*2])
        decode_block(buf, addr, length, cur, typ)
        if first and cur == 0:                       # auto-detect the CryptKey
            cur = (((buf[AUTO_OFFSET]<<8)|buf[AUTO_OFFSET+1]) ^ AUTO_VALUE) & 0xffff
            idx = CRYPT_START if typ == TYPE_MCU else 0
            while idx < length*2:
                buf[idx] ^= (cur>>8)&0xff; buf[idx+1] ^= cur&0xff; idx += 2
        out[addr-start : addr-start+len(buf)] = buf
        addr = (addr + length*2) & 0xffffffff; pos += length*2; first = False
    return out, cur, typ, start, nch

def _self_test():
    import os
    plain = bytearray(os.urandom(0x4000))
    addr, base = FLASH_START, 0x1234
    enc = bytearray(plain); encode_block(enc, addr, len(enc)//2, base, TYPE_MCU)
    dec = bytearray(enc);   decode_block(dec, addr, len(dec)//2, base, TYPE_MCU)
    assert bytes(dec) == bytes(plain), "round-trip mismatch"
    assert DE[EN[0x4242]] == 0x4242, "substitution table not invertible"
    print("self-test OK (encode/decode round-trip byte-exact)")

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '--self-test':
        _self_test(); sys.exit()
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    data = open(sys.argv[1], 'rb').read()
    out, key, typ, start, nch = decrypt_rom(data)
    open(sys.argv[2], 'wb').write(out)
    print(f"{'MCU' if typ==0 else 'PPM'}: {nch} chunks, start={start:#x}, "
          f"CryptKey={key:#06x}, {len(out)} bytes -> {sys.argv[2]}")
