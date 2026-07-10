#!/usr/bin/env python3
"""
gen_register.py — emit nk_register() calls so the guest can call itself.

Reads functions.json and writes game_register.c: one nk_register(addr, func_xxxx)
per lifted function, plus nk_game_register() that installs them all. The runtime's
nk_call() then dispatches guest addresses to the matching lifted C function — the
firmware calls its own functions natively.

    py gen_register.py functions.json game_register.c
"""
import json, sys

def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    funcs = json.load(open(sys.argv[1]))["functions"]
    lines = ['#include "nokia_cpu.h"', '#include "nokia_rt.h"', ""]
    for f in funcs:
        lines.append("void func_%08x(nk_cpu_t*);" % f["start"])
    lines += ["", "void nk_game_register(void) {"]
    for f in funcs:
        # Thumb entry points carry bit0 = 1 in call targets; nk_call masks it, and we
        # register the even address so both forms resolve.
        lines.append("    nk_register(%#010xu, func_%08x);" % (f["start"], f["start"]))
    lines += ["}", ""]
    open(sys.argv[2], "w").write("\n".join(lines))
    print("registered %d functions -> %s" % (len(funcs), sys.argv[2]))

if __name__ == "__main__":
    main()
