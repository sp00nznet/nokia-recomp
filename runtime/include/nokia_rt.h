/*
 * nokia-recomp — runtime helpers the generated C calls.
 *
 * Flat little-endian guest memory + ARM NZCV flag math, as static-inline so each
 * generated translation unit stays dependency-light. Ported from ngagerecomp's
 * runtime core (the ARM CPU model is platform-independent).
 *
 * Flat model: set c->mem = backing - NK_FLASH_BASE, so a guest address indexes
 * directly (nk_r32(c, a) touches c->mem + a).
 */
#ifndef NOKIA_RT_H
#define NOKIA_RT_H

#include <stdint.h>
#include "nokia_cpu.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NK_FLASH_BASE 0x01000000u   /* DCT4 MCU image load address */

/* ---- guest memory (little-endian) ---- */
static inline uint32_t nk_r32(nk_cpu_t* c, uint32_t a) {
    const uint8_t* p = c->mem + a;
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static inline uint16_t nk_r16(nk_cpu_t* c, uint32_t a) {
    const uint8_t* p = c->mem + a;
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1]<<8));
}
static inline uint8_t  nk_r8 (nk_cpu_t* c, uint32_t a) { return c->mem[a]; }

static inline void nk_w32(nk_cpu_t* c, uint32_t a, uint32_t v) {
    uint8_t* p = c->mem + a;
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static inline void nk_w16(nk_cpu_t* c, uint32_t a, uint16_t v) {
    uint8_t* p = c->mem + a; p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
}
static inline void nk_w8 (nk_cpu_t* c, uint32_t a, uint8_t v) { c->mem[a]=v; }

/* ---- NZCV flags (in cpsr) ---- */
#define NK_BIT(n) (1u << (n))
static inline uint32_t nk_nf(nk_cpu_t* c){ return (c->cpsr >> NK_FLAG_N) & 1u; }
static inline uint32_t nk_zf(nk_cpu_t* c){ return (c->cpsr >> NK_FLAG_Z) & 1u; }
static inline uint32_t nk_cf(nk_cpu_t* c){ return (c->cpsr >> NK_FLAG_C) & 1u; }
static inline uint32_t nk_vf(nk_cpu_t* c){ return (c->cpsr >> NK_FLAG_V) & 1u; }
static inline void nk_setf(nk_cpu_t* c, int bit, uint32_t v) {
    if (v) c->cpsr |= NK_BIT(bit); else c->cpsr &= ~NK_BIT(bit);
}
static inline void nk_set_nz(nk_cpu_t* c, uint32_t r) {
    nk_setf(c, NK_FLAG_N, r >> 31);
    nk_setf(c, NK_FLAG_Z, r == 0);
}
static inline uint32_t nk_add_flags(nk_cpu_t* c, uint32_t a, uint32_t b, uint32_t cin) {
    uint64_t u = (uint64_t)a + (uint64_t)b + (uint64_t)cin;
    uint32_t r = (uint32_t)u;
    nk_set_nz(c, r);
    nk_setf(c, NK_FLAG_C, (uint32_t)(u >> 32));
    nk_setf(c, NK_FLAG_V, (~(a ^ b) & (a ^ r)) >> 31);
    return r;
}
static inline uint32_t nk_sub_flags(nk_cpu_t* c, uint32_t a, uint32_t b) {
    uint32_t r = a - b;
    nk_set_nz(c, r);
    nk_setf(c, NK_FLAG_C, a >= b);
    nk_setf(c, NK_FLAG_V, ((a ^ b) & (a ^ r)) >> 31);
    return r;
}

/* ---- register-amount shifts (Rs[7:0]; C shift by >= width is UB) ---- */
static inline uint32_t nk_lsl(uint32_t v, uint32_t amt){ amt&=0xff; return amt>=32?0u:(v<<amt); }
static inline uint32_t nk_lsr(uint32_t v, uint32_t amt){ amt&=0xff; return amt>=32?0u:(v>>amt); }
static inline uint32_t nk_asr(uint32_t v, uint32_t amt){ amt&=0xff; if(amt>=32)amt=31; return (uint32_t)((int32_t)v>>amt); }
static inline uint32_t nk_ror(uint32_t v, uint32_t amt){ amt&=0xff; amt&=31; return amt?((v>>amt)|(v<<(32-amt))):v; }

/* ---- guest -> native dispatch (impl in nokia_rt.c) ---- */
typedef void (*nk_fn)(nk_cpu_t*);
void nk_register(uint32_t guest_addr, nk_fn fn);   /* populate the table at startup */
void nk_call(nk_cpu_t* c, uint32_t guest_addr);    /* bl / indirect / tail dispatch */
void nk_unimplemented(nk_cpu_t* c, uint32_t guest_addr, const char* what);
void nk_game_register(void);                       /* register all lifted funcs (generated) */

#ifdef __cplusplus
}
#endif
#endif /* NOKIA_RT_H */
