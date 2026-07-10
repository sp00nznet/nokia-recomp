/*
 * nokia-recomp — ARMv4T (ARM7TDMI) guest CPU context.
 *
 * The shape the recompiler's emitted C targets: one generated function per guest
 * function, each taking a pointer to this context and operating on guest
 * registers / flags / memory directly. Ported from ngagerecomp.
 */
#ifndef NOKIA_CPU_H
#define NOKIA_CPU_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nk_cpu {
    uint32_t r[16];   /* r0..r15; r13=sp, r14=lr, r15=pc */
    uint32_t cpsr;    /* NZCV condition flags (+ mode bits, later) */
    uint8_t* mem;     /* flat guest address space (single-VA model) */
} nk_cpu_t;

enum { NK_FLAG_N = 31, NK_FLAG_Z = 30, NK_FLAG_C = 29, NK_FLAG_V = 28 };

#ifdef __cplusplus
}
#endif
#endif /* NOKIA_CPU_H */
