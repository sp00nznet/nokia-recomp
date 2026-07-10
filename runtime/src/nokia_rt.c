/*
 * nokia-recomp — runtime dispatch + image loading.
 *
 * Minimal guest->native dispatch: a sorted table of (guest_addr, fn). nk_call
 * looks up the target and invokes the lifted C function. Anything not lifted hits
 * nk_unimplemented (loud + traceable), matching ngagerecomp's bring-up model.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nokia_rt.h"

typedef struct { uint32_t addr; nk_fn fn; } entry_t;

static entry_t* g_tab = NULL;
static size_t   g_len = 0, g_cap = 0;
static int      g_sorted = 0;

void nk_register(uint32_t addr, nk_fn fn) {
    if (g_len == g_cap) {
        g_cap = g_cap ? g_cap * 2 : 1024;
        g_tab = (entry_t*)realloc(g_tab, g_cap * sizeof(entry_t));
    }
    g_tab[g_len].addr = addr; g_tab[g_len].fn = fn; g_len++;
    g_sorted = 0;
}

static int cmp(const void* a, const void* b) {
    uint32_t x = ((const entry_t*)a)->addr, y = ((const entry_t*)b)->addr;
    return (x > y) - (x < y);
}

static nk_fn lookup(uint32_t addr) {
    if (!g_sorted) { qsort(g_tab, g_len, sizeof(entry_t), cmp); g_sorted = 1; }
    size_t lo = 0, hi = g_len;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (g_tab[mid].addr < addr) lo = mid + 1;
        else hi = mid;
    }
    if (lo < g_len && g_tab[lo].addr == addr) return g_tab[lo].fn;
    return NULL;
}

void nk_call(nk_cpu_t* c, uint32_t guest_addr) {
    nk_fn fn = lookup(guest_addr & ~1u);   /* Thumb targets carry bit0=1 */
    if (fn) { fn(c); return; }
    fprintf(stderr, "[nk_call] no function at %#010x (lr=%#010x)\n",
            guest_addr, c->r[14]);
}

void nk_unimplemented(nk_cpu_t* c, uint32_t guest_addr, const char* what) {
    (void)c;
    fprintf(stderr, "[nk_unimplemented] %#010x: %s\n", guest_addr, what);
}
