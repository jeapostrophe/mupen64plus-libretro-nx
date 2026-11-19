/* retro-trainer's instruction trace: rt_trace.h says what it is.
 *
 * The cached interpreter keeps one decoded array per 4 KB page, and decodes past the page's end
 * into the array's spare slots, so one address can hold a decoded word in two arrays at once.
 * Its counts are therefore kept per slot of the array that ran it, beside the word decoded
 * there. The pure interpreter fetches the word it runs, so its counts are kept per address. A
 * count is written out (and zeroed) when its word is replaced by another, when the cached
 * interpreter resets the page, and when the trace stops: at the interpreter's end, or at
 * process exit when the emulation never returned. */
#ifdef RT_TRACE

#include "rt_trace.h"

#include <stdio.h>
#include <stdlib.h>

#include "api/callbacks.h"
#include "api/m64p_types.h"
#include "cached_interp.h"
#include "recomp_types.h"

#define PAGES 0x100000
/* get_block_memsize's slot count for a 4 KB page: 1024, its FIN_BLOCK, and the spare quarter. */
#define BLOCK_SLOTS (1024 + 1 + 256)
#define PAGE_SLOTS 1024

struct slot
{
    uint64_t hits;
    uint32_t iw;
    uint32_t decoded;
};

int rt_trace_on;
static FILE *out;
/* Per page: the cached interpreter's slots, and the pure interpreter's addresses. */
static struct slot **blocks, **words;

static void flush(uint32_t addr, struct slot *s)
{
    if (s->decoded && s->hits)
        fprintf(out, "r4300 %08x %08x %llu\n", addr, s->iw, (unsigned long long)s->hits);
    s->hits = 0;
    s->decoded = 0;
}

static void flush_page(struct slot *p, uint32_t pg, int n)
{
    for (int i = 0; i < n; i++) flush((pg << 12) + 4 * (uint32_t)i, &p[i]);
}

static struct slot *page(struct slot **table, uint32_t pg, int n)
{
    if (!table[pg]) table[pg] = calloc(n, sizeof(struct slot));
    return table[pg];
}

static void stop_at_exit(void) { rt_trace_stop(); }

void rt_trace_start(void)
{
    static int registered;
    const char *path = getenv("RT_TRACE");
    rt_trace_stop();
    if (!path || !*path) return;
    out = fopen(path, "w");
    blocks = calloc(PAGES, sizeof(*blocks));
    words = calloc(PAGES, sizeof(*words));
    if (!out || !blocks || !words) {
        DebugMessage(M64MSG_ERROR, "RT_TRACE: cannot trace to %s", path);
        if (out) fclose(out);
        free(blocks);
        free(words);
        out = NULL;
        blocks = words = NULL;
        return;
    }
    setvbuf(out, NULL, _IOFBF, 1 << 20);
    fputs("rt-trace 1\n", out);
    if (!registered) { atexit(stop_at_exit); registered = 1; }
    rt_trace_on = 1;
    DebugMessage(M64MSG_INFO, "RT_TRACE: tracing executed instructions to %s", path);
}

void rt_trace_count(const struct precomp_block *block, const struct precomp_instr *inst)
{
    struct slot *p = blocks[block->start >> 12];
    ptrdiff_t i = inst - block->block;
    /* A FIN_BLOCK is no instruction: it counts the one it runs, after its jump. */
    if (p && i >= 0 && i < BLOCK_SLOTS && inst->ops != cached_interp_FIN_BLOCK) p[i].hits++;
}

/* The cached interpreter decoded iw into the block's slot. Decoding a slot that held no decoded
 * word zeroes its count: the NOTCOMPILED dispatch that asked for the decode was counted there,
 * and the instruction's own execution is counted once more by cached_interp_NOTCOMPILED. */
void rt_trace_decoded(const struct precomp_block *block, int slot, uint32_t iw)
{
    struct slot *p, *s;
    if (!rt_trace_on || slot < 0 || slot >= BLOCK_SLOTS) return;
    if (!(p = page(blocks, block->start >> 12, BLOCK_SLOTS))) return;
    s = &p[slot];
    if (!s->decoded || s->iw != iw) flush(block->start + 4 * (uint32_t)slot, s);
    s->iw = iw;
    s->decoded = 1;
}

void rt_trace_reset_block(const struct precomp_block *block)
{
    struct slot *p;
    if (!rt_trace_on || !(p = blocks[block->start >> 12])) return;
    flush_page(p, block->start >> 12, BLOCK_SLOTS);
}

void rt_trace_fetched(uint32_t addr, uint32_t iw)
{
    struct slot *p = page(words, addr >> 12, PAGE_SLOTS), *s;
    if (!p) return;
    s = &p[(addr >> 2) & (PAGE_SLOTS - 1)];
    if (s->decoded && s->iw != iw) flush(addr, s);
    s->iw = iw;
    s->decoded = 1;
    s->hits++;
}

void rt_trace_stop(void)
{
    if (!rt_trace_on) return;
    rt_trace_on = 0;
    for (uint32_t pg = 0; pg < PAGES; pg++) {
        if (blocks[pg]) flush_page(blocks[pg], pg, BLOCK_SLOTS);
        if (words[pg]) flush_page(words[pg], pg, PAGE_SLOTS);
        free(blocks[pg]);
        free(words[pg]);
    }
    free(blocks);
    free(words);
    blocks = words = NULL;
    fclose(out);
    out = NULL;
}

#endif /* RT_TRACE */
