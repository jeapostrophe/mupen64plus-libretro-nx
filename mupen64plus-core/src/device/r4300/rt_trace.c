/* retro-trainer's instruction trace: rt_trace.h says what it is.
 *
 * Counts are kept per virtual address, beside the instruction word the cached interpreter last
 * decoded there. A count is written out (and zeroed) when that word is replaced by another, when
 * the interpreter resets the page, and when the trace stops: at the cached interpreter's end, or
 * at process exit when the emulation thread never returned. */
#ifdef RT_TRACE

#include "rt_trace.h"

#include <stdio.h>
#include <stdlib.h>

#include "api/callbacks.h"
#include "api/m64p_types.h"

#define PAGES 0x100000
#define SLOTS 0x400

struct slot
{
    uint64_t hits;
    uint32_t iw;
    uint32_t decoded;
};

int rt_trace_on;
static FILE *out;
static struct slot **pages;

static void flush(uint32_t addr, struct slot *s)
{
    if (s->decoded && s->hits)
        fprintf(out, "r4300 %08x %08x %llu\n", addr, s->iw, (unsigned long long)s->hits);
    s->hits = 0;
    s->decoded = 0;
}

static void stop_at_exit(void) { rt_trace_stop(); }

void rt_trace_start(void)
{
    static int registered;
    const char *path = getenv("RT_TRACE");
    rt_trace_stop();
    if (!path || !*path) return;
    out = fopen(path, "w");
    pages = calloc(PAGES, sizeof(*pages));
    if (!out || !pages) {
        DebugMessage(M64MSG_ERROR, "RT_TRACE: cannot trace to %s", path);
        if (out) fclose(out);
        free(pages);
        out = NULL;
        pages = NULL;
        return;
    }
    setvbuf(out, NULL, _IOFBF, 1 << 20);
    fputs("rt-trace 1\n", out);
    if (!registered) { atexit(stop_at_exit); registered = 1; }
    rt_trace_on = 1;
    DebugMessage(M64MSG_INFO, "RT_TRACE: tracing executed instructions to %s", path);
}

void rt_trace_count(uint32_t addr)
{
    struct slot *p = pages[addr >> 12];
    if (p) p[(addr >> 2) & (SLOTS - 1)].hits++;
}

/* The cached interpreter decoded iw at addr. Decoding a slot that held no decoded word zeroes its
 * count: the NOTCOMPILED dispatch that asked for the decode was counted there, and the
 * instruction's own execution is counted once more by cached_interp_NOTCOMPILED. */
void rt_trace_decoded(uint32_t addr, uint32_t iw)
{
    struct slot *p, *s;
    if (!rt_trace_on) return;
    p = pages[addr >> 12];
    if (!p) {
        p = pages[addr >> 12] = calloc(SLOTS, sizeof(*p));
        if (!p) return;
    }
    s = &p[(addr >> 2) & (SLOTS - 1)];
    if (s->decoded && s->iw != iw) flush(addr, s);
    if (!s->decoded) s->hits = 0;
    s->iw = iw;
    s->decoded = 1;
}

void rt_trace_reset_page(uint32_t addr)
{
    struct slot *p;
    uint32_t base = addr & ~UINT32_C(0xfff);
    if (!rt_trace_on || !(p = pages[addr >> 12])) return;
    for (uint32_t i = 0; i < SLOTS; i++) flush(base + 4 * i, &p[i]);
}

void rt_trace_stop(void)
{
    if (!rt_trace_on) return;
    for (uint32_t pg = 0; pg < PAGES; pg++) {
        if (!pages[pg]) continue;
        rt_trace_reset_page(pg << 12);
        free(pages[pg]);
    }
    rt_trace_on = 0;
    free(pages);
    pages = NULL;
    fclose(out);
    out = NULL;
}

#endif /* RT_TRACE */
