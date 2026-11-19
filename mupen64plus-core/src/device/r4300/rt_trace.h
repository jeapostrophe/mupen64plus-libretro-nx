/* retro-trainer's instruction trace (its PLAN-handheld HH-32).
 *
 * In a build with RT_TRACE defined (the macOS build: the Makefile's osx branch), when the
 * RT_TRACE environment variable names a file as an interpreter starts, every R4300 instruction
 * the cached or the pure interpreter executes is counted by its (virtual address, instruction
 * word), and the counts are written to that file in retro-trainer's `rt-trace 1` format: its
 * cores/README.md, "Instruction traces", is the one statement of the format. A process traces
 * one emulation: a second start truncates the file. Without RT_TRACE the hooks compile to
 * nothing. */
#ifndef M64P_DEVICE_R4300_RT_TRACE_H
#define M64P_DEVICE_R4300_RT_TRACE_H

#include <stdint.h>

struct precomp_block;
struct precomp_instr;

#ifdef RT_TRACE
extern int rt_trace_on;
void rt_trace_start(void);
void rt_trace_stop(void);
/* The cached interpreter: counts kept per slot of each block's decoded array. */
void rt_trace_count(const struct precomp_block *block, const struct precomp_instr *inst);
void rt_trace_decoded(const struct precomp_block *block, int slot, uint32_t iw);
void rt_trace_reset_block(const struct precomp_block *block);
/* The pure interpreter: counts kept per address, of the word fetched there. */
void rt_trace_fetched(uint32_t addr, uint32_t iw);
/* One execution of the cached interpreter's current instruction. */
#define RT_TRACE_HIT(r4300) do { if (rt_trace_on) \
    rt_trace_count((r4300)->cached_interp.actual, *r4300_pc_struct(r4300)); } while (0)
#define RT_TRACE_FETCH(addr, iw) do { if (rt_trace_on) rt_trace_fetched(addr, iw); } while (0)
#else
#define RT_TRACE_HIT(r4300) do { } while (0)
#define RT_TRACE_FETCH(addr, iw) do { } while (0)
static inline void rt_trace_start(void) { }
static inline void rt_trace_stop(void) { }
static inline void rt_trace_decoded(const struct precomp_block *b, int s, uint32_t iw) { (void)b; (void)s; (void)iw; }
static inline void rt_trace_reset_block(const struct precomp_block *b) { (void)b; }
#endif

#endif /* M64P_DEVICE_R4300_RT_TRACE_H */
