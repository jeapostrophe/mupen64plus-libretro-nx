/* retro-trainer's instruction trace (its PLAN-handheld HH-32).
 *
 * In a build with RT_TRACE defined (the macOS build: the Makefile's osx branch), when the
 * RT_TRACE environment variable names a file as the cached interpreter starts, every R4300
 * instruction the cached interpreter executes is counted by its (virtual address, instruction
 * word), and the counts are written to that file in retro-trainer's `rt-trace 1` format: its
 * cores/README.md, "Instruction traces", is the one statement of the format. Without RT_TRACE
 * the hooks compile to nothing. */
#ifndef M64P_DEVICE_R4300_RT_TRACE_H
#define M64P_DEVICE_R4300_RT_TRACE_H

#include <stdint.h>

#ifdef RT_TRACE
extern int rt_trace_on;
void rt_trace_count(uint32_t addr);
void rt_trace_start(void);
void rt_trace_decoded(uint32_t addr, uint32_t iw);
void rt_trace_reset_page(uint32_t addr);
void rt_trace_stop(void);
/* One execution of the instruction at addr. */
#define RT_TRACE_HIT(addr) do { if (rt_trace_on) rt_trace_count(addr); } while (0)
#else
#define RT_TRACE_HIT(addr) do { } while (0)
static inline void rt_trace_start(void) { }
static inline void rt_trace_decoded(uint32_t addr, uint32_t iw) { (void)addr; (void)iw; }
static inline void rt_trace_reset_page(uint32_t addr) { (void)addr; }
static inline void rt_trace_stop(void) { }
#endif

#endif /* M64P_DEVICE_R4300_RT_TRACE_H */
