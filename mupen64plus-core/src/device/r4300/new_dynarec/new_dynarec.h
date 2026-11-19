/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *   Mupen64plus - new_dynarec.h                                           *
 *   Mupen64Plus homepage: https://mupen64plus.org/                        *
 *   Copyright (C) 2002 Hacktarux                                          *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.          *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef M64P_DEVICE_R4300_NEW_DYNAREC_H
#define M64P_DEVICE_R4300_NEW_DYNAREC_H

#include "device/r4300/recomp_types.h" /* for precomp_instr */

#include <stddef.h>
#include <stdint.h>

#define NEW_DYNAREC_X86 1
#define NEW_DYNAREC_X64 2
#define NEW_DYNAREC_ARM 3
#define NEW_DYNAREC_ARM64 4

#define WRITE_PROTECT ((uintptr_t)1<<((sizeof(uintptr_t)<<3)-2))

struct r4300_core;

/* This struct contains "hot" variables used by the new_dynarec
 *
 * For the ARM version, care has been taken to place struct members at offsets within LDR/STR offsets ranges.
 * TODO: add static_asserts to verify that offsets are within LDR/STR offsets ranges.
 */

struct new_dynarec_hot_state
{
#ifdef NEW_DYNAREC
    /* 0-6:   used by dynarec to push/pop caller-saved register (r0-r3, r12) and possibly lr (see invalidate_addr)
       7-15:  saved_context*/
#if (NEW_DYNAREC == NEW_DYNAREC_ARM64) || (NEW_DYNAREC == NEW_DYNAREC_X64)
    uint64_t dynarec_local[32];
#else
    uint32_t dynarec_local[16];
#endif
    int cycle_count;
    int pending_exception;
    int pcaddr;
    int stop;
    char* invc_ptr;
    uint32_t address;
    uint64_t rdword;
    uint64_t wdword;
    uint32_t wword;
    uint32_t cp1_fcr0;
    uint32_t cp1_fcr31;
    int64_t  regs[32];
    int64_t  hi;
    int64_t  lo;
    uint32_t cp0_regs[32];
    uint64_t cp0_latch;
    float* cp1_regs_simple[32];
    double* cp1_regs_double[32];
    uint64_t cp2_latch;
    uint32_t rounding_modes[4];
    int branch_target;
    struct precomp_instr* pc;
    struct precomp_instr fake_pc;
    int64_t rs;
    int64_t rt;
    int64_t rd;
    intptr_t ram_offset;
    uintptr_t mini_ht[32][2];
    /* retro-trainer PLAN-handheld HH-33: the helpers an AOT-shaped block calls, by index
       (assem_arm64.c, aot_import_index), loaded off FP so the block holds no host address */
#if NEW_DYNAREC == NEW_DYNAREC_ARM64
    uintptr_t aot_imports[256];
#endif
    uintptr_t memory_map[1048576];
#else
    char dummy;
#endif
};

extern unsigned int stop_after_jal;
extern unsigned int using_tlb;

void invalidate_cached_code_new_dynarec(struct r4300_core* r4300, uint32_t address, size_t size);
void new_dynarec_init(void);
void new_dyna_start(void);
void new_dynarec_cleanup(void);
/* retro-trainer PLAN-handheld HH-33/HH-36: the arm64 dynarec's AOT form (arm64/aot_arm64.c), from
 * the next new_dynarec_init on. mode: NULL or "" for the stock dynarec, or "load"; an RT_TRACE build
 * also has "shape", "emit" and "hybrid". image: the image dylib a load or hybrid run reads, or the
 * path an emit writes its .code and .meta beside. log: the compile log a shape or hybrid run
 * writes, or the one an emit reads. corrupt: an emit's block to corrupt on purpose, or 0.
 * core_uuid: the LC_UUID ("8-4-4-4-12") of the core build an emit's image is for, or NULL for the
 * emitting core's own. A no-op on the other dynarecs. */
void new_dynarec_aot_configure(const char *mode, const char *image, const char *log, unsigned int corrupt,
                               const char *core_uuid);
/* Whether the dynarec may start (r4300_execute asks first): a load whose image this core refuses,
 * or a build that cannot JIT with no image configured, answers 0 and says why on stderr, and the
 * cached interpreter runs instead. 1 on the other dynarecs. */
int new_dynarec_aot_admits(void);

#endif /* M64P_DEVICE_R4300_NEW_DYNAREC_H */
