/*===-- LICENSE -------------------------------------------------------------===
 * 
 * University of Illinois/NCSA Open Source License 
 *
 * Copyright (C) 2018, The Board of Trustees of the University of Illinois.
 * All rights reserved. 
 *
 * Developed by: 
 *
 *    Research Group of Professor Vikram Adve in the Department of Computer
 *    Science The University of Illinois at Urbana-Champaign
 *    http://web.engr.illinois.edu/~vadve/Home.html
 *
 * Copyright (c) 2018, Nathan Dautenhahn
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the Software), to deal
 * with the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions: 
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimers. 
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimers in the documentation
 * and/or other materials provided with the distribution.  Neither the names of
 * Nathan Dautenhahn or the University of Illinois, nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * Software without specific prior written permission. 
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * WITH THE SOFTWARE. 
 *
 *===------------------------------------------------------------------------===
 *
 *       Filename:  stats.c
 *
 *    Description:  
 *
 *===------------------------------------------------------------------------===
 */

#include <linux/debugfs.h>
#include <linux/printk.h>
#include <linux/seq_file.h>

#include "stats.h"
#include "kobj_metadata.h"

#define pr_fmt(fmt) "memorizer: " fmt

#ifdef CONFIG_MEMORIZER_STATS
//==-- Debug and Stats Output Code --==//

/* syntactic sugar to reduce line length below */
static __always_inline uint64_t geta(atomic64_t * a) { return atomic64_read(a); }
static __always_inline void inca(atomic64_t * a) { atomic64_inc(a); }

/* Lookup Table */
static atomic64_t num_l3 = ATOMIC_INIT(0);
static atomic64_t num_l2 = ATOMIC_INIT(0);
static atomic64_t num_l1 = ATOMIC_INIT(0);
static const uint64_t l3size = sizeof(struct lt_l3_tbl);
static const uint64_t l2size = sizeof(struct lt_l2_tbl);
static const uint64_t l1size = sizeof(struct lt_l1_tbl);

void __always_inline track_l1_alloc(void){inca(&num_l1);};
void __always_inline track_l2_alloc(void){inca(&num_l2);};
void __always_inline track_l3_alloc(void){inca(&num_l3);};

/* Memory Access */
static atomic64_t tracked_kobj_accesses = ATOMIC_INIT(0);
static atomic64_t num_induced_accesses = ATOMIC_INIT(0);
static atomic64_t num_accesses_while_disabled = ATOMIC_INIT(0);
static atomic64_t num_untracked_obj_access = ATOMIC_INIT(0);

void __always_inline 
track_access(void) 
{
    inca(&tracked_kobj_accesses); 
}

void __always_inline 
track_induced_access(void) 
{
    inca(&num_induced_accesses);
}

void __always_inline 
track_disabled_access(void) 
{
    inca(&num_accesses_while_disabled);
}

void __always_inline 
track_untracked_access(void) 
{ 
    inca(&num_untracked_obj_access); 
}

/* General object info */
static atomic64_t num_allocs_while_disabled = ATOMIC_INIT(0);
static atomic64_t num_induced_allocs = ATOMIC_INIT(0);
static atomic64_t stats_frees = ATOMIC_INIT(0);
static atomic64_t stats_kobj_frees = ATOMIC_INIT(0);
static atomic64_t failed_kobj_allocs = ATOMIC_INIT(0);

void __always_inline track_disabled_alloc(void) { inca(&num_allocs_while_disabled); }
void __always_inline track_induced_alloc(void) { inca(&num_induced_allocs); }
void __always_inline track_free(void) { inca(&stats_frees); }
void __always_inline track_kobj_free(void) { inca(&stats_kobj_frees); }
void __always_inline track_failed_kobj_alloc(void) { inca(&failed_kobj_allocs); }

/* specific allocators */
static atomic64_t num_stack_allocs = ATOMIC_INIT(0);
static atomic64_t num_globals = ATOMIC_INIT(0);
static atomic64_t num_kmalloc_allocs = ATOMIC_INIT(0);
static atomic64_t num_kmem_cache_allocs = ATOMIC_INIT(0);
static atomic64_t num_page_allocs = ATOMIC_INIT(0);
static atomic64_t num_undefined_allocs = ATOMIC_INIT(0);

void __always_inline track_alloc(enum AllocType AT)
{
    switch(AT)
    {
    case MEM_STACK:
        inca(&num_stack_allocs);
        break;
    case MEM_GLOBAL:
        inca(&num_globals);
        break;
    case MEM_KMALLOC:
    case MEM_KMALLOC_ND:
        inca(&num_kmalloc_allocs);
        break;
    case MEM_KMEM_CACHE:
    case MEM_KMEM_CACHE_ND:
        inca(&num_kmem_cache_allocs);
        break;
    case MEM_ALLOC_PAGES:
        inca(&num_page_allocs);
        break;
    case MEM_NONE:
        inca(&num_undefined_allocs);
        break;
    default: 
        pr_err("No default case for track alloc: fix yourself!");
    }
}

void lt_pr_stats(size_t pr_level)
{
    uint64_t l3s = geta(&num_l3);
    uint64_t l2s = geta(&num_l2);
    uint64_t l1s = geta(&num_l1);
	printk(KERN_CRIT "------- Memorizer LT Stats -------\n");
	printk(KERN_CRIT "  L3: %8d tbls * %6llu KB = %6llu MB\n", 
            l3s, l3size>>10, (l3s*l3size)>>20);
	printk(KERN_CRIT "  L2: %8d tbls * %6llu KB = %6llu MB\n", 
            l2s, l2size>>10, (l2s*l2size)>>20);
	printk(KERN_CRIT "  L1: %8d tbls * %6llu KB = %6llu MB\n", 
            l1s, l1size>>10, (l1s*l1size)>>20);
}

void lt_pr_stats_seq(struct seq_file *seq)
{
    uint64_t l3s = 1;
    uint64_t l2s = geta(&num_l2);
    uint64_t l1s = geta(&num_l1);
	seq_printf(seq,"------- Memorizer LT Stats -------\n");
	seq_printf(seq,"  L3: %8d tbls * %6llu KB = %6llu MB\n", 
            l3s, l3size>>10, (l3s*l3size)>>20);
	seq_printf(seq,"  L2: %8d tbls * %6llu KB = %6llu MB\n", 
            l2s, l2size>>10, (l2s*l2size)>>20);
	seq_printf(seq,"  L1: %8d tbls * %6llu KB = %6llu MB\n", 
            l1s, l1size>>10, (l1s*l1size)>>20);
}

static uint64_t _total_tracked(void)
{
    return geta(&num_stack_allocs)
        + geta(&num_globals)
        + geta(&num_kmalloc_allocs)
        + geta(&num_kmem_cache_allocs)
        + geta(&num_page_allocs);
}

static uint64_t _live_objs(void)
{
    return _total_tracked() - geta(&stats_frees);
}

static uint64_t _total_accesses(void)
{
    return geta(&tracked_kobj_accesses)
        + geta(&num_induced_accesses)
        + geta(&num_accesses_while_disabled)
        + geta(&num_untracked_obj_access); 
}

/**
 * print_stats() - print global stats from memorizer 
 */
void print_stats(size_t pr_level)
{
	printk(KERN_CRIT "------- Memory Accesses -------\n");
	printk(KERN_CRIT "  Tracked:      %16llu\n", geta(&tracked_kobj_accesses));
	printk(KERN_CRIT "  Missing:      %16llu\n", geta(&num_untracked_obj_access));
	printk(KERN_CRIT "  Induced:      %16llu\n", geta(&num_induced_accesses));
	printk(KERN_CRIT "  Disabled:     %16llu\n", geta(&num_accesses_while_disabled));
	printk(KERN_CRIT "    ---------------------------\n");
	printk(KERN_CRIT "  Total Obs:    %16llu\n", _total_accesses());

	printk(KERN_CRIT "------- Tracked Memory Allocations -------\n");
	printk(KERN_CRIT "  stack:        %16llu\n", geta(&num_stack_allocs));
	printk(KERN_CRIT "  globals:      %16llu\n", geta(&num_globals));
	printk(KERN_CRIT "  kmalloc:      %16llu\n", geta(&num_kmalloc_allocs));
	printk(KERN_CRIT "  kmem_cache:   %16llu\n", geta(&num_kmem_cache_allocs));
	printk(KERN_CRIT "  page:         %16llu\n", geta(&num_page_allocs));
	printk(KERN_CRIT "        ------\n");
	printk(KERN_CRIT "  Total:        %16llu\n", _total_tracked());
	printk(KERN_CRIT "  Frees:        %16llu\n", geta(&stats_frees));
	printk(KERN_CRIT "  Live Now:     %16llu\n", _live_objs());

	printk(KERN_CRIT "------- Missing Allocs -------\n");
	printk(KERN_CRIT "  Mem disabled: %16llu\n", geta(&num_allocs_while_disabled));
	printk(KERN_CRIT "  Mem induced:  %16llu\n", geta(&num_induced_allocs));
	printk(KERN_CRIT "  kobj fails:   %16llu\n", geta(&failed_kobj_allocs));
	
    printk(KERN_CRIT "------- Internal Allocs -------\n");
    /* TODO: right now if we don't drain inline then this is total tracked */
    printk(KERN_CRIT "  Live KOBJs: %10llu * %d B = %6llu MB\n", 
            _total_tracked()-geta(&stats_kobj_frees),
            sizeof(struct memorizer_kobj), 
            (_total_tracked()-geta(&stats_kobj_frees)) * sizeof(struct memorizer_kobj) >> 20 );
    printk(KERN_CRIT "  Live Count Objs: TODO!!!!\n");

    lt_pr_stats(pr_level);
}

int seq_print_stats(struct seq_file *seq)
{
	seq_printf(seq,"------- Memory Accesses -------\n");
	seq_printf(seq,"  Tracked:      %16llu\n", geta(&tracked_kobj_accesses));
	seq_printf(seq,"  Missing:      %16llu\n", geta(&num_untracked_obj_access));
	seq_printf(seq,"  Induced:      %16llu\n", geta(&num_induced_accesses));
	seq_printf(seq,"  Disabled:     %16llu\n", geta(&num_accesses_while_disabled));
	seq_printf(seq,"    ---------------------------\n");
	seq_printf(seq,"  Total Obs:    %16llu\n", _total_accesses());

	seq_printf(seq,"------- Tracked Memory Allocations -------\n");
	seq_printf(seq,"  stack:        %16llu\n", geta(&num_stack_allocs));
	seq_printf(seq,"  globals:      %16llu\n", geta(&num_globals));
	seq_printf(seq,"  kmalloc:      %16llu\n", geta(&num_kmalloc_allocs));
	seq_printf(seq,"  kmem_cache:   %16llu\n", geta(&num_kmem_cache_allocs));
	seq_printf(seq,"  page:         %16llu\n", geta(&num_page_allocs));
	seq_printf(seq,"        ------\n");
	seq_printf(seq,"  Total:        %16llu\n", _total_tracked());
	seq_printf(seq,"  Frees:        %16llu\n", geta(&stats_frees));
	seq_printf(seq,"  Live Now:     %16llu\n", _live_objs());

	seq_printf(seq,"------- Missing Allocs -------\n");
	seq_printf(seq,"  Mem disabled: %16llu\n", geta(&num_allocs_while_disabled));
	seq_printf(seq,"  Mem induced:  %16llu\n", geta(&num_induced_allocs));
	seq_printf(seq,"  kobj fails:   %16llu\n", geta(&failed_kobj_allocs));
	
    seq_printf(seq,"------- Internal Allocs -------\n");
    /* TODO: right now if we don't drain inline then this is total tracked */
    seq_printf(seq,"  Live KOBJs: %10llu * %d B = %6llu MB\n", 
            _total_tracked()-geta(&stats_kobj_frees),
            sizeof(struct memorizer_kobj), 
            (_total_tracked()-geta(&stats_kobj_frees)) * sizeof(struct memorizer_kobj) >> 20 );
            
    seq_printf(seq,"  Live Count Objs: TODO!!!!\n");
    lt_pr_stats_seq(seq);
	return 0;
}
#endif /* CONFIG_MEMORIZER_STATS */
