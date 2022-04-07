/*===-- LICENSE -------------------------------------------------------------===
 * Developed by:
 *
 *    Research Group of Professor Vikram Adve in the Department of Computer
 *    Science The University of Illinois at Urbana-Champaign
 *    http://web.engr.illinois.edu/~vadve/Home.html
 *
 * Copyright (c) 2015, Nathan Dautenhahn
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *===------------------------------------------------------------------------===
 *
 *       Filename:  stats.c
 *
 *    Description:  Statistic summary of Memorizer data
 *
 *===------------------------------------------------------------------------===
 */

#include <linux/debugfs.h>
#include <linux/printk.h>
#include <linux/seq_file.h>

#include <linux/memorizer.h>
#include "stats.h"
#include "kobj_metadata.h"

#ifdef CONFIG_MEMORIZER_STATS

//==-- Debug and Stats Output Code --==//

/* syntactic sugar to reduce line length below */
static __always_inline int64_t geta(atomic64_t * a) { return atomic64_read(a); }
static __always_inline void inca(atomic64_t * a) { atomic64_inc(a); }
static __always_inline void adda(uint64_t i, atomic64_t * a){atomic64_add(i,a);}

/* stats data structure accounting for each type of alloc */
static atomic64_t untracked_refs[NumAllocTypes];
static atomic64_t tracked_refs[NumAllocTypes];
static atomic64_t tracked_allocs[NumAllocTypes];
static atomic64_t untracked_bytes_accessed[NumAllocTypes];
static atomic64_t tracked_bytes_accessed[NumAllocTypes];
static uint64_t bytes_accessed_overflows = 0;

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
static atomic64_t num_stack_accesses = ATOMIC_INIT(0);
static atomic64_t num_accesses_while_disabled = ATOMIC_INIT(0);
static atomic64_t num_untracked_obj_access = ATOMIC_INIT(0);

char * alloc_type_str(enum AllocType AT)
{
	switch(AT)
	{
		case MEM_STACK:
			return "STACK";
		case MEM_STACK_FRAME:
			return "STACK_FRAME";
		case MEM_STACK_ARGS:
			return "STACK_ARGS";
		case MEM_STACK_PAGE:
			return "STACK_PAGE";
		case MEM_HEAP:
			return "GEN_HEAP";
		case MEM_UFO_HEAP:
			return "UFO_HEAP";
		case MEM_GLOBAL:
			return "GLOBAL";
		case MEM_KMALLOC:
			return "KMALLOC";
		case MEM_KMALLOC_ND:
			return "KMALLOC_ND";
		case MEM_KMEM_CACHE:
			return "KMEM_CACHE";
		case MEM_KMEM_CACHE_ND:
			return "KMEM_CACHE_ND";
		case MEM_ALLOC_PAGES:
			return "ALLOC_PAGES";
		case MEM_VMALLOC:
			return "VMALLOC";
		case MEM_INDUCED:
			return "INDUCED_ALLOC";
		case MEM_BOOTMEM:
			return "BOOTMEM";
		case MEM_MEMBLOCK:
			return "MEMBLOCK";
		case MEM_UFO_MEMBLOCK:
			return "UFO_MEMBLOCK";
		case MEM_MEMORIZER:
			return "MEMORIZER";
		case MEM_USER:
			return "USER";
		case MEM_BUG:
			return "BUG";
		case MEM_UFO_GLOBAL:
			return "UFO_GLOBAL";
		case MEM_UFO_NONE:
			return "UFO_NONE";
		case MEM_NONE:
			return "NONE";
		default:
			pr_info("Searching for unavailable alloc type");
			return "ALLOC TYPE NOT FOUND";
	}
};

void __always_inline
track_access(enum AllocType AT, uint64_t size)
{
    inca(&tracked_kobj_accesses);
    if (AT<NumAllocTypes) {
        inca(&tracked_refs[AT]);
        adda(size, &tracked_bytes_accessed[AT]);
        if(geta(&tracked_bytes_accessed[AT]) < 0)
            bytes_accessed_overflows = 0;
    }
}

void __always_inline
track_induced_access(void)
{
    inca(&num_induced_accesses);
}

void __always_inline
track_stack_access(void)
{
    inca(&num_stack_accesses);
}

void __always_inline
track_disabled_access(void)
{
    inca(&num_accesses_while_disabled);
}

void __always_inline
track_untracked_access(enum AllocType AT, uint64_t size)
{
    inca(&num_untracked_obj_access);
    if (AT<NumAllocTypes) {
        inca(&untracked_refs[AT]);
        adda(size, &untracked_bytes_accessed[AT]);
        if (geta(&untracked_bytes_accessed[AT]) < 0)
            bytes_accessed_overflows = 0;
    }
}

/* General object info */
static atomic64_t num_allocs_while_disabled = ATOMIC_INIT(0);
static atomic64_t num_induced_allocs = ATOMIC_INIT(0);
static atomic64_t stats_frees = ATOMIC_INIT(0);
static atomic64_t num_induced_frees = ATOMIC_INIT(0);
static atomic64_t stats_untracked_obj_frees = ATOMIC_INIT(0);
static atomic64_t stats_kobj_frees = ATOMIC_INIT(0);
static atomic64_t failed_kobj_allocs = ATOMIC_INIT(0);
static atomic64_t num_access_counts = ATOMIC_INIT(0);

void __always_inline track_disabled_alloc(void) { inca(&num_allocs_while_disabled); }
void __always_inline track_induced_alloc(void) { inca(&num_induced_allocs); }
void __always_inline track_free(void) { inca(&stats_frees); }
void __always_inline track_untracked_obj_free(void) { inca(&stats_untracked_obj_frees); }
void __always_inline track_induced_free(void) { inca(&num_induced_frees); }
void __always_inline track_kobj_free(void) { inca(&stats_kobj_frees); }
void __always_inline track_failed_kobj_alloc(void) { inca(&failed_kobj_allocs); }
void __always_inline track_access_counts_alloc(void) { inca(&num_access_counts); }

void __always_inline track_alloc(enum AllocType AT)
{
    if (AT > NumAllocTypes) {
        pr_info("Bad allocation type for memorizer!");
        return;
    }
    inca(&tracked_allocs[AT]);
}

void lt_pr_stats(size_t pr_level)
{
    int64_t l3s = geta(&num_l3);
    int64_t l2s = geta(&num_l2);
    int64_t l1s = geta(&num_l1);
	printk(KERN_CRIT "------- Memorizer LT Stats -------\n");
	printk(KERN_CRIT "  L3: %8lld tbls * %6llu KB = %6llu MB\n",
            l3s, l3size>>10, (l3s*l3size)>>20);
	printk(KERN_CRIT "  L2: %8lld tbls * %6llu KB = %6llu MB\n",
            l2s, l2size>>10, (l2s*l2size)>>20);
	printk(KERN_CRIT "  L1: %8lld tbls * %6llu KB = %6llu MB\n",
            l1s, l1size>>10, (l1s*l1size)>>20);
}

void lt_pr_stats_seq(struct seq_file *seq)
{
    int64_t l3s = 1;
    int64_t l2s = geta(&num_l2);
    int64_t l1s = geta(&num_l1);
	seq_printf(seq,"------- Memorizer LT Stats -------\n");
	seq_printf(seq,"  L3: %8lld tbls * %6lld KB = %6lld MB\n",
            l3s, l3size>>10, (l3s*l3size)>>20);
	seq_printf(seq,"  L2: %8lld tbls * %6lld KB = %6lld MB\n",
            l2s, l2size>>10, (l2s*l2size)>>20);
	seq_printf(seq,"  L1: %8lld tbls * %6lld KB = %6lld MB\n",
            l1s, l1size>>10, (l1s*l1size)>>20);
}

static int64_t _total_tracked_refs(void)
{
    int i;
    int64_t total = 0;
    for (i = 0; i < NumAllocTypes; i++)
            total += geta(&tracked_refs[i]);
    return total;
}

static int64_t _total_untracked_refs(void)
{
    int64_t i;
    int64_t total = 0;
    for (i = 0; i < NumAllocTypes; i++)
            total += geta(&untracked_refs[i]);
    return total;
}

static size_t _percent_refs_hit(void)
{
    return (_total_tracked_refs() || _total_untracked_refs()) ?
            100*_total_tracked_refs() /
            (_total_untracked_refs()+_total_tracked_refs()) : 0;
}

static int64_t _total_tracked_bytes(void)
{
    int i;
    int64_t total = 0;
    for (i = 0; i < NumAllocTypes; i++)
            total += geta(&tracked_bytes_accessed[i]);
    return total;
}

static int64_t _total_untracked_bytes(void)
{
    int64_t i;
    int64_t total = 0;
    for (i = 0; i < NumAllocTypes; i++)
            total += geta(&untracked_bytes_accessed[i]);
    return total;
}

static size_t _percent_bytes_hit(void)
{
    return (_total_tracked_bytes() || _total_untracked_bytes()) ?
            100*_total_tracked_bytes() /
            (_total_untracked_bytes()+_total_tracked_bytes()) : 0;
}

static int64_t _total_tracked(void)
{
    int64_t i;
    int64_t total = 0;
    for ( i = 0; i < NumAllocTypes; i++)
            total += geta(&tracked_allocs[i]);
    return total;
}

static uint64_t _live_objs(void)
{
    return _total_tracked() - geta(&stats_frees);
}

static int64_t _total_accesses(void)
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
    int i;
    printk(KERN_CRIT "------- Memory Accesses -------\n");
    printk(KERN_CRIT "   Tracked:%16lld\n", geta(&tracked_kobj_accesses));
    printk(KERN_CRIT "   Missing:%16lld\n", geta(&num_untracked_obj_access));
    printk(KERN_CRIT "   Induced:%16lld\n", geta(&num_induced_accesses));
    printk(KERN_CRIT "  Disabled:%16lld\n", geta(&num_accesses_while_disabled));
    printk(KERN_CRIT "    ---------------------------\n");
    printk(KERN_CRIT "  Total Obs:    %16lld\n", _total_accesses());

/* Print out the access counts */
    printk(KERN_CRIT "------- Per Object Access Count (hit/miss) -------\n");
    for ( i = 0; i < NumAllocTypes; i++) {
            printk(KERN_CRIT "   %-15s: %16lld, %16lld\n",
                            alloc_type_str(i), geta(&tracked_refs[i]),
			geta(&untracked_refs[i]));
	}

    printk(KERN_CRIT "    ---------------------------\n");
    printk(KERN_CRIT "   %-15s: %16lld, %16lld --- %d%% hit rate\n", "Total",
                    _total_tracked_refs(), _total_untracked_refs(),
                    (int)_percent_refs_hit());

	/* Print out the byte counts using simple total bytes accessed */
	printk(KERN_CRIT "------- Per Object Bytes Accessed (hit/miss) -------\n");
    for (i = 0; i < NumAllocTypes; i++) {
        printk(KERN_CRIT "   %-15s: %16lld, %16lld\n",
		alloc_type_str(i),
		geta(&tracked_bytes_accessed[i]),
		geta(&untracked_bytes_accessed[i]));
	}

    printk(KERN_CRIT "    ---------------------------\n");
    printk(KERN_CRIT "   %-15s: %16lld, %16lld --- %d%% hit rate\n", "Total",
                    _total_tracked_bytes(), _total_untracked_bytes(),
                    (int)_percent_bytes_hit());
	printk(KERN_CRIT "    ****** We had %lld overflows on byte counters.\n",
	       bytes_accessed_overflows);

	/* Print aggregate memory alloc stats for mem types */
    printk(KERN_CRIT "------- Tracked Memory Allocations -------\n");
    for (i = 0; i < NumAllocTypes; i++) {
            printk(KERN_CRIT "   %-15s: %16lld\n",
                            alloc_type_str(i), geta(&tracked_allocs[i]));
    }
    printk(KERN_CRIT "        ------\n");
    printk(KERN_CRIT "  Total:        %16lld\n", _total_tracked());
    printk(KERN_CRIT "  Frees:        %16lld\n", geta(&stats_frees));
    printk(KERN_CRIT "  Live Now:     %16lld\n", _live_objs());

	/* Print out info on missing allocations */
	/* -- TODO: depracated and can probably remove */
    printk(KERN_CRIT "------- Missing Allocs -------\n");
    printk(KERN_CRIT "  Mem disabled: %16lld\n", geta(&num_allocs_while_disabled));
    printk(KERN_CRIT "  Allocs(InMem):%16lld\n", geta(&num_induced_allocs));
    printk(KERN_CRIT "  Frees(InMem): %16lld\n", geta(&num_induced_frees));
    printk(KERN_CRIT "  Frees(NoObj): %16lld\n", geta(&stats_untracked_obj_frees));
    printk(KERN_CRIT "  kobj fails:   %16lld\n", geta(&failed_kobj_allocs));

    printk(KERN_CRIT "------- Internal Allocs -------\n");
    /* TODO: right now if we don't drain inline then this is total tracked */
    printk(KERN_CRIT "  Live KOBJs: %10lld * %lu B = %6llu MB\n",
                    _total_tracked()-geta(&stats_kobj_frees), sizeof(struct
                            memorizer_kobj),
                    (_total_tracked()-geta(&stats_kobj_frees)) * sizeof(struct
                            memorizer_kobj) >> 20 );

    printk(KERN_CRIT "  Total Edgs: %10lld * %lu B = %6llu MB\n",
                    geta(&num_access_counts), sizeof(struct access_from_counts),
                    geta(&num_access_counts)*sizeof(struct access_from_counts)>>20);

    lt_pr_stats(pr_level);
}

int seq_print_stats(struct seq_file *seq)
{
	int i;
	seq_printf(seq,"------- Memory Accesses -------\n");
	seq_printf(seq,"  Tracked:      %16lld\n", geta(&tracked_kobj_accesses));
	seq_printf(seq,"  Missing:      %16lld\n", geta(&num_untracked_obj_access));
	seq_printf(seq,"  Induced:      %16lld\n", geta(&num_induced_accesses));
	seq_printf(seq,"  Disabled:     %16lld\n", geta(&num_accesses_while_disabled));
	seq_printf(seq,"    ---------------------------\n");
	seq_printf(seq,"  Total Obs:    %16lld\n", _total_accesses());

	seq_printf(seq,"------- Per Object Access Count (hit/miss) -------\n");
	for (i = 0; i < NumAllocTypes; i++) {
		seq_printf(seq,"   %-15s: %16lld, %16lld\n",
			   alloc_type_str(i), geta(&tracked_refs[i]),
			   geta(&untracked_refs[i]));
	}

	seq_printf(seq,"    ---------------------------\n");
	seq_printf(seq,"   %-15s: %16lld, %16lld --- %lu%% hit rate\n", "Total",
		   _total_tracked_refs(), _total_untracked_refs(),
		   _percent_refs_hit());

	/* Print out the byte counts using simple total bytes accessed */
	seq_printf(seq,"------- Per Object Bytes Accessed (hit/miss) -------\n");
	for (i = 0; i < NumAllocTypes; i++) {
		seq_printf(seq,"   %-15s: %16lld, %16lld\n",
			   alloc_type_str(i),
			   geta(&tracked_bytes_accessed[i]),
			   geta(&untracked_bytes_accessed[i]));
	}

	seq_printf(seq,"    ---------------------------\n");
	seq_printf(seq,"   %-15s: %16lld, %16lld --- %lu%% hit rate\n", "Total",
		   _total_tracked_bytes(), _total_untracked_bytes(),
		   _percent_bytes_hit());
	seq_printf(seq,"    ****** We had %lld overflows on byte counters.\n",
	       bytes_accessed_overflows);

	seq_printf(seq,"------- Tracked Memory Allocations -------\n");
	for (i = 0; i < NumAllocTypes; i++) {
		seq_printf(seq,"   %-15s: %16lld\n",
			   alloc_type_str(i), geta(&tracked_allocs[i]));
	}
	seq_printf(seq,"        ------\n");
	seq_printf(seq,"  Total:        %16lld\n", _total_tracked());
	seq_printf(seq,"  Frees:        %16lld\n", geta(&stats_frees));
	seq_printf(seq,"  Live Now:     %16lld\n", _live_objs());

	seq_printf(seq,"------- Missing Allocs -------\n");
	seq_printf(seq,"  Mem disabled: %16lld\n", geta(&num_allocs_while_disabled));
	seq_printf(seq,"  Allocs(InMem):%16lld\n", geta(&num_induced_allocs));
	seq_printf(seq,"  Frees(InMem): %16lld\n", geta(&num_induced_frees));
	seq_printf(seq,"  Frees(NoObj): %16lld\n", geta(&stats_untracked_obj_frees));
	seq_printf(seq,"  kobj fails:   %16lld\n", geta(&failed_kobj_allocs));

	seq_printf(seq,"------- Internal Allocs -------\n");
	/* TODO: right now if we don't drain inline then this is total tracked */
	seq_printf(seq,"  Live KOBJs: %10lld * %lu B = %6lld MB\n",
		   _total_tracked()-geta(&stats_kobj_frees),
		   sizeof(struct memorizer_kobj),
		   (_total_tracked()-geta(&stats_kobj_frees)) * sizeof(struct memorizer_kobj) >> 20 );

	seq_printf(seq,"  Total Edges: %10lld * %lu B = %6llu MB\n",
		   geta(&num_access_counts), sizeof(struct access_from_counts),
		   geta(&num_access_counts) * sizeof(struct access_from_counts)>>20);
	lt_pr_stats_seq(seq);
	return 0;
}

#endif /* CONFIG_MEMORIZER_STATS */
