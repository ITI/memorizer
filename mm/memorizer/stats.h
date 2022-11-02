/*===-- LICENSE
 * -------------------------------------------------------------===
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
 *       Filename:  stats.h
 *
 *    Description:
 *
 *===------------------------------------------------------------------------===
 */


#ifndef _MEMSTATS_H_
#define _MEMSTATS_H_

#include <asm/atomic.h>
#include <linux/memorizer.h>
#include "kobj_metadata.h"

//==-- External Interface --==//
#ifdef CONFIG_MEMORIZER_STATS
char * alloc_type_str(enum AllocType AT);
void track_alloc(enum AllocType AT);
void track_disabled_alloc(void);
void track_induced_alloc(void);
void track_failed_kobj_alloc(void);
void track_free(void);
void track_untracked_obj_free(void);
void track_induced_free(void);
void track_kobj_free(void);
void track_access(enum AllocType AT, uint64_t size);
void track_induced_access(void);
void track_stack_access(void);
void track_disabled_access(void);
void track_untracked_access(enum AllocType AT, uint64_t size);
void track_access_counts_alloc(void);
void track_l1_alloc(void);
void track_l2_alloc(void);
void track_l3_alloc(void);
void print_stats(size_t pr_level);
int seq_print_stats(struct seq_file *seq);
#else
static inline char * alloc_type_str(enum AllocType AT){}
static inline void track_alloc(enum AllocType AT){}
static inline void track_disabled_alloc(void){}
static inline void track_induced_alloc(void){}
static inline void track_failed_kobj_alloc(void){}
static inline void track_free(void){}
static inline void track_untracked_obj_free(void){}
static inline void track_induced_free(void){}
static inline void track_kobj_free(void){}
static inline void track_access(enum AllocType AT, uint64_t size) {}
static inline void track_induced_access(void){}
static inline void track_stack_access(void){}
static inline void track_disabled_access(void){}
static inline void track_untracked_access(enum AllocType AT, uint64_t size){}
static inline void track_access_counts_alloc(void){}
static inline void track_l1_alloc(void){}
static inline void track_l2_alloc(void){}
static inline void track_l3_alloc(void){}
static inline void print_stats(size_t pr_level){}
static inline int seq_print_stats(struct seq_file *seq){return 0;}
#endif

//TODO: Add kernel config option so can be disabled or add boot flag

#endif /* _MEMSTATS_H_ */
