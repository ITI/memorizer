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
 *       Filename:  memorizer.h
 *
 *    Description:  General inclues and utilities for memorizer tracing
 *                  framework.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef __MEMORIZER_H_
#define __MEMORIZER_H_

#include <linux/gfp.h>

/* mask to apply to memorizer allocations TODO: verify the list */
#define gfp_memorizer_mask(gfp)	((GFP_ATOMIC | __GFP_NOTRACK | __GFP_NORETRY | GFP_NOWAIT))

unsigned long get_index(void);
struct memorizer_kobj *create_kobj(uintptr_t call_site, uintptr_t ptr, uint64_t size, enum AllocType AT);

extern int memorizer_data_late_init(struct dentry *dentryMemDir);
extern struct wait_queue_head object_list_wq;

extern struct list_head memorizer_object_allocated_list;
extern struct list_head memorizer_object_freed_list;
extern struct list_head memorizer_object_reuse_list;

struct bool_name {
	bool value;
	char* name;
};
extern struct bool_name track_calling_context;
extern struct bool_name print_live_obj;

enum column_type {
	COLUMN_SERIAL,
	COLUMN_TIME,
};

/* RW Spinlock for access to any kobject list */
extern rwlock_t object_list_spinlock;

extern enum column_type index_column_type;
/**
 * __memorizer_enter() - set recursion flag for entry into memorizer
 *
 * Return value: 0 for success. Any other value for failure.
 *
 * The primary goal of this is to stop recursive handling of events. Memorizer
 * by design tracks two types of events: allocations and accesses. Effectively,
 * while tracking either type we do not want to re-enter and track memorizer
 * events that are sources from within memorizer. Yes this means we may not
 * track legitimate access of some types, but these are caused by memorizer and
 * we want to ignore them.
 *
 * N.b. There is no way yet to wait for memorizer to be available. Before
 * you try `while(__memorizer_enter()) yield();`, look at the comment
 * for `yield()` in kernel/sched/core.c
 */
DECLARE_PER_CPU(unsigned long, inmem);
static inline int __memorizer_enter(void)
{
    return this_cpu_cmpxchg(inmem, 0, 1);
}

static __always_inline void __memorizer_exit(void)
{
    this_cpu_write(inmem, 0);
}
extern struct FunctionHashTable * cfgtbl;
void memorizer_discard_kobj(struct memorizer_kobj * kobj);
#endif /* __MEMORIZER_H_ */
