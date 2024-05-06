/*===-- LICENSE -------------------------------------------------------------===
 * Developed by:
 *
 *    Research Group of Professor Vikram Adve in the Department of Computer
 *    Science The University of Illinois at Urbana-Champaign
 *    http://web.engr.illinois.edu/~vadve/Home.html
 *
 * Copyright (c) 2015, Nathan Dautenhahn
 * Copyright 2024 Board of Trustees of the University of Illinois
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
#include <linux/delay.h>

/* mask to apply to memorizer allocations TODO: verify the list of bits */
#define gfp_memorizer_mask(gfp)	((GFP_ATOMIC | __GFP_NOTRACK | __GFP_NORETRY | GFP_NOWAIT))

/**
 * pop_or_null - extract first item from a list
 * @head__: the list from which to extract
 *
 * Removes the first item from a non-empty list. Returns
 * NULL for an empty list. Caller must own any required locks.
 */
#define pop_or_null(head__) ({ \
	struct list_head *pos__ = READ_ONCE((head__)->next); \
	if(pos__ != head__) { \
		list_del_init(pos__); \
	} else { \
		pos__ = NULL; \
	} \
	pos__; \
})

/**
 * pop_or_null_mementer - extract first item from a list,
 * but only after acquiring memorizer_enter lock.
 *
 */
#define pop_or_null_mementer(head__) ({            \
	struct list_head *pos__;                   \
	int err = __memorizer_enter_wait(1);       \
	if(err) {                                  \
		pos__ = ERR_PTR(err);              \
	} else {                                   \
		pos__ = pop_or_null(head__);       \
		__memorizer_exit();                \
	}                                          \
	pos__;                                     \
})

/**
 * list_move_mementer - list_move, but protected with @inmem
 */
#define list_move_mementer(list, head)             \
	do                                         \
	{                                          \
		(void)__memorizer_enter_wait(1);   \
		list_move(list, head);             \
		__memorizer_exit();                \
	} while(0);

/* Named boolean so that memorizer_write_file_bool can print the right name */
struct bool_name {
	bool value;
	char* name;
};

/* What goes in the kmap "index" column? Time or a serial number? */
enum column_type {
	COLUMN_SERIAL,
	COLUMN_TIME,
};


/**
 * memorizer_enabled - determines whether, and how much, data is recorded.
 * Controlled by the debugfs file of the same name.
 *
 * @memorizer_enabled can take on 1 of three values:
 *
 *   0: no activity is recorded. memorizer entry points should exit
 *      as quickly as possible.
 *
 *   1: "all" activity is recorded, including activity in process-
 *      interrupt-context code.
 *
 *   2: "all" activity is recorded in non-task context, but in-task contexts
 *      are only recorded if the current process has been selected.
 *
 *   3: Only in-task activity of selected processes is recorded.
 *
 * Rougly speaking, the size of the data set, from largest to smallest, is
 * 1, 2, 3, 0.
 */
extern int memorizer_enabled;

/**
 * object_list_wq - notice when we change any kobject list.
 */
extern struct wait_queue_head object_list_wq;

/**
 * object_list_spinlock - grab this before you edit any kobject list.
 */
extern rwlock_t object_list_spinlock;

/* The object lists */
extern struct list_head memorizer_object_allocated_list;
extern struct list_head memorizer_object_freed_list;
extern struct list_head memorizer_object_reuse_list;

/* state variables edited by /sys/kernel/debug/memorizer */
extern struct bool_name track_calling_context;
extern struct bool_name print_live_obj;
extern struct bool_name verbose_warnings;

/* sets the output format - jiffies or serial? */
extern enum column_type index_column_type;

/* a graph of all caller/callee relations */
extern struct FunctionHashTable * cfgtbl;

/* flag to enforce non-reentrancy of memorizer */
DECLARE_PER_CPU(unsigned long, inmem);

/**
 * get_index - retrieve the current index value
 *
 * Returns either the current jiffies time, or a serial number
 * from a strictly-increasing series.
 */
extern unsigned long get_index(void);

/**
 * create_kobj - create the shadow object of an allocation
 * @call_site: the location of the allocator call
 * @ptr: a pointer to the newly-allocated region
 * @size: the size of the allocation
 * @AT: the name of the allocator
 */
extern struct memorizer_kobj *create_kobj(
	uintptr_t call_site,
	uintptr_t ptr,
	uint64_t size,
	enum AllocType AT);

/* For creating the debugfs files */
extern int memorizer_data_late_init(struct dentry *dentryMemDir);
extern int memorizer_control_late_init(struct dentry *dentryMemDir);
extern int memorizer_stats_late_init(struct dentry *dentryMemDir);

/**
 * memorizer_discard_kobj - free the memory previously used by a kernel object
 *
 * @kobj: - no-longer-used description of a kernel allocation.
 *
 * Must be called from process context, @inmem must not be acquired.
 */
void memorizer_discard_kobj(struct memorizer_kobj * kobj);
/**
 * __memorizer_discard_obj - free the memory previously used by a kernel object
 *
 * Must be called with @inmem acquired.
 */
void __memorizer_discard_kobj(struct memorizer_kobj * kobj);

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
static inline int __memorizer_enter(void)
{
    return this_cpu_cmpxchg(inmem, 0, 1);
}

/**
 * __memorizer_enter_wait() - set recursion flag for entyr into memorizer
 *
 * Keep trying to set the recursion flag, sleep @msecs each time.
 * This implements a lock based on the @inmem flag. This feels like
 * an obscene hack that needs to be reconsidered, rewritten, or more
 * fully justified. TODO robadams@illinois.edu
 */
static inline int __memorizer_enter_wait(unsigned int msecs)
{
	while(__memorizer_enter() != 0) {
		msleep(msecs);
		if(signal_pending(current)) {
			return -EINTR;
		}
	}
	return 0;
}

/**
 * __memorizer_exit - clear recursion flag 
 *
 * See __memorizer_enter()
 */
static __always_inline void __memorizer_exit(void)
{
    this_cpu_write(inmem, 0);
}

#endif /* __MEMORIZER_H_ */
