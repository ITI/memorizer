/*===-- LICENSE ------------------------------------------------------------===
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
 *===-----------------------------------------------------------------------===
 *
 *       Filename:  kobj_metadata.h
 *
 *    Description:  Header file for metadata tracking functionality.
 *
 *===-----------------------------------------------------------------------===
 */

#ifndef _KOBJ_METADATA_H_
#define _KOBJ_METADATA_H_

#include <linux/kallsyms.h>
#include <linux/rbtree.h>
#include <linux/rwlock.h>
#include <linux/sched.h>

/**
 * struct memorizer_kobj - metadata for kernel objects
 * @rb_node:		the red-black tree relations
 * @alloc_ip:		instruction that allocated the object
 * @va_ptr:		Virtual address of the beginning of the object
 * @pa_ptr:		Physical address of the beginning of object
 * @size:		Size of the object
 * @jiffies:		Time stamp of creation
 * @pid:		PID of the current task
 * @comm:		Executable name
 * @kobj_list:		List of all objects allocated
 * @access_counts:	List of memory access count structures
 * @arg_kobj:   Pointer points to a function argument kobj.
 *
 * This data structure captures the details of allocated objects
 */
struct memorizer_kobj {
	struct rb_node	    rb_node;
	enum AllocType      alloc_type;
	rwlock_t	    rwlock;
	long		    obj_id;
	uintptr_t	    alloc_ip;
	uintptr_t	    free_ip;
	uintptr_t	    va_ptr;
	uintptr_t	    pa_ptr;
	size_t		    size;
	unsigned long	    alloc_jiffies;
	unsigned long	    free_jiffies;
	pid_t		    pid;
	char		    comm[TASK_COMM_LEN];
	char		    funcstr[KSYM_NAME_LEN];
	bool		    printed;
	//char		    *modsymb[KSYM_NAME_LEN];
	char		    *slabname;
	struct list_head    object_list;
	struct list_head    access_counts;
	struct memorizer_kobj *args_kobj;
};

/**
 * access_counts - track reads/writes from single source IP
 */
struct access_from_counts {
	struct list_head list;
	uintptr_t ip;
	uintptr_t caller;
	uint64_t pid;
	uint64_t writes;
	uint64_t reads;
};


struct pid_obj {
	uint32_t key;
	pid_t pid;
	char comm[TASK_COMM_LEN];
};

/*
 * Kernel virtual addresses start at ffff880000000000 - ffffc7ffffffffff (=64
 * TB) direct mapping of all phys. memory --- see
 * Documentation/x86/x86_64/mm.txt. This means bit 43 is always set, which means
 * we can remove all bytes where it is unset: TODO Optimization.
 *
 *  63             47 46                   24 23        12 11         0
 * +-----------------+--*--------------------+------------+------------+
 * |      ---        |          L3           |     L2     |     L1     |
 * +-----------------+-----------------------+------------+------------+
 *
 * The lookup table maps each byte of allocatable virtual address space to a
 * pointer to kernel object metadata--> 8 byte pointer.
 *
 */
#define LT_L1_SHIFT		    12
#define LT_L1_ENTRIES		(_AC(1,UL) << LT_L1_SHIFT)
#define LT_L1_ENTRY_SIZE	(sizeof(void *))
#define LT_L1_SIZE		    (LT_L1_ENTRIES * LT_L1_ENTRY_SIZE)

#define LT_L2_SHIFT		    27
#define LT_L2_ENTRIES		(_AC(1,UL) << (LT_L2_SHIFT - LT_L1_SHIFT))
#define LT_L2_ENTRY_SIZE	(sizeof(void *))
#define LT_L2_SIZE		    (LT_L2_ENTRIES * LT_L2_ENTRY_SIZE)

#define LT_L3_SHIFT		    47
#define LT_L3_ENTRIES		(_AC(1,UL) << (LT_L3_SHIFT - LT_L2_SHIFT))
#define LT_L3_ENTRY_SIZE	(sizeof(void *))
#define LT_L3_SIZE		    (LT_L3_ENTRIES * LT_L3_ENTRY_SIZE)


#define PID_ENTRIES		    (_AC(1,UL) << 5)
//PLACEHOLDER VALUE
//==-- Table data structures -----------------------------------------------==//

/*
 * Each structure contains an array of pointers to the next level of the lookup.
 * So the lowest level L1 has an array of pointers to the kobjects, L2 has an
 * array of pointers to structs of type l2_tbl.
 */
struct lt_l1_tbl {
	struct memorizer_kobj *kobj_ptrs[LT_L1_ENTRIES];
};

struct lt_l2_tbl {
	struct lt_l1_tbl *l1_tbls[LT_L2_ENTRIES];
};

struct lt_l3_tbl {
	struct lt_l2_tbl *l2_tbls[LT_L3_ENTRIES];
};

struct lt_pid_tbl {
	struct pid_obj pid_obj_list[PID_ENTRIES];
};

#define lt_l1_tbl_index(va)	(va & (LT_L1_ENTRIES - 1))
#define lt_l2_tbl_index(va)	((va >> LT_L1_SHIFT) & (LT_L2_ENTRIES - 1))
#define lt_l3_tbl_index(va)	((va >> LT_L2_SHIFT) & (LT_L3_ENTRIES - 1))

/*
 * lt_l*_entry() --- get the table entry associated with the virtual address
 *
 * This uses ** because the value returned is a pointer to the table entry, but
 * also can be dereferenced to point to the next level down.
 */
static inline struct memorizer_kobj **lt_l1_entry(struct lt_l1_tbl *l1_tbl,
		uintptr_t va)
{
	return &(l1_tbl->kobj_ptrs[lt_l1_tbl_index(va)]);
}

static inline struct lt_l1_tbl **lt_l2_entry(struct lt_l2_tbl *l2_tbl, uintptr_t
		va)
{
	return &l2_tbl->l1_tbls[lt_l2_tbl_index(va)];
}

static inline struct lt_l2_tbl **lt_l3_entry(struct lt_l3_tbl *l3_tbl, uintptr_t
		va)
{
	return &l3_tbl->l2_tbls[lt_l3_tbl_index(va)];
}

static inline struct pid_obj * lt_pid(struct lt_pid_tbl *pid_tbl,  uint32_t key)
{
	return &(pid_tbl->pid_obj_list[key]);
}

//==-- External Interface -------------------------------------------------==//
void lt_init(void);
int lt_insert_kobj(struct memorizer_kobj *kobj);
struct memorizer_kobj * lt_remove_kobj(uintptr_t va);
struct memorizer_kobj * lt_get_kobj(uintptr_t va);
int lt_insert_induced(void * vaddr, size_t size);
bool is_induced_obj(uintptr_t va);

#endif /* __KOBJ_METADATA_H_ */
