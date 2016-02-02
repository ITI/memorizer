/*===-- LICENSE ------------------------------------------------------------===
 * 
 * University of Illinois/NCSA Open Source License 
 *
 * Copyright (C) 2016, The Board of Trustees of the University of Illinois.
 * All rights reserved. 
 *
 * Developed by: 
 *
 *    Research Group of Professor Vikram Adve in the Department of Computer
 *    Science The University of Illinois at Urbana-Champaign
 *    http://web.engr.illinois.edu/~vadve/Home.html
 *
 * Copyright (c) 2016, Nathan Dautenhahn
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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH
 * THE SOFTWARE. 
 *
 *===-----------------------------------------------------------------------===
 *
 *       Filename:  kobj_metadata.h
 *
 *    Description:  Header file for metadata tracking functionality.
 *
 *===-----------------------------------------------------------------------===
 */

#ifndef __KOBJ_METADATA_H_
#define __KOBJ_METADATA_H_

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
 *
 * This data structure captures the details of allocated objects
 */
struct memorizer_kobj {
	struct rb_node	rb_node;
	rwlock_t	rwlock;
	long		obj_id;
	uintptr_t	alloc_ip;
	uintptr_t	free_ip;
	uintptr_t	va_ptr;
	uintptr_t	pa_ptr;
	size_t		size;
	unsigned long	alloc_jiffies;
	unsigned long	free_jiffies;
	pid_t		pid;
	char		comm[TASK_COMM_LEN];
	char		funcstr[KSYM_NAME_LEN];
	char		*modsymb[KSYM_NAME_LEN];
	struct list_head	freed_kobjs;
	struct list_head	access_counts;
};

/*
 * Kernel virtual addresses start at ffff880000000000 - ffffc7ffffffffff (=64
 * TB) direct mapping of all phys. memory --- see
 * Documentation/x86/x86_64/mm.txt. This means bit 43 is always set, which means
 * we can remove all bytes where it is unset: TODO Optimization.
 *
 * This value is analogous to PAGE_OFFSET
 *
 *  63             47 46                      24                      0
 * +-----------------+---*-------------------+------------------------+
 * |      ---        |       Directory       |         Table          |
 * +-----------------+-----------------------+------------------------+
 *
 * Right now I assume that all allocation are serviced from the direct mapped
 * region. This may not be the case as I'm not sure where module allocations
 * come from.
 *
 * So the table effectively maps each byte of allocatable virtual address space
 * to a pointer to kernel object metadata--> 8 byte pointer.
 *
 */

/* 
 * 2**23 entries * 8 Bytes per  =  67 MB directory table table
 * 2**24 tables * 8 bytes	= 134 MB Table Size to track 16 MB of VA space
 */
#define LT_TBL_MASK_BITS	24
#define LT_DIR_MASK_BITS	(47 - LT_TBL_MASK_BITS)

#define LT_KADDR_MASK \
	(~((1UL << (LT_TBL_MASK_BITS + LT_DIR_MASK_BITS)) - 1))

#define LT_TBL_ENTRIES	(_AC(1,UL) << LT_TBL_MASK_BITS)
#define LT_DIR_ENTRIES	(_AC(1,UL) << LT_DIR_MASK_BITS)

#define LT_TBL_ENTRY_SIZE	(sizeof(void *))
#define LT_DIR_ENTRY_SIZE	(sizeof(void *))

#define LT_TBL_SIZE	(LT_TBL_ENTRIES * LT_TBL_ENTRY_SIZE)
#define LT_DIR_SIZE	(LT_DIR_ENTRIES * LT_DIR_ENTRY_SIZE)
#define LT_PTR_SIZE	sizeof(void *)

struct lt_tbl {
	struct memorizer_kobj *kobj_ptrs[LT_TBL_SIZE];
};

struct lt_dir {
	struct lt_tbl *tbl_ptrs[LT_DIR_ENTRIES];
};

#define lt_dir_index(va) \
	(va >> LT_TBL_MASK_BITS) & (LT_DIR_ENTRIES - 1)

inline struct lt_tbl **lt_dir_entry(struct lt_dir *dir, uintptr_t va)
{
	return &dir->tbl_ptrs[lt_dir_index(va)];
}

//inline struct lt_tbl *lt_dir_set(struct lt_dir *dir, uintptr_t va)
//{
	//return &(*dir[lt_dir_index(va)]);
//}

#define lt_tbl_index(va)		va & (LT_TBL_ENTRIES - 1)
#define lt_tbl_entry_get(tbl,index)	&(tbl->kobj_ptrs[index]);

void lt_init(void);
int lt_insert_kobj(struct memorizer_kobj *kobj);
void lt_remove_kobj(struct memorizer_kobj *kobj);
struct memorizer_kobj * lt_get_kobj(uintptr_t va);

#endif /* __KOBJ_METADATA_H_ */

