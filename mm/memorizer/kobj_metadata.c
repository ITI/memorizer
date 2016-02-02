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
 *       Filename:  kobj_metadata.c
 *
 *    Description:  Metadata tracking for all kobject allocations. Includes
 *		    types for metadata as well as data structure
 *		    implementations.
 *
 *===-----------------------------------------------------------------------===
 */

#include <linux/gfp.h>
#include <linux/slab.h>

#include "kobj_metadata.h"

/* allocate table and add to the dir */
extern unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order);
extern void *alloc_pages_exact(size_t size, gfp_t gfp_mask);

//struct lt_l3_tbl kobj_l3_tbl;
struct lt_l2_tbl kobj_l2_tbl;

static struct lt_l1_tbl * lt_l1_alloc(void)
{
	struct lt_l1_tbl *l1_tbl;
	int i = 0;

	//l1ptr = alloc_pages(sizeof(struct lt_l1), GFP_ATOMIC);

	l1_tbl = (struct lt_l1_tbl *)
		//__get_free_pages(GFP_ATOMIC, sizeof(struct lt_l1_tbl) /
		//		 PAGE_SIZE);
		alloc_pages_exact(sizeof(struct lt_l1_tbl), GFP_ATOMIC);

	if(!l1_tbl)
	{
		pr_err("failed to allocate table");
		panic("help");
		return 0;
	}

	/* Zero out the memory */
	for(i = 0; i < LT_L1_ENTRIES; ++i)
		l1_tbl->kobj_ptrs[i] = 0;

	return l1_tbl;
}

int lt_insert_kobj(struct memorizer_kobj *kobj)
{
	struct lt_l1_tbl **l2e;
	uint64_t l1_i = 0;
	uintptr_t va = kobj->va_ptr;
	uintptr_t kobjend = kobj->va_ptr + kobj->size;

	while(va < kobjend)
	{
		/* Pointer to the l2 entry for va */
		l2e = lt_l2_entry(&kobj_l2_tbl, va);

		/* Table is not allocated yet so do it and set the entry in l2 */
		if(!*l2e){
			*l2e = lt_l1_alloc();
		}

		//entries = set_l1_entries(va, kobj);

		l1_i = lt_l1_tbl_index(va);

		while(l1_i < LT_L1_ENTRIES && va < kobjend)
		{
			/* get the pointer to the l1_entry for this va byte */
			struct memorizer_kobj **l1e = lt_l1_entry(*l2e,va);

			/* If it is not null then we are double allocating */
			if(*l1e){
				pr_err("Cannot insert 0x%lx into lookup table"
				       " (overlaps existing)\n", kobj->va_ptr);
				return -1;
			}

			/* insert the object pointer in the table for byte va */
			*l1e = kobj;

			/* Track the end of the table and the object tracking */
			va += 1;
			++l1_i;
		}
	}
	return 0;
}

void lt_remove_kobj(struct memorizer_kobj *kobj)
{
#if 0
	uintptr_t va = kobj->va_ptr;
	uintptr_t kobjend = kobj->va_ptr + kobj->size;
	while(va<kobjend)
	{
		struct lt_l1 ** dir_entry = lt_dir_entry(&kobj_dir, va);
		if(!*dir_entry)
		{
			pr_info("<free> No table entry");
			return;
		}
		(*dir_entry)->kobj_ptrs[lt_l1_index(va)] = NULL;
		va += 1;
	}
#endif
}

struct memorizer_kobj * lt_get_kobj(uintptr_t va)
{
	struct memorizer_kobj *kobj = NULL;
#if 0
	struct lt_l1 ** dir_entry = lt_dir_entry(&kobj_dir, va);
	if(!*dir_entry)
		return NULL;

	kobj = (*dir_entry)->kobj_ptrs[lt_l1_index(va)];

#endif
	return kobj;
}

void __init lt_init(void)
{
	/* Zero the page dir contents */
	memset(&kobj_l2_tbl, 0, sizeof(kobj_l2_tbl));
}
