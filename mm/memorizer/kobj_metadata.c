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

struct lt_dir kobj_dir;

int lt_insert_kobj(struct memorizer_kobj *kobj)
{
	struct lt_tbl *tbl;
	uint64_t dir_i;
	uint64_t tbl_i;
	uintptr_t va = kobj->va_ptr;
	uintptr_t kobjend = kobj->va_ptr + kobj->size;

	while(va < kobjend)
	{
		/* find the table from the directory and alloc if needed */
		dir_i = lt_dir_index(va);

		if (dir_i >= LT_DIR_ENTRIES)
		{
			pr_info("Dir index out of bounds\n");
		}

		tbl = kobj_dir.tbl_ptrs[dir_i];

		if(!tbl){
			/* allocate table and add to the dir */
			//tbl = alloc_pages(sizeof(struct lt_tbl), GFP_ATOMIC);
			extern unsigned long __get_free_pages(gfp_t gfp_mask,
							      unsigned int
							      order);

			extern void *alloc_pages_exact(size_t size, gfp_t
						       gfp_mask);
			//tbl = (struct lt_tbl *) __get_free_pages(GFP_ATOMIC,
							 //LT_TBL_SIZE/PAGE_SIZE);
			tbl = alloc_pages_exact(sizeof(struct lt_tbl)/PAGE_SIZE,
						GFP_ATOMIC);
			if(!tbl)
			{
				pr_err("failed to allocate table");
				panic("help");
				return -1;
			}
			memset(tbl,0,sizeof(struct lt_tbl));
			kobj_dir.tbl_ptrs[dir_i] = tbl;
		}

		tbl_i = lt_tbl_index(va);

		while(tbl_i < LT_TBL_ENTRIES && va < kobjend)
		{
			/* get the pointer to the tbl_entry for this va byte */
			struct memorizer_kobj **tbl_entry =
				lt_tbl_entry_get(tbl,tbl_i);

			/* If it is not null then we are double allocating */
			if(*tbl_entry){
				pr_err("Cannot insert 0x%lx into lookup table"
				       " (overlaps existing)\n", kobj->va_ptr);
				return -1;
			}

			/* insert the object pointer in the table for byte va */
			*tbl_entry = kobj;

			/* Track the end of the table and the object tracking */
			va += 1;
			++tbl_i;
		}
	}
	return 0;
}

void lt_remove_kobj(struct memorizer_kobj *kobj)
{
	uintptr_t va = kobj->va_ptr;
	uintptr_t kobjend = kobj->va_ptr + kobj->size;
	while(va<kobjend)
	{
		struct lt_tbl ** dir_entry = lt_dir_entry(&kobj_dir, va);
		if(!*dir_entry)
		{
			pr_info("<free> No table entry");
			return;
		}
		(*dir_entry)->kobj_ptrs[lt_tbl_index(va)] = NULL;
		va += 1;
	}
}

struct memorizer_kobj * lt_get_kobj(uintptr_t va)
{
	struct memorizer_kobj *kobj = NULL;
	struct lt_tbl ** dir_entry = lt_dir_entry(&kobj_dir, va);
	if(!*dir_entry)
		return NULL;

	kobj = (*dir_entry)->kobj_ptrs[lt_tbl_index(va)];

	return kobj;
}

void __init lt_init(void)
{
	/* Zero the page dir contents */
	memset(&kobj_dir, 0, sizeof(kobj_dir));
}
