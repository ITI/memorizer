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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/seq_file.h>

#include "kobj_metadata.h"
#include "memorizer.h"
#include "stats.h"

/* Caches for lookup tables */
static struct kmem_cache *lt_l1_tbl_cache;
static struct kmem_cache *lt_l2_tbl_cache;

/* RW Spinlock for access to table */
DEFINE_RWLOCK(lookup_tbl_rw_lock);

static struct lt_l3_tbl kobj_l3_tbl;
static struct lt_pid_tbl pid_tbl; 

/* Emergency Pools for l1 + l2 pages */
#define NUM_EMERGENCY_PAGES 200
struct pages_pool {
    uintptr_t base;  /* pointer to array of l1/l2 pages */
    size_t next;        /* index of next available */
    size_t entries;     /* number of entries to last page */
    size_t pg_size;     /* size of object for indexing */
};

/**
 * get_pg_from_pool() --- get the next page from the pool
 *
 * @pool: the pool to get the next value
 *
 * desc: this should not care about the type, so the type info is put into the
 * pages_pool struct so that we can do pointer arithmetic to find the next
 * available entry. The pointer is going to be the next index * the size of the
 * object, which is set on initializing the pool.
 *
 */
uintptr_t get_pg_from_pool(struct pages_pool *pool)
{
    pr_info("Getting page from pool (%p). i=%d e=%d\n",
            pool->base, pool->next, pool->entries);
    if(pool->entries == pool->next)
        return 0;
    /* next * pg_size is the offset in bytes from the base of the pool */
    return (uintptr_t) (pool->base + (pool->next++ * pool->pg_size));
}

struct lt_l1_tbl l1_tbl_pool[NUM_EMERGENCY_PAGES];
struct pages_pool l1_tbl_reserve =
{
    .base = (uintptr_t) &l1_tbl_pool,
    .next = 0,
    .entries = NUM_EMERGENCY_PAGES,
    .pg_size = sizeof(struct lt_l1_tbl)
};

struct lt_l2_tbl l2_tbl_pool[NUM_EMERGENCY_PAGES];
struct pages_pool l2_tbl_reserve =
{
    .base = (uintptr_t) &l2_tbl_pool,
    .next = 0,
    .entries = NUM_EMERGENCY_PAGES,
    .pg_size = sizeof(struct lt_l2_tbl)
};

/**
 * tbl_get_l1_entry() --- get the l1 entry
 * @va:	The virtual address to lookup
 *
 * Typical table walk starting from top to bottom. 
 *
 * Return: the return value is a pointer to the entry in the table, which means
 * it is a double pointer to the object pointed to by the region. To simplify
 * lookup and setting this returns a double pointer so access to both the entry
 * and the object in the entry can easily be obtained.
 */
static struct memorizer_kobj **tbl_get_l1_entry(uint64_t va)
{
	struct memorizer_kobj **l1e;
	struct lt_l1_tbl **l2e;
	struct lt_l2_tbl **l3e;

	/* Do the lookup starting from the top */
	l3e = lt_l3_entry(&kobj_l3_tbl, va);
	if(!*l3e)
		return NULL;
	l2e = lt_l2_entry(*l3e, va);
	if(!*l2e)
		return NULL;
	l1e = lt_l1_entry(*l2e, va);
	if(!*l1e)
		return NULL;
	return l1e;
}

/**
 * l1_alloc() --- allocate an l1 table
 */
static struct lt_l1_tbl * l1_alloc(void)
{
	struct lt_l1_tbl *l1_tbl;
	int i = 0;

	l1_tbl = kmem_cache_alloc(lt_l1_tbl_cache, GFP_ATOMIC);
	if(!l1_tbl)
    {
        l1_tbl = (struct lt_l1_tbl *) get_pg_from_pool(&l1_tbl_reserve);
        if(!l1_tbl)
        {
            /* while in dev we want to print error and panic */
            print_stats(KERN_CRIT);
            panic("Failed to allocate L1 table for memorizer kobj\n");
        }
    }

	/* Zero out the memory */
	for(i = 0; i < LT_L1_ENTRIES; ++i)
		l1_tbl->kobj_ptrs[i] = 0;

    /* increment stats counter */
    track_l1_alloc();

	return l1_tbl;
}

/** 
 * l2_alloc() - alloc level 2 table
 */
static struct lt_l2_tbl * l2_alloc(void)
{
	struct lt_l2_tbl *l2_tbl;
	int i = 0;

	l2_tbl = kmem_cache_alloc(lt_l2_tbl_cache, GFP_ATOMIC);
	if(!l2_tbl)
    {
        l2_tbl = (struct lt_l2_tbl *) get_pg_from_pool(&l2_tbl_reserve);
        if(!l2_tbl)
            print_stats(KERN_CRIT);
            panic("Failed to allocate L2 table for memorizer kobj\n");
    }

	/* Zero out the memory */
	for(i = 0; i < LT_L2_ENTRIES; ++i)
		l2_tbl->l1_tbls[i] = 0;

    /* increment stats counter */
    track_l2_alloc();

	return l2_tbl;
}

/**
 * l2_entry_may_alloc() - get the l2 entry and alloc if needed
 * @l2_tbl:	pointer to the l2 table to look into
 * @va:		Pointer of the va to index into the table
 *
 * Check if the l1 table exists, if not allocate. Lock this update so that we
 * don't get double allocations for the entry.
 */
static struct lt_l1_tbl **l2_entry_may_alloc(struct lt_l2_tbl *l2_tbl, uintptr_t
					     va)
{
	unsigned long flags;
	struct lt_l1_tbl **l2e;
	write_lock_irqsave(&lookup_tbl_rw_lock, flags);
	l2e = lt_l2_entry(l2_tbl, va);
	if(unlikely(!*l2e))
		*l2e = l1_alloc();
	write_unlock_irqrestore(&lookup_tbl_rw_lock, flags);
	return l2e;
}

/**
 * l3_entry_may_alloc() - get the l3 entry and alloc if needed
 * @va:		Pointer of the va to index into the table
 *
 * Check if the l2 table exists, if not allocate. Lock this update so that we
 * don't get double allocations for the entry.
 */
static struct lt_l2_tbl **l3_entry_may_alloc(uintptr_t va)
{
	unsigned long flags;
	struct lt_l2_tbl **l3e;
	write_lock_irqsave(&lookup_tbl_rw_lock, flags);
	l3e = lt_l3_entry(&kobj_l3_tbl, va);
	if(unlikely(!*l3e))
		*l3e = l2_alloc();
	write_unlock_irqrestore(&lookup_tbl_rw_lock, flags);
	return l3e;
}

/**
 * lt_remove_kobj() --- remove object from the table
 * @va: pointer to the beginning of the object
 *
 * This code assumes that it will only ever get a remove from the beginning of
 * the kobj. TODO: check the beginning of the kobj to make sure.
 *
 * Return: the object at the location that was removed. 
 */
struct memorizer_kobj * lt_remove_kobj(uintptr_t va)
{
	struct memorizer_kobj **l1e, *kobj;
	uintptr_t kobjend;

	/* 
	 * Get the l1 entry for the va, if there is not entry then we not only
	 * haven't tracked the object, but we also haven't allocated a l1 page
	 * for the particular address
	 */
	l1e = tbl_get_l1_entry(va);
	if(!l1e)
		return NULL;

	kobj = *l1e;

	/* 
	 * get the beginning VA entry for this object in case we called free
	 * from within the object at some offset 
	 */
	//kobj = tbl_get_l1_entry(va);

	if(kobj){
		/* For each byte in the object set the l1 entry to NULL */
		kobjend = kobj->va_ptr + kobj->size;
		while(va<kobjend){
			/* TODO Optimize this: can just use the indices on the l1
			 * tbl instead of getting the entry from the top each
			 * time.
			 */
			l1e = tbl_get_l1_entry(va);
			if(l1e)
				*l1e = NULL;
			va += 1;
		}
	}
	return kobj;
}

inline struct memorizer_kobj * lt_get_kobj(uintptr_t va)
{
	struct memorizer_kobj **l1e = tbl_get_l1_entry(va);
	if(l1e)
		return *l1e;
	else
		return NULL;
}

/* 
 * handle_overalpping_insert() -- hanlde the overlapping insert case
 * @va:		the virtual address that is currently not vacant
 * @l1e:	the l1 entry pointer for the va
 *
 * There is some missing free's currently, it isn't clear what is causing them;
 * however, if we assume objects are allocated before use then the most recent
 * allocation will be viable for any writes to these regions so we remove the
 * previous entry and set up its free times with a special code denoting it was
 * evicted from the table in an erroneous fasion.
 */
static void handle_overlapping_insert(uintptr_t va, struct memorizer_kobj **l1e)
{
	unsigned long flags;
	struct memorizer_kobj *obj = lt_remove_kobj(va);
	//pr_err("Inserting 0x%lx into lookup table"
	//       " (overlaps existing) removing\n", va);
	/* 
	 * Note we don't need to free because the object
	 * is in the free list and will get expunged
	 * later.
	 */
	write_lock_irqsave(&obj->rwlock, flags);
	obj->free_jiffies = jiffies;
	obj->free_ip = 0xDEADBEEF;
	write_unlock_irqrestore(&obj->rwlock, flags);
#if 0 // Debug code
	__print_memorizer_kobj(*l1e, "Orig Kobj:");
	__print_memorizer_kobj(kobj, "New Kobj:");
	pr_info("L3 Entry Index: %p\n",
		lt_l3_tbl_index(va));
	pr_info("L2 Entry Index: %p\n",
		lt_l2_tbl_index(va));
	pr_info("L1 Entry Index: %p\n",
		lt_l1_tbl_index(va));
#endif
}

/**
 * lt_insert_kobj() - insert kobject into the lookup table
 * @kobj:	pointer to the kobj to insert
 *
 * For each virtual address in the range of the kobj allocation set the l1 table
 * entry mapping for the virtual address to the kobj pointer. The function
 * starts by getting the l2 table from the global l3 table. If it doesn't exist
 * then allocates the table. The same goes for looking up the l1 table for the
 * given va. Once the particular l1 table is obtained for the start va of the
 * object, iterate through the table setting each entry of the object to the
 * given kobj pointer. 
 */
int lt_insert_kobj(struct memorizer_kobj *kobj)
{
	struct lt_l1_tbl **l2e;
	struct lt_l2_tbl **l3e;
	uint64_t l1_i = 0;
	uintptr_t va = kobj->va_ptr;
	uintptr_t kobjend = kobj->va_ptr + kobj->size;

	while(va < kobjend)
	{
		/* Pointer to the l3 entry for va and alloc if needed */
		l3e = l3_entry_may_alloc(va);

		/* Pointer to the l2 entry for va and alloc if needed */
		l2e = l2_entry_may_alloc(*l3e, va);

		/* 
		 * Get the index for this va for boundary on this l1 table;
		 * however, TODO, this might not be needed as our table indices
		 * are page aligned and it might be unlikely allocations are
		 * page aligned and will not traverse the boundary of an l1
		 * table. Note that I have not tested this condition yet.
		 */
		l1_i = lt_l1_tbl_index(va);

		while(l1_i < LT_L1_ENTRIES && va < kobjend)
		{
			/* get the pointer to the l1_entry for this va byte */
			struct memorizer_kobj **l1e = lt_l1_entry(*l2e,va);

			/* If it is not null then we are double allocating */
			if(*l1e)
				handle_overlapping_insert(va, l1e);

			/* insert the object pointer in the table for byte va */
			*l1e = kobj;

			/* Track the end of the table and the object tracking */
			va += 1;
			++l1_i;
		}
	}
	return 0;
}

void plt_insert(struct pid_obj pobj)
{
	// Insert into the PID Table based on the Key of the Object
	pid_tbl.pid_obj_list[pobj.key] = pobj;
}


void __init lt_init(void)
{
	/* Zero the page dir contents */
	memset(&kobj_l3_tbl, 0, sizeof(kobj_l3_tbl));
	// Zero Out the Contents of the PID Table
	memset(&pid_tbl, 0, sizeof(pid_tbl));
    /* Init the kmem table caches */
	lt_l1_tbl_cache = KMEM_CACHE(lt_l1_tbl, SLAB_PANIC);
	lt_l2_tbl_cache = KMEM_CACHE(lt_l2_tbl, SLAB_PANIC);
    /* track that we statically allocated an l3 */
    track_l3_alloc();
}
