/*===-- LICENSE ------------------------------------------------------------===
 * 
 * University of Illinois/NCSA Open Source License 
 *
 * Copyright (C) 2015, The Board of Trustees of the University of Illinois.
 * All rights reserved. 
 *
 * Developed by: 
 *
 *    Research Group of Professor Vikram Adve in the Department of Computer
 *    Science The University of Illinois at Urbana-Champaign
 *    http://web.engr.illinois.edu/~vadve/Home.html
 *
 * Copyright (c) 2015, Nathan Dautenhahn
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
 * Sam King or the University of Illinois, nor the names of its contributors
 * may be used to endorse or promote products derived from this Software
 * without specific prior written permission. 
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * WITH THE SOFTWARE. 
 *
 *===-----------------------------------------------------------------------===
 *
 *       Filename:  memorizer.c
 *
 *    Description:  Memorizer is a memory tracing tool. It hooks into KASAN
 *                  events to record object allocation/frees and all
 *                  loads/stores. 
 *
 *===-----------------------------------------------------------------------===
 */

#include <linux/bug.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kmemleak.h>
#include <linux/memorizer.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/smp.h>

#include <asm/atomic.h>

//==-- Data types and structs for building maps ---------------------------==//
enum AllocType {KALLAC};
enum EventType {READ,WRITE,ALLOC,FREE};

/* flag to keep track of whether or not to track writes */
bool memorizer_enabled = false;

/**
 * struct memorizer_event - structure to capture all memory related events
 * @alloc_type:	 if allocation then set the type of alloca
 * @event_type:	 type of event
 * @obj_id:	 for allocations track object identifier
 * @src_ip:	 virtual address of the invoking instruction
 * @access_addr: starting address of the operation
 * @access_size: size of the access: for wr/rd size, allocation length
 * @jiffies:	 timestamp
 * @pid:	 PID of invoking task
 * @comm:	 String of executable
 */
struct memorizer_event {
	enum AllocType alloc_type;
	enum EventType event_type;
	uint64_t obj_id;
	uintptr_t src_ip;
	uintptr_t access_addr;		/* The location being accessed */
	uint64_t access_size;		/* events can be allocs or memcpy */
	unsigned long jiffies;		/* creation timestamp */
	pid_t pid;			/* pid of the current task */
	char comm[TASK_COMM_LEN];	/* executable name */
};

/** 
 * struct memorizer_kobj - metadata for kernel objects 
 * @rb_node:	the red-black tree relations
 * @alloc_ip:	instruction that allocated the object
 * @begin_va:	Virtual address of the beginning of the object
 * @end_va:	Last valid byte virutal address of the object
 * @size:	Size of the object
 * @begin_pa:	Physical address of the beginning of object
 * @end_pa:	Physical address of the last valid byte of object
 *
 * This data structure captures the details of allocated objects
 */
struct memorizer_kobj {
	struct rb_node	node;
	uintptr_t	alloc_ip;
	uintptr_t	va_ptr_to_obj;
	uintptr_t	pa_ptr_to_obj;
	size_t		size;
};

/**
 * struct code_region - simple struct to capture begin and end of a code region
 */
struct code_region {
	uintptr_t b;
	uintptr_t e;
};

struct code_region audit_code_region = {
	.b = 0xffffffff81158b30,
	.e = 0xffffffff8116b550
};

struct code_region crypto_code_region = {
	.b = 0xffffffff814a3520,
	.e = 0xffffffff814d61e0
};

/* TODO make this dynamically allocated based upon free memory */
struct memorizer_event mem_events[10000];
uint64_t log_index = 0;

/* object cache for memorizer kobjects */
static struct kmem_cache *kobj_cache;

/* mask to apply to memorizer allocations TODO: verify the list */
#define gfp_memorizer_mask(gfp)	(((gfp) & (		\
					 | GFP_ATOMIC		\
					 | __GFP_NOACCOUNT))	\
					 | __GFP_NORETRY	\
					 | __GFP_NOMEMALLOC	\
					 | __GFP_NOWARN		\
					 | __GFP_NOTRACK	\
				 )

//==-- Debugging and print information ------------------------------------==//

//==-- Temporary test code --==//
atomic_t memorizer_num_accesses = ATOMIC_INIT(0);
int __memorizer_get_opsx(void)
{
    return atomic_read(&memorizer_num_accesses);
}
EXPORT_SYMBOL(__memorizer_get_opsx);

atomic_t memorizer_num_untracked_allocs = ATOMIC_INIT(0);
atomic_t memorizer_num_tracked_allocs = ATOMIC_INIT(0);
int __memorizer_get_allocs(void)
{
    return atomic_read(&memorizer_num_tracked_allocs);
}
EXPORT_SYMBOL(__memorizer_get_allocs);

/**
 * __memorizer_print_events - print the last num events
 * @num_events:		The total number of events to print
 *
 * Simple print assuming an array log. Only tricky thing is to wrap around the
 * circular buffer when hitting the end or printing the last set of events if
 * some of them are at the end of the linear buffer. 
 */
void __memorizer_print_events(unsigned int num_events)
{
	int i;
	int e;

	pr_info("\n\n***Memorizer Num Accesses: %d\n",
		atomic_read(&memorizer_num_accesses));
	pr_info("\n\n***Memorizer Num Allocs Tracked: %d Untracked: %d\n",
		atomic_read(&memorizer_num_tracked_allocs),
		atomic_read(&memorizer_num_untracked_allocs));

	if((log_index - num_events) > 0)
		i = log_index - num_events;
	else
		i = ARRAY_SIZE(mem_events) - (num_events - log_index + 1);

	for(e = 0; e < num_events; e++)
	{
		char *type_str[10];
		pr_info("Memorizer: access from IP 0x%p at addr 0x%p\n",
				(void *)mem_events->src_ip, (void *)
				mem_events->access_addr);
		switch(mem_events->event_type){
		case READ:
			*type_str = "Read\0";
			break;
		case WRITE:
			*type_str = "Write\0";
			break;
		case ALLOC:
			*type_str = "Alloc\0";
			break;
		case FREE:
			*type_str = "Free\0";
			break;
		default:
			pr_info("Unmatched event type\n");
			*type_str = "Unknown\0";
		}
		pr_info("%s of size %lu by task %s/%d\n", *type_str,
			(unsigned long) mem_events->access_size,
			mem_events->comm, task_pid_nr(current));
		i++;
		if(i >= ARRAY_SIZE(mem_events))
			i = 0;
	}
}
EXPORT_SYMBOL(__memorizer_print_events);

//==-- Memorizer memory access tracking -----------------------------------==//

/**
 * log_event() - log the memory event
 * @addr:	The virtual address for the event start location
 * @size:	The number of bits associated with the event
 * @event_type:	The type of event to record
 * @ip:		IP of the invoking instruction
 *
 * This function records the memory event to the event log. Currently emulates a
 * circular buffer for logging the most recent set of events. TODO extend this
 * to be dynamically determined.
 */
void log_event(uintptr_t addr, size_t size, enum EventType event_type, 
	       uintptr_t ip)
{
	mem_events[log_index].access_addr = addr;
	mem_events[log_index].event_type = event_type;
	mem_events[log_index].access_size = size;
	mem_events[log_index].src_ip = ip;
	mem_events[log_index].jiffies = jiffies;

#if 0 /* NOT IMPLEMENTED YET--- BREAKS EARLY BOOT */
	/* task information */
	if (in_irq()) {
		mem_events[log_index].pid = 0;
		//strncpy(mem_events[log_index].comm, "hardirq",
		//	sizeof(mem_events[log_index].comm));
	} else if (in_softirq()) {
		mem_events[log_index].pid = 0;
		//strncpy(mem_events[log_index].comm, "softirq",
		//	sizeof(mem_events[log_index].comm));
	} else {
		mem_events[log_index].pid = current->pid;
		/*
		 * There is a small chance of a race with set_task_comm(),
		 * however using get_task_comm() here may cause locking
		 * dependency issues with current->alloc_lock. In the worst
		 * case, the command line is not correct.
		 */
		//strncpy(mem_events[log_index].comm, current->comm,
		//	sizeof(mem_events[log_index].comm));
	}
#endif

#if 0 // TODO: Working on creating a lookup function to determine if the given
	page is being used as a PTP. 
	if(is_pagetbl(addr))
	   pr_info("Memorizer: Write to PT from IP 0x%p",ip);
#endif

	if(log_index >= ARRAY_SIZE(mem_events))
		log_index = 0;
	else
		++log_index;
}

/**
 * memorize_mem_access() - record associated data with the load or store
 * @addr:	The virtual address being accessed
 * @size:	The number of bits for the load/store
 * @write:	True if the memory access is a write (store)
 * @ip:		IP of the invocing instruction
 *
 * This function will memorize, ie. log, the particular data access.
 */
void memorize_mem_access(uintptr_t addr, size_t size, bool write, uintptr_t ip)
{
	unsigned long flags;
	enum EventType event_type;

	atomic_inc(&memorizer_num_accesses);

#if 0 // TO_IMPLEMENT
	if(!memorizer_enabled)
		return;

	//local_irq_save(flags);
	//if(memorizer_enabled){
	//if(addr > crypto_code_region.b && addr < crypto_code_region.e)
	{
		event_type = write ? WRITE : READ;
		log_event(addr, size, event_type, ip);
	}
	//local_irq_restore(flags);
#endif
}

//==-- Memorizer kernel object tracking -----------------------------------==//

/**
 * init_kobj() - Initalize the metadata to track the recent allocation
 */
int init_kobj(struct memorizer_kobj * kobj, uintptr_t call_site, uintptr_t
	      ptr_to_kobj, size_t bytes_alloc)
{
	kobj->alloc_ip = call_site;
	kobj->va_ptr_to_obj = ptr_to_kobj;
	kobj->pa_ptr_to_obj = __pa(ptr_to_kobj);
	kobj->size = bytes_alloc;
}

/**
 * add_kobj_to_rb_tree - add the object to the tree
 * @kobj:	Pointer to the object to add to the tree
 */
int add_kobj_to_rb_tree(struct memorizer_kobj *kobj)
{
#if 0 // TODO IMPLEMENT
	unsigned long flags;
	write_lock_irqsave(&active_kobj_rbtree_spinlock, flags);
	write_unlock_irqsave(&active_kobj_rbtree_spinlock, flags);
#endif
}

/**
 * move_kobj_to_free_list - move the specified objec to free list
 * @call_site:	Call site requesting the original free
 * @ptr:	Address of the object to be freed
 *
 * Algorithm: 
 *	1) find the object in the rbtree
 *	2) add the object to the memorizer process kobj queue
 *	3) remove the object from the rbtree
 *
 * Maybe TODO: Do some processing here as opposed to later? This depends on when
 * we want to add our filtering.
 */
static void move_kobj_to_free_list(uintptr_t call_site, uintptr_t ptr_to_kobj)
{
}

/**
 * memorize_alloc() - record allocation event
 * @object:	Pointer to the beginning of hte object
 * @size:	Size of the object
 *
 * Track the allocation and add the object to the set of active object tree.
 */
void __memorize_kmalloc(unsigned long call_site, const void *ptr, size_t
			 bytes_req, size_t bytes_alloc, gfp_t gfp_flags)
{
	//unlikely(IS_ERR(ptr)))
	//if(object > crypto_code_region.b && object < crypto_code_region.e)
	if(unlikely(ptr==NULL))
		return;


	if(unlikely(!memorizer_enabled))
	{
		atomic_inc(&memorizer_num_untracked_allocs);
		return;
	}

	atomic_inc(&memorizer_num_tracked_allocs);

	pr_debug("Memorizer object from %p @ %p of size: %. GFP-Flags: 0x%llx\n",
		(void*)call_site, ptr, bytes_alloc, (unsigned long long)
		gfp_flags);

	struct memorizer_kobj * kobj = kmem_cache_alloc(kobj_cache,
							gfp_flags |
							GFP_ATOMIC);
	if(!kobj){
		pr_info("Cannot allocate a memorizer_kobj structure\n");
	}

	init_kobj(kobj, call_site, ptr, bytes_alloc);

	/* This function uses a spinlock to ensure tree insertion */
	add_kobj_to_rb_tree(kobj);
}

/*** HOOKS similar to the kmem points ***/
void memorize_kmalloc(unsigned long call_site, const void *ptr, size_t
		      bytes_req, size_t bytes_alloc, gfp_t gfp_flags)
{
	__memorize_kmalloc(call_site, ptr, bytes_req, bytes_alloc, gfp_flags);
}

void memorize_kmalloc_node(unsigned long call_site, const void *ptr, size_t
			   bytes_req, size_t bytes_alloc, gfp_t gfp_flags, int
			   node)
{
	__memorize_kmalloc(call_site, ptr, bytes_req, bytes_alloc, gfp_flags);
}

void memorize_kfree(unsigned long call_site, const void *ptr)
{
	/* 
	 * Condition for ensuring free is from online cpu: see trace point
	 * condition from include/trace/events/kmem.h for reason
	 */
	if(unlikely(!cpu_online(raw_smp_processor_id())) || !memorizer_enabled){
		return;
	}

	move_kobj_to_free_list(call_site, (void *) ptr);
}

#if 0
void memorize_kmem_cache_alloc(_RET_IP_, ret, s->object_size, s->size,
			       gfpflags);
void memorize_kmem_cache_alloc_node(_RET_IP_, ret, s->object_size, s->size,
				    gfpflags, node);
void memorize_kmem_cache_free(_RET_IP_, x);
#endif


void memorize_alloc_pages(struct page *page, unsigned int order) { }
void memorize_free_pages(struct page *page, unsigned int order) { }

//==-- Memorizer Initializtion --------------------------------------------==//

/**
 * create_obj_kmem_cache() create the kernel object kmem_cache
 */
void create_obj_kmem_cache(void)
{
	pr_info("Creating kmem_cache object\n");
	kobj_cache = KMEM_CACHE(memorizer_kobj,
				SLAB_PANIC
				//| SLAB_TRACE | SLAB_NOLEAKTRACE
			       );
	pr_info("Just created kmem_cache object\n");
}

/**
 * memorizer_init() - initialize memorizer state
 *
 * Set enable flag to true which enables tracking for memory access and object
 * allocation. Allocate the object cache as well.
 */
void __init memorizer_init(void)
{
	unsigned long flags;
	create_obj_kmem_cache();

	local_irq_save(flags);
	memorizer_enabled = true;
	local_irq_restore(flags);
}

/*
 * Late initialization function.
 */
static int __init memorizer_late_init(void)
{
	//struct dentry *dentry;

	//dentry = debugfs_create_file("memorizer", S_IRUGO, NULL, NULL,
				     //&kmemleak_fops);
	//if (!dentry)
		//pr_warning("Failed to create the debugfs kmemleak file\n");

	pr_info("Memorizer initialized\n");

	return 0;
}
late_initcall(memorizer_late_init);

/**
 * init_from_driver() - Initialize memorizer from a driver
 *
 * The primary focus of this funciton is to allow for very late enable and init
 */
int memorizer_init_from_driver(void)
{
	if(memorizer_enabled)
		return 0;

	create_obj_kmem_cache();

	memorizer_enabled = true;

	return 0;
}
EXPORT_SYMBOL(memorizer_init_from_driver);
