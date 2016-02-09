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
 *       Filename:  memorizer.c
 *
 *    Description:  Memorizer is a memory tracing tool. It hooks into KASAN
 *		    events to record object allocation/frees and all
 *		    loads/stores. 
 *
 *===-----------------------------------------------------------------------===
 *
 * Locking:  
 *
 *	Memorizer has two global and a percpu data structure:
 *	
 *		- global rbtree of active kernel objects - queue for holding
 *		  free'd objects that haven't logged - A percpu event queue to
 *		  track memory access events
 *		    
 *     Therefore, we have the following locks:
 *
 *		- active_kobj_rbtree_spinlock: 
 *		
 *			The insert routine is generic to any kobj_rbtree and
 *			therefore is only provided in an unlocked variant
 *			currently. The code must take this lock prior to
 *			inserting into the rbtree.  
 * 
 *		- freed_kobjs_spinlock: 
 *			
 *			Lock for the list of all objects. This list is added to
 *			on each kobj free. On log this queue should collect any
 *			queued writes in the local PerCPU access queues and then
 *			remove it from the list.
 *
 *		- memorizer_kobj.rwlock: 
 *
 *			RW spinlock for access to object internals. 
 * 
 * Re-Entrance:
 *
 *	This system hooks all memory reads/writes and object allocation,
 *	therefore any external function called will re-enter via ld/st
 *	instrumentation as well as from allocations. So to avoid this we must be
 *	very careful about any external functions called to ensure correct
 *	behavior. This is particulary critical of the memorize access function.
 *	The others can call external, but note that the memory ld/st as a
 *	response to that call will be recorded. 
 *
 *===-----------------------------------------------------------------------===
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/bug.h>
#include <linux/cpumask.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/memorizer.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/rbtree.h>
#include <linux/rwlock.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/smp.h>

#include <asm/atomic.h>
#include <asm/percpu.h>

#include "kobj_metadata.h"

//==-- Debugging and print information ------------------------------------==//
#define MEMORIZER_DEBUG		1
#define FIXME			0

#define MEMORIZER_STATS		1

//==-- Prototype Declarations ---------------------------------------------==//
static struct memorizer_kobj * unlocked_lookup_kobj_rbtree(uintptr_t kobj_ptr,
							   struct rb_root *
							   kobj_rbtree_root);
//==-- Data types and structs for building maps ---------------------------==//

/* Size of the memory access recording worklist arrays */
#define MEM_ACC_L_SIZE 1

/* Types for events */
enum AccessType {Memorizer_READ=0,Memorizer_WRITE};

/**
 * struct memorizer_mem_access - structure to capture all memory related events
 * @access_type: type of event
 * @src_ip:	 virtual address of the invoking instruction
 * @access_addr: starting address of the operation
 * @access_size: size of the access: for wr/rd size, allocation length
 * @jiffies:	 timestamp
 * @pid:	 PID of invoking task
 * @comm:	 String of executable
 */
struct memorizer_mem_access {
	enum AccessType access_type;
	uintptr_t src_ip;
	uintptr_t access_addr;		/* The location being accessed */
	uint64_t access_size;		/* events can be allocs or memcpy */
	unsigned long jiffies;		/* creation timestamp */
	pid_t pid;			/* pid of the current task */
	char comm[TASK_COMM_LEN];	/* executable name */
};

/**
 * mem_access_wlists - This struct contains work queues holding accesses
 *
 * Size Calculation for memorizer_mem_access:
 *	(1+64+64+64+64+32+256)*100000 = 54.5Mb
 */
struct mem_access_worklists {
	struct memorizer_mem_access wls[2][MEM_ACC_L_SIZE];
	size_t selector;
	long head;
	long tail;
};

/**
 * access_counts - track reads/writes from single source IP
 */
 struct access_from_counts {
	 struct list_head list;
	 uintptr_t ip;
	 pid_t pid;
	 uint64_t writes;
	 uint64_t reads;
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

struct code_region selinux = {
	.b = 0xffffffff81475450,
	.e = 0xffffffff814a3000
};


struct code_region crypto_code_region = {
	.b = 0xffffffff814a3000,
	.e = 0xffffffff814cee00
};

/* TODO make this dynamically allocated based upon free memory */
//DEFINE_PER_CPU(struct mem_access_worklists, mem_access_wls = {.selector = 0, .head = 0, .tail = 0 });
DEFINE_PER_CPU(struct mem_access_worklists, mem_access_wls);

/* flag to keep track of whether or not to track writes */
static bool memorizer_enabled = false;
module_param(memorizer_enabled, bool, 0644);

/* flag enable/disable memory access logging */
static bool memorizer_log_access = false;
module_param(memorizer_log_access, bool, 0644);

/* object cache for memorizer kobjects */
static struct kmem_cache *kobj_cache;

/* object cache for access count objects */
static struct kmem_cache *access_from_counts_cache;

/* active kobj metadata rb tree */
static struct rb_root active_kobj_rbtree_root = RB_ROOT;

/* full list of freed kobjs */
static LIST_HEAD(freed_kobjs);

/* global object id reference counter */
static atomic_long_t global_kobj_id_count = ATOMIC_INIT(0);

//==-- Locks --=//
/* RW Spinlock for access to rb tree */
DEFINE_RWLOCK(active_kobj_rbtree_spinlock);

/* RW Spinlock for access to freed kobject list */
DEFINE_RWLOCK(freed_kobjs_spinlock);

/* mask to apply to memorizer allocations TODO: verify the list */
#define gfp_memorizer_mask(gfp)	(((gfp) & (		\
					 | GFP_ATOMIC		\
					 | __GFP_NOACCOUNT))	\
					 | __GFP_NORETRY	\
					 | __GFP_NOMEMALLOC	\
					 | __GFP_NOWARN		\
					 | __GFP_NOTRACK	\
				 )

/**
 * __memorizer_enter() - increment recursion counter for entry into memorizer
 *
 * The primary goal of this is to stop recursive handling of events. Memorizer
 * by design tracks two types of events: allocations and accesses. Effectively,
 * while tracking either type we do not want to re-enter and track memorizer
 * events that are sources from within memorizer. Yes this means we may not
 * track legitimate access of some types, but these are caused by memorizer and
 * we want to ignore them. 
 */
static inline void __memorizer_enter(void)
{
	++current->memorizer_recursion;
}

static inline void __memorizer_exit(void)
{
	--current->memorizer_recursion;
}

/**
 * in_memorizer() - check if this thread has already entered memorizer
 */
static inline bool in_memorizer(void)
{
	return current->memorizer_recursion;
}

//==-- Debug and Stats Output Code --==//
static atomic_long_t memorizer_num_untracked_accesses = ATOMIC_INIT(0);
static atomic_long_t memorizer_caused_accesses = ATOMIC_INIT(0);
static atomic_long_t memorizer_num_accesses = ATOMIC_INIT(0);
static atomic_long_t memorizer_num_untracked_allocs = ATOMIC_INIT(0);
static atomic_long_t memorizer_num_tracked_allocs = ATOMIC_INIT(0);
static atomic_long_t stats_num_page_allocs = ATOMIC_INIT(0);
static atomic_long_t stats_num_globals = ATOMIC_INIT(0);
static atomic_long_t stats_num_induced_allocs = ATOMIC_INIT(0);

/**
 * __print_memorizer_kobj() - print out the object for debuggin
 *
 * Grab reader lock if you want to  make sure things don't get modified while we
 * are printing
 */
void __print_memorizer_kobj(struct memorizer_kobj * kobj, char * title)
{
	struct list_head * listptr;
	struct access_from_counts *entry;

	pr_info("%s: \n", title);
	pr_info("\tkobj_id:	%ld\n", kobj->obj_id);
	pr_info("\talloc_mod:	%s\n", *kobj->modsymb);
	pr_info("\talloc_func:	%s\n", kobj->funcstr);
	pr_info("\talloc_ip:	0x%p\n", (void*) kobj->alloc_ip);
	pr_info("\tfree_ip:	0x%p\n", (void*) kobj->free_ip);
	pr_info("\tva:		0x%p\n", (void*) kobj->va_ptr);
	pr_info("\tpa:		0x%p\n", (void*) kobj->pa_ptr);
	pr_info("\tsize:	%lu\n", kobj->size);
	pr_info("\talloc jiffies: %lu\n", kobj->alloc_jiffies);
	pr_info("\tfree jiffies:  %lu\n", kobj->free_jiffies);
	pr_info("\tpid: %d\n", kobj->pid);
	pr_info("\texecutable: %s\n", kobj->comm);
	list_for_each(listptr, &(kobj->access_counts)){
		entry = list_entry(listptr, struct access_from_counts, list);
		pr_info("\t  Access IP: %p, PID: %d, Writes: %llu, Reads: %llu\n",
			(void *) entry->ip, entry->pid,
			(unsigned long long) entry->writes,
			(unsigned long long) entry->reads);
	}
}
EXPORT_SYMBOL(__print_memorizer_kobj);

/**
 * read_locking_print_memorizer_kobj() - grap the reader spinlock then print
 */
static void read_locking_print_memorizer_kobj(struct memorizer_kobj * kobj, char
					      * title)
{
	unsigned long flags;
	read_lock_irqsave(&kobj->rwlock, flags);
	__print_memorizer_kobj(kobj, title);
	read_unlock_irqrestore(&kobj->rwlock, flags);
}

/**
 * __print_rb_tree() - print the tree
 */
static void __print_active_rb_tree(struct rb_node * rb)
{
	struct memorizer_kobj * kobj;
	if(rb){
		kobj = rb_entry(rb, struct memorizer_kobj, rb_node);
		read_locking_print_memorizer_kobj(kobj,"Kernel Object");
		if(kobj->rb_node.rb_left)
			__print_active_rb_tree(kobj->rb_node.rb_left);
		if(kobj->rb_node.rb_right)
			__print_active_rb_tree(kobj->rb_node.rb_right);
	}
}

/**
 * access_degree() - for the specified access type count the degree of access
 */
void access_degree(struct list_head * acl, unsigned int * write_deg,
		   unsigned int * read_deg)
{
	struct list_head * listptr;
	struct access_from_counts * ac;
	/* For each ld/st in the access counts entry add 1 */
	list_for_each(listptr, acl) {
		ac = list_entry(listptr, struct access_from_counts, list);
		/* if the ac has at least one write then it counts */
		if(ac->writes > 0)
			*write_deg += 1;
		if(ac->reads > 0)
			*read_deg += 1;
	}
}

/**
 * __print_rb_tree() - print the tree
 */
static void print_rb_tree_access_counts(struct rb_node * rb)
{
	struct memorizer_kobj * kobj;
	if(rb){
		kobj = rb_entry(rb, struct memorizer_kobj, rb_node);

		unsigned int write_deg = 0, read_deg = 0;

		access_degree(&kobj->access_counts, &write_deg, &read_deg);

		pr_info("%s %d %s %u %u\n", kobj->funcstr, kobj->pid, kobj->comm,
			write_deg, read_deg);

		if(kobj->rb_node.rb_left)
			print_rb_tree_access_counts(kobj->rb_node.rb_left);
		if(kobj->rb_node.rb_right)
			print_rb_tree_access_counts(kobj->rb_node.rb_right);
	}
}

/**
 */
static void print_pdf_table(void)
{
	unsigned long flags;

	/* calculate stats and print the free'd objects */
	struct list_head *p;
	struct memorizer_kobj *kobj;

	read_lock_irqsave(&freed_kobjs_spinlock, flags);

	list_for_each(p, &freed_kobjs){
		unsigned int write_deg = 0, read_deg = 0;

		kobj = list_entry(p, struct memorizer_kobj, freed_kobjs);

		access_degree(&kobj->access_counts, &write_deg, &read_deg);

		pr_info("%s %d %s %u %u\n", kobj->funcstr, kobj->pid, kobj->comm,
			write_deg, read_deg);

	}
	read_unlock_irqrestore(&freed_kobjs_spinlock, flags);

	/* same for live objects */
	print_rb_tree_access_counts(active_kobj_rbtree_root.rb_node);
}

/**
 * print_stats() - print global stats from memorizer 
 */
static void print_stats(void)
{
	pr_info("------- Memory Accesses -------\n");
	pr_info("    Tracked:			\t%16ld\n",
		atomic_long_read(&memorizer_num_accesses) -
		atomic_long_read(&memorizer_num_untracked_accesses) -
		atomic_long_read(&memorizer_caused_accesses)
		);
	pr_info("    Not-tracked:		\t%16ld\n",
		atomic_long_read(&memorizer_num_untracked_accesses));
	pr_info("    Memorizer-Induced:		%16ld\n",
		atomic_long_read(&memorizer_caused_accesses));
	pr_info("    Total:			\t%16ld\n",
		atomic_long_read(&memorizer_num_accesses));
	pr_info("------- Memory Allocations -------\n");
	pr_info("    Tracked (kmalloc+kmem_cache):     %16ld\n",
		atomic_long_read(&memorizer_num_tracked_allocs));
	pr_info("    Untracked (kmalloc+kmem_cache):   %16ld\n",
		atomic_long_read(&memorizer_num_untracked_allocs));
	pr_info("    Memorizer induced:                %16ld\n",
		atomic_long_read(&stats_num_induced_allocs));
	pr_info("    Page Alloc (total):               %16ld\n",
		atomic_long_read(&stats_num_page_allocs));
	pr_info("    Global Var (total):               %16ld\n",
		atomic_long_read(&stats_num_globals));
}

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
	int i, e, log_index;
	struct mem_access_worklists * ma_wls;
	struct memorizer_mem_access *mal, *ma; /* mal is the list ma is the
						  instance */
	__memorizer_enter();

	print_stats();

	/* Get data structure for the worklists and init the iterators */
	ma_wls = &get_cpu_var(mem_access_wls);
	mal = (struct memorizer_mem_access*) &(ma_wls->wls[ma_wls->selector]);
	log_index = ma_wls->head;

	pr_info("WLS State: selector = %lu, head = %ld, tail = %ld",
		ma_wls->selector, ma_wls->head, ma_wls->tail);

	/* 
	 * If we are at the front of the list then allow wrap back, note that
	 * this will print garbage if this function is called without having
	 * wrapped.
	 */
	if((log_index - num_events) > 0)
		i = log_index - num_events;
	else
		i = MEM_ACC_L_SIZE - 1 - (num_events - log_index + 1);

	for(e = 0; e < num_events; e++)
	{
		char *type_str[10];
		ma = &mal[i];
		pr_info("access from IP 0x%p at addr 0x%p\n", (void *)
			ma->src_ip, (void *) ma->access_addr);
		switch(ma->access_type){
		case Memorizer_READ:
			*type_str = "Read\0";
			break;
		case Memorizer_WRITE:
			*type_str = "Write\0";
			break;
		default:
			pr_info("Unmatched event type\n");
			*type_str = "Unknown\0";
		}
		pr_info("%s of size %lu by task %s/%d\n", *type_str,
			(unsigned long) ma->access_size, ma->comm, ma->pid);
		if(++i >= MEM_ACC_L_SIZE)
			i = 0;
	}
	put_cpu_var(mem_access_wls);

	__memorizer_exit();
}
EXPORT_SYMBOL(__memorizer_print_events);


/**
 * dump_freed_kobjs() - print out the list of free'd objects
 */
static void dump_freed_kobjs(void)
{
	unsigned long flags;
	struct list_head *p;
	struct memorizer_kobj *kobj;
	read_lock_irqsave(&freed_kobjs_spinlock, flags);
	list_for_each(p, &freed_kobjs){
		kobj = list_entry(p, struct memorizer_kobj, freed_kobjs);
		read_locking_print_memorizer_kobj(kobj, "Dump Free'd kobj");
	}
	read_unlock_irqrestore(&freed_kobjs_spinlock, flags);
}

//----
//==-- Memorizer Access Processing ----------------------------------------==//
//----

/**
 * init_access_counts_object() - initialize data for the object
 * @afc:	object to init 
 * @ip:		ip of access
 */
static inline void
init_access_counts_object(struct access_from_counts *afc, uint64_t ip, pid_t
			  pid)
{
	afc->ip = ip;
	afc->pid = pid;
	afc->writes = 0;
	afc->reads = 0;
}

/**
 * alloc_new_and_init_access_counts() - allocate a new access count and init
 * @ip:		the access from value
 */
static inline struct access_from_counts *
alloc_and_init_access_counts(uint64_t ip, pid_t pid)
{
	struct access_from_counts * afc = NULL;
	afc = kmem_cache_alloc(access_from_counts_cache, GFP_ATOMIC);
	if(afc)
		init_access_counts_object(afc, ip, pid);
	return afc;
}

/**
 * access_from_counts - search kobj's access_from for an entry from src_ip
 * @src_ip:	the ip to search for
 * @kobj:	the object to search within
 *
 * This function does not do any locking and therefore assumes the caller will
 * already have at least a reader lock. This is a big aggregate function, but
 * given that it will occur a lot we will be searching the list for a given
 * object, therefore we can easily do insertion if we don't find it, keeping a
 * linearly monotonic sorted list.
 */
static inline struct access_from_counts *
unlckd_insert_get_access_counts(uint64_t src_ip, pid_t pid, struct
				memorizer_kobj *kobj)
{
	struct list_head * listptr;
	struct access_from_counts *entry;
	struct access_from_counts * afc = NULL;
	list_for_each(listptr, &(kobj->access_counts)){
		entry = list_entry(listptr, struct access_from_counts, list);
		if(src_ip == entry->ip)
			return entry;
		else if(src_ip < entry->ip)
			break;
	}
	/* allocate the new one and initialize the count none in list */
	afc = alloc_and_init_access_counts(src_ip, pid);
	if(afc)
		list_add_tail(&(afc->list), listptr);
	return afc;
}

/**
 * update_kobj_access() - find and update the object information
 * @memorizer_mem_access:	The access to account for
 *
 * Find the object associated with this memory write, search for the src ip in
 * the access structures, incr if found or alloc and add new if not.
 *
 * Executes from the context of memorizer_mem_access and therefore we are
 * already operating with interrupts off and preemption disabled, and thus we
 * cannot sleep.
 */
static inline int find_and_update_kobj_access(struct memorizer_mem_access *ma)
{
	struct memorizer_kobj *kobj = NULL;
	struct access_from_counts *afc = NULL;

	/* Get the kernel object associated with this VA */
	//read_lock(&active_kobj_rbtree_spinlock);
	//kobj = unlocked_lookup_kobj_rbtree(ma->access_addr,
					   //&active_kobj_rbtree_root);
	kobj = lt_get_kobj(ma->access_addr);
	//read_unlock(&active_kobj_rbtree_spinlock);

	if(!kobj){
		atomic_long_inc(&memorizer_num_untracked_accesses);
		return -1;
	}

	/* Grab the object lock here */
	write_lock(&kobj->rwlock);
	if(likely(kobj->alloc_jiffies <= ma->jiffies))
	{
		/* Search access queue to the entry associated with src_ip */
		afc = unlckd_insert_get_access_counts(ma->src_ip, ma->pid,
						      kobj);
		/* increment teh counter associated with the access type */
		if(afc)
			ma->access_type ? ++afc->writes : ++afc->reads;

#if MEMORIZER_DEBUG >= 2
		__print_memorizer_kobj(kobj, "New Object Access Update");
#endif
	}
	write_unlock(&kobj->rwlock);
	return afc ? 0 : -1;
}

/**
 * drain_and_process_access_queue() - remove entries from the queue and do stats
 * @mawls:	the percpu wl struct to drain
 *
 * While the list is not empty take the top element and update the kobj it
 * accessed. Note that the kobj for this could be not found so we just ignore it
 * and move on if the update function failed.
 */
static inline void drain_and_process_access_queue(struct mem_access_worklists *
						  ma_wls) 
{
	while(ma_wls->head >= 0){
		//pr_info("Head: %ld", ma_wls->head);
		find_and_update_kobj_access(
			    &(ma_wls->wls[ma_wls->selector][ma_wls->head])
			     );
		--ma_wls->head;
	}
}

//==-- Memorizer memory access tracking -----------------------------------==//

/**
 * set_comm_and_pid - Find the execution context of the ld/st
 *
 * Set the pid and the task name. These are together because we want to optimize
 * the number of branches in this to make it faster.
 */
static inline void set_comm_and_pid(struct memorizer_mem_access *ma)
{
	int i;
	char *comm;
	char *hardirq = "hardirq";
	char *softirq = "softirq";

	/* task information */
	if (unlikely(in_irq())) {
		ma->pid = 0;
		comm = hardirq;
	} else if (unlikely(in_softirq())) {
		ma->pid = 0;
		comm = softirq;
	} else {
		ma->pid = task_pid_nr(current);
		/*
		 * There is a small chance of a race with set_task_comm(),
		 * however using get_task_comm() here may cause locking
		 * dependency issues with current->alloc_lock. In the worst
		 * case, the command line is not correct.
		 */
		comm = current->comm;
	}
#if 0 /* TODO: this is to make the testing faster */
	for(i=0; i<sizeof(comm); i++)
		ma->comm[i] = comm[i];
	ma->comm[i] = '\0';
#endif
}

/**
 * memorizer_mem_access() - record associated data with the load or store
 * @addr:	The virtual address being accessed
 * @size:	The number of bits for the load/store
 * @write:	True if the memory access is a write (store)
 * @ip:		IP of the invocing instruction
 *
 * Memorize, ie. log, the particular data access by inserting it into a percpu
 * queue. 
 */
void __always_inline memorizer_mem_access(uintptr_t addr, size_t size, bool
					  write, uintptr_t ip)
{
	unsigned long flags;
	struct memorizer_mem_access ma;
	struct mem_access_worklists * ma_wls;

#if MEMORIZER_STATS // Stats take time per access
	atomic_long_inc(&memorizer_num_accesses);

	if(!(lt_get_kobj(addr)))
	{
		atomic_long_inc(&memorizer_num_untracked_accesses);
		return;
	}

	if(!memorizer_log_access){
		atomic_long_inc(&memorizer_num_untracked_accesses);
		return;
	}

	/* Try to grab the lock and if not just returns */
	if(in_memorizer()){
		atomic_long_inc(&memorizer_caused_accesses);
		return;
	}
#else
	if(!(lt_get_kobj(addr)))
		return;
	if(!memorizer_log_access)
		return;
	if(in_memorizer())
		return;
#endif

	__memorizer_enter();

	local_irq_save(flags);

	/* Get the local cpu data structure */
	//ma_wls = &get_cpu_var(mem_access_wls);
	/* Head points to the last inserted element, except for -1 on init */
	//if(ma_wls->head >= MEM_ACC_L_SIZE - 1){
		//drain_and_process_access_queue(ma_wls);
	//}
	//++ma_wls->head;
	//ma_wls->head = 0;

	/* if producer caught consumer overwrite, losing the oldest events */
	//if(ma_wls->head == ma_wls->tail)
		//++ma_wls->tail;
	//ma = &(ma_wls->wls[ma_wls->selector][ma_wls->head]);

	/* Initialize the event data */
	//set_comm_and_pid(ma);
	ma.pid = task_pid_nr(current);
	ma.access_type = write;
	ma.access_addr = addr;
	ma.access_size = size;
	ma.src_ip = ip;
	ma.jiffies = jiffies;

	find_and_update_kobj_access(&ma);

	/* put the cpu vars and reenable interrupts */
	//put_cpu_var(mem_access_wls);
	local_irq_restore(flags);

	__memorizer_exit();
}

//==-- Memorizer kernel object tracking -----------------------------------==//

/**
 * init_kobj() - Initalize the metadata to track the recent allocation
 */
static void init_kobj(struct memorizer_kobj * kobj, uintptr_t call_site,
		      uintptr_t ptr_to_kobj, size_t bytes_alloc)
{
	rwlock_init(&kobj->rwlock);

	if(atomic_long_inc_and_test(&global_kobj_id_count)){
		pr_warn("Global kernel object counter overlapped...");
	}

	kobj->alloc_ip = call_site;
	kobj->va_ptr = ptr_to_kobj;
	kobj->pa_ptr = __pa(ptr_to_kobj);
	kobj->size = bytes_alloc;
	kobj->alloc_jiffies = jiffies;
	kobj->free_jiffies = 0;
	kobj->obj_id = atomic_long_read(&global_kobj_id_count);
	INIT_LIST_HEAD(&kobj->access_counts);
	INIT_LIST_HEAD(&kobj->freed_kobjs);
	memset(kobj->comm, '\0', sizeof(kobj->comm));
	/* Some of the call sites are not tracked correctly so don't try */
	if(call_site)
		kallsyms_lookup((unsigned long) call_site, NULL, NULL,
				&(kobj->modsymb), kobj->funcstr);
	/* task information */
	if (in_irq()) {
		kobj->pid = 0;
		strncpy(kobj->comm, "hardirq", sizeof(kobj->comm));
	} else if (in_softirq()) {
		kobj->pid = 0;
		strncpy(kobj->comm, "softirq", sizeof(kobj->comm));
	} else {
		kobj->pid = current->pid;
		/*
		 * There is a small chance of a race with set_task_comm(),
		 * however using get_task_comm() here may cause locking
		 * dependency issues with current->alloc_lock. In the worst
		 * case, the command line is not correct.
		 */
		strncpy(kobj->comm, current->comm, sizeof(kobj->comm));
	}

#if MEMORIZER_DEBUG >= 5
	__print_memorizer_kobj(kobj, "Allocated and initalized kobj");
#endif
}

/**
 * clear_free_list() --- remove entries from free list and free kobjs
 */
static void clear_free_list(void)
{
	struct memorizer_kobj *kobj;
	struct access_from_counts *afc;
	unsigned long flags;

	pr_info("Clearing the free'd list\n");

	__memorizer_enter();
	write_lock_irqsave(&freed_kobjs_spinlock, flags);
	/* free each kobj */
	while(!list_empty(&freed_kobjs))
	{
		kobj = list_first_entry(&freed_kobjs, struct memorizer_kobj,
					freed_kobjs);
		/* remove the kobj from the free-list */
		list_del(&kobj->freed_kobjs);

		/* Free each memory_access object */
		read_lock(&kobj->rwlock);
		while(!list_empty(&kobj->access_counts)){
			afc = list_first_entry(&kobj->access_counts, struct
					       access_from_counts, list);
			list_del(&afc->list);
			kmem_cache_free(&access_from_counts_cache, afc);
		}
		read_unlock(&kobj->rwlock);
		/* free the kobj */
		kmem_cache_free(&kobj_cache, kobj);
	}
	write_unlock_irqrestore(&freed_kobjs_spinlock, flags);
	__memorizer_exit();
}

/**
 * add_kobj_to_rb_tree - add the object to the tree
 * @kobj:	Pointer to the object to add to the tree
 *
 * Standard rb tree insert. The key is the range. So if the object is allocated
 * < than the active node's region then traverse left, if greater than traverse
 * right, and if not that means we have an overlap and have a problem in
 * overlapping allocations. 
 */
static struct memorizer_kobj * unlocked_insert_kobj_rbtree(struct memorizer_kobj
							   *kobj, struct rb_root
							   *kobj_rbtree_root)
{
	struct memorizer_kobj *parent;
	struct rb_node **link;
	struct rb_node *rb_parent = NULL;

	link = &(kobj_rbtree_root->rb_node);
	while (*link) {
		rb_parent = *link;
		parent = rb_entry(rb_parent, struct memorizer_kobj, rb_node);
		if (kobj->va_ptr + kobj->size <= parent->va_ptr)
		{
			link = &parent->rb_node.rb_left;
		}
		else if (parent->va_ptr + parent->size <= kobj->va_ptr)
		{
			link = &parent->rb_node.rb_right;
		}
		else
		{
			pr_err("Cannot insert 0x%lx into the object search tree"
			       " (overlaps existing)\n", kobj->va_ptr);
			__print_memorizer_kobj(parent, "");
			kmem_cache_free(kobj_cache, kobj);
			kobj = NULL;
			break;
		}
	}
	if(likely(kobj != NULL)){
		rb_link_node(&kobj->rb_node, rb_parent, link);
		rb_insert_color(&kobj->rb_node, kobj_rbtree_root);
	}
	return kobj;
}

/**
 * search_kobj_from_rbtree() - lookup the kobj from the tree
 * @kobj_ptr:	The ptr to find the active for 
 * @rbtree:	The rbtree to lookup in
 *
 * This function searches for the memorizer_kobj associated with the passed in
 * pointer in the passed in kobj_rbtree. Since this is a reading on the rbtree
 * we assume that the particular tree being accessed has had it's lock acquired
 * properly already.
 */
static struct memorizer_kobj * unlocked_lookup_kobj_rbtree(uintptr_t kobj_ptr,
							   struct rb_root *
							   kobj_rbtree_root)
{
	struct rb_node *rb = kobj_rbtree_root->rb_node;

	while (rb) {
		struct memorizer_kobj * kobj =
			rb_entry(rb, struct memorizer_kobj, rb_node);
		/* Check if our pointer is less than the current node's ptr */
		if (kobj_ptr < kobj->va_ptr)
			rb = kobj->rb_node.rb_left;
		/* Check if our pointer is greater than the current node's ptr */
		else if (kobj_ptr >= (kobj->va_ptr + kobj->size))
			rb = kobj->rb_node.rb_right;
		/* At this point we have found the node because rb != null */
		else
			return kobj;
	}
	return NULL;
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
void static move_kobj_to_free_list(uintptr_t call_site, uintptr_t kobj_ptr)
{
	struct memorizer_kobj *kobj;

	unsigned long flags;

	//read_lock_irqsave(&active_kobj_rbtree_spinlock, flags);
	//kobj = unlocked_lookup_kobj_rbtree(kobj_ptr, &active_kobj_rbtree_root);
	kobj = lt_remove_kobj(kobj_ptr);
	//kobj = lt_get_kobj(kobj_ptr);
	//read_unlock_irqrestore(&active_kobj_rbtree_spinlock, flags);

	/* 
	 * If this is null it means we are freeing something we did not insert
	 * into our tree and we have a missed alloc track
	 */
	if(kobj){
		/* remove from the active_kobj_rbtree */
		//write_lock_irqsave(&active_kobj_rbtree_spinlock, flags);
		/* External Memorizer Function: Must protect from re-entry */
		//rb_erase(&(kobj->rb_node), &active_kobj_rbtree_root);
		//lt_remove_kobj(kobj_ptr);
		//write_unlock_irqrestore(&active_kobj_rbtree_spinlock, flags);

		/* Update the free_jiffies for the object */
		write_lock_irqsave(&kobj->rwlock, flags);
		kobj->free_jiffies = jiffies;
		kobj->free_ip = call_site;
#if MEMORIZER_DEBUG >= 2
		__print_memorizer_kobj(kobj, "Free'd kobject");
#endif
		write_unlock_irqrestore(&kobj->rwlock, flags);

		/* Insert into the process queue */
		write_lock_irqsave(&freed_kobjs_spinlock, flags);
		list_add(&kobj->freed_kobjs, &freed_kobjs);
		write_unlock_irqrestore(&freed_kobjs_spinlock, flags);
	}
}

/**
 * free_kobj_kmem_cache() - free the object from the kmem_cache
 * @kobj:	The kernel object metadata to free
 * @kmemcache:	The cache to free from
 */

/**
 * memorizer_alloc() - record allocation event
 * @object:	Pointer to the beginning of hte object
 * @size:	Size of the object
 *
 * Track the allocation and add the object to the set of active object tree.
 */
static void inline __memorizer_kmalloc(unsigned long call_site, const void *ptr,
				       size_t bytes_req, size_t bytes_alloc,
				       gfp_t gfp_flags)
{
	unsigned long flags;
	struct memorizer_kobj *kobj;

	if(unlikely(ptr==NULL) || unlikely(IS_ERR(ptr)))
		return;

	if(unlikely(!memorizer_enabled))
	{
		atomic_long_inc(&memorizer_num_untracked_allocs);
		return;
	}

	if(in_memorizer())
	{
		atomic_long_inc(&stats_num_induced_allocs);
		return;
	}

#if 0 // Prototype for filtering: static though so leave off
	if(call_site < selinux.b || call_site >= crypto_code_region.e)
		return;
#endif

	atomic_long_inc(&memorizer_num_tracked_allocs);

	__memorizer_enter();

#if MEMORIZER_DEBUG >= 4
	pr_info("alloca from %p @ %p of size: %lu. GFP-Flags: 0x%lx\n",
		(void*)call_site, ptr, bytes_alloc, (unsigned long long)
		gfp_flags);
#endif

	kobj = kmem_cache_alloc(kobj_cache, gfp_flags | GFP_ATOMIC);
	if(!kobj){
		pr_info("Cannot allocate a memorizer_kobj structure\n");
	}

	init_kobj(kobj, (uintptr_t) call_site, (uintptr_t) ptr, bytes_alloc);

	/* Grab the writer lock for the active_kobj_rbtree */
	//write_lock_irqsave(&active_kobj_rbtree_spinlock, flags);
	/* subcall to an non-memorizer function that re-enters ma code */
	//unlocked_insert_kobj_rbtree(kobj, &active_kobj_rbtree_root);

	if(lt_insert_kobj(kobj)){
		//kmem_cache_free(kobj_cache, kobj);
		//kobj = NULL;
	}

	//write_unlock_irqrestore(&active_kobj_rbtree_spinlock, flags);

	__memorizer_exit();
}

/*** HOOKS similar to the kmem points ***/
void memorizer_kmalloc(unsigned long call_site, const void *ptr, size_t
		      bytes_req, size_t bytes_alloc, gfp_t gfp_flags)
{
	__memorizer_kmalloc(call_site, ptr, bytes_req, bytes_alloc, gfp_flags);
}

void memorizer_kmalloc_node(unsigned long call_site, const void *ptr, size_t
			   bytes_req, size_t bytes_alloc, gfp_t gfp_flags, int
			   node)
{
	__memorizer_kmalloc(call_site, ptr, bytes_req, bytes_alloc, gfp_flags);
}

void memorizer_kfree(unsigned long call_site, const void *ptr)
{
	/* 
	 * Condition for ensuring free is from online cpu: see trace point
	 * condition from include/trace/events/kmem.h for reason
	 */
	if(unlikely(!cpu_online(raw_smp_processor_id())) || !memorizer_enabled){
		return;
	}
	__memorizer_enter();
	move_kobj_to_free_list((uintptr_t) call_site, (uintptr_t) ptr);
	__memorizer_exit();
}

void memorizer_kmem_cache_alloc(unsigned long call_site, const void *ptr, size_t
				bytes_req, size_t bytes_alloc, gfp_t gfp_flags)
{
	__memorizer_kmalloc(call_site, ptr, bytes_req, bytes_alloc, gfp_flags);
}

void memorizer_kmem_cache_alloc_node (unsigned long call_site, const void *ptr,
				      size_t bytes_req, size_t bytes_alloc,
				      gfp_t gfp_flags, int node)
{
	__memorizer_kmalloc(call_site, ptr, bytes_req, bytes_alloc, gfp_flags);
}

void memorizer_kmem_cache_free(unsigned long call_site, const void *ptr)
{
	/* 
	 * Condition for ensuring free is from online cpu: see trace point
	 * condition from include/trace/events/kmem.h for reason
	 */
	if(unlikely(!cpu_online(raw_smp_processor_id())) || !memorizer_enabled){
		return;
	}
	__memorizer_enter();
	move_kobj_to_free_list((uintptr_t) call_site, (uintptr_t) ptr);
	__memorizer_exit();
}


void memorizer_alloc_pages(unsigned long call_site, struct page *page, unsigned
			   int order)
{
	atomic_long_inc(&stats_num_page_allocs);
	//__memorizer_kmalloc(call_site, page_address(page),
			    //(uintptr_t) (PAGE_SIZE << order),
			    //(uintptr_t) (PAGE_SIZE << order), 0);
}

void memorizer_free_pages(unsigned long call_site, struct page *page, unsigned
			  int order)
{
	/* 
	 * Condition for ensuring free is from online cpu: see trace point
	 * condition from include/trace/events/kmem.h for reason
	 */
	if(unlikely(!cpu_online(raw_smp_processor_id())) || !memorizer_enabled){
		return;
	}
	__memorizer_enter();
	move_kobj_to_free_list((uintptr_t) call_site, (uintptr_t)
			       page_address(page));
	__memorizer_exit();
}

void memorizer_register_global(const void *ptr, size_t size)
{
	static int once = 0;
	atomic_long_inc(&stats_num_globals);
	__memorizer_kmalloc(0, ptr, size, size, 0);
}

//==-- Memorizer Data Export ----------------------------------------------==//

/*
 * Iterate over the object_list and return the first valid object at or after
 * the required position with its use_count incremented. The function triggers
 * a memory scanning when the pos argument points to the first position.
 */
static void *memorizer_seq_start(struct seq_file *seq, loff_t *pos)
{
	//loff_t n = *pos;

	if(list_empty(&freed_kobjs))
	   return NULL;

	return list_first_entry(&freed_kobjs, struct memorizer_kobj,
				freed_kobjs);
	//err = mutex_lock_interruptible(&scan_mutex);
	//if (err < 0)
		//return ERR_PTR(err);

	//rcu_read_lock();
	//list_for_each_entry_rcu(object, &object_list, object_list) {
		//if (n-- > 0)
			//continue;
		//if (get_object(object))
			//goto out;
	//}
	//object = NULL;
//out:
	//return object;
}

/*
 */
static void *memorizer_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	unsigned long flags;
	struct memorizer_kobj *prev_kobj = v;
	struct memorizer_kobj *next_kobj = NULL;
	//struct memorizer_object *kobj = prev_kobj;

	++(*pos);

	write_lock_irqsave(&freed_kobjs_spinlock, flags);

	/* Get the next kobj */
	next_kobj = list_entry(prev_kobj->freed_kobjs.next, struct
			       memorizer_kobj, freed_kobjs);

	/* Remove the previous from the list */
	list_del(&prev_kobj->freed_kobjs);


	/* TODO: free the memory */

	if(list_empty(&next_kobj->freed_kobjs))
		next_kobj = NULL;

	write_unlock_irqrestore(&freed_kobjs_spinlock, flags);

	return next_kobj;

	//list_for_each_entry_continue_rcu(obj, &object_list, object_list) {
		//if (get_object(obj)) {
			//next_obj = obj;
			//break;
		//}
	//}

	//put_object(prev_obj);
	//return next_obj;
}

/*
 */
static void memorizer_seq_stop(struct seq_file *seq, void *v)
{
	/* do nothing */
}

/*
 * Print the information for an unreferenced object to the seq file.
 */
static int memorizer_seq_show(struct seq_file *seq, void *v)
{
	struct memorizer_kobj *kobj = v;
	struct list_head * listptr;
	struct access_from_counts *entry;
	unsigned long flags;

	read_lock_irqsave(&kobj->rwlock, flags);

	seq_printf(seq,"%p,%p,%p,%lu,%d,%s\n",
		   (void*) kobj->alloc_ip, (void*) kobj->free_ip, (void*)
		   kobj->va_ptr, kobj->size, kobj->pid, kobj->comm);

	list_for_each(listptr, &(kobj->access_counts)){
		entry = list_entry(listptr, struct access_from_counts, list);
		//seq_printf(seq, "  Access IP: %p, PID: %d, Writes: %llu, Reads: %llu\n",
		seq_printf(seq, "  %p,%d,%llu,%llu\n",
			(void *) entry->ip, entry->pid,
			(unsigned long long) entry->writes,
			(unsigned long long) entry->reads);
	}

	read_unlock_irqrestore(&kobj->rwlock, flags);
	return 0;
}

static const struct seq_operations memorizer_seq_ops = {
	.start = memorizer_seq_start,
	.next  = memorizer_seq_next,
	.stop  = memorizer_seq_stop,
	.show  = memorizer_seq_show,
};

static int memorizer_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &memorizer_seq_ops);
}

static ssize_t memorizer_write(struct file *file, const char __user *user_buf,
			       size_t size, loff_t *ppos)
{
	char buf[64];
	int buf_size;
	int ret;

#if 0
	buf_size = min(size, (sizeof(buf) - 1));
	if (strncpy_from_user(buf, user_buf, buf_size) < 0)
		return -EFAULT;
	buf[buf_size] = 0;

	if (strncmp(buf, "clear", 5) == 0) {
		if (kmemleak_enabled)
			kmemleak_clear();
		else
			__kmemleak_do_cleanup();
		goto out;
	}
#endif

	return 0;
}

static const struct file_operations memorizer_fops = {
	.owner		= THIS_MODULE,
	.open		= memorizer_open,
	.read		= seq_read,
	.write		= memorizer_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

//==-- Memorizer Initializtion --------------------------------------------==//

/**
 * create_obj_kmem_cache() - create the kernel object kmem_cache
 */
static void create_obj_kmem_cache(void)
{
	kobj_cache = KMEM_CACHE(memorizer_kobj,
				SLAB_PANIC
				//| SLAB_TRACE | SLAB_NOLEAKTRACE
			       );
}

/**
 * create_access_counts_kmem_cache() - create the kmem_cache for access_counts
 */
static void create_access_counts_kmem_cache(void)
{
	access_from_counts_cache = KMEM_CACHE(access_from_counts,
				SLAB_PANIC
				//| SLAB_TRACE | SLAB_NOLEAKTRACE
			       );
	pr_info("Just created kmem_cache object\n");
}

/**
 * init_mem_access_wl - initialize the percpu data structures
 *
 * Init all the values to 0 for the selector, head, and tail
 */
static void init_mem_access_wls(void)
{
	struct mem_access_worklists * wls;
	size_t cpu;
	for_each_possible_cpu(cpu){
		wls = &per_cpu(mem_access_wls, cpu);
		wls->selector = 0;
		wls->head = -1;
		wls->tail = 0;
	}
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
	__memorizer_enter();
	init_mem_access_wls();
	create_obj_kmem_cache();
	create_access_counts_kmem_cache();
	lt_init();
	local_irq_save(flags);
	memorizer_enabled = true;
	memorizer_log_access = true;
	local_irq_restore(flags);
	__memorizer_exit();
}

/*
 * Late initialization function.
 */
static int memorizer_late_init(void)
{
	unsigned long flags;
	struct dentry *dentry, *dentryMemDir;

	__memorizer_enter();

	dentryMemDir = debugfs_create_dir("memorizer", NULL);
	dentry = debugfs_create_file("memorizer_log", S_IRUGO, dentryMemDir,
				     NULL, &memorizer_fops);
	// Add a memorizer debug log function
	dentry = debugfs_create_bool("memorizer_enabled", 644, dentryMemDir,
				     &memorizer_enabled);
	dentry = debugfs_create_bool("memorizer_enabled", 644, dentryMemDir,
				     &memorizer_log_access);
	if (!dentry)
		pr_warning("Failed to create the debugfs memorizer file\n");

	local_irq_save(flags);
	memorizer_enabled = true;
	memorizer_log_access = true;
	local_irq_restore(flags);

	pr_info("Memorizer initialized\n");

	print_stats();
	//__memorizer_print_events(10);
	//dump_freed_kobjs();
	//__print_active_rb_tree(active_kobj_rbtree_root.rb_node);
	//print_pdf_table();

	__memorizer_exit();

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
	unsigned long flags;

	__memorizer_enter();

	pr_info("Running test from driver...");

	local_irq_save(flags);
	memorizer_enabled = true;
	memorizer_log_access = true;
	local_irq_restore(flags);

	print_stats();

#if MEMORIZER_DEBUG >= 5
	//read_lock_irqsave(&active_kobj_rbtree_spinlock, flags);

	pr_info("The free'd Kobj list");
	dump_freed_kobjs();

	pr_info("The live kernel object tree now:");
	__print_active_rb_tree(active_kobj_rbtree_root.rb_node);

	//read_unlock_irqrestore(&active_kobj_rbtree_spinlock, flags);
#endif

	print_stats();

	__memorizer_exit();
	return 0;
}
EXPORT_SYMBOL(memorizer_init_from_driver);
