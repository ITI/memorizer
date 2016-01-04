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
 *
 * Locking:  
 *
 *	Memorizer has two global and a percpu data structure:
 *	
 *		- global rbtree of active kernel objects 
 *		- TODO queue for holding free'd objects that haven't logged 
 *		- A percpu event queue to track memory access events
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
#include <linux/err.h>
#include <linux/export.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kmemleak.h>
#include <linux/memorizer.h>
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

//==-- Debugging and print information ------------------------------------==//
#define MEMORIZER_DEBUG		1

/* 
 * If we have a bug in memorizer (like calling an external function from the
 * memorizer_mem_access function, then we will re-enter that function. This is
 * costly so disable most of the time.
 */
#define PROTECT_MEM_ACCESS_REENTRY 1

//==-- Prototype Declarations ---------------------------------------------==//
static struct memorizer_kobj * unlocked_lookup_kobj_rbtree(uintptr_t kobj_ptr,
							   struct rb_root *
							   kobj_rbtree_root);
//==-- Data types and structs for building maps ---------------------------==//

/* Size of the memory access recording worklist arrays */
#define MEM_ACC_L_SIZE 100000

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
 * struct memorizer_kobj - metadata for kernel objects 
 * @rb_node:		the red-black tree relations
 * @alloc_ip:		instruction that allocated the object
 * @va_ptr:		Virtual address of the beginning of the object
 * @pa_ptr:		Physical address of the beginning of object
 * @size:		Size of the object
 * @jiffies:		Time stamp of creation
 * @pid:		PID of the current task
 * @comm:		Executable name
 *
 * This data structure captures the details of allocated objects
 */
struct memorizer_kobj {
	struct rb_node	rb_node;
	rwlock_t	rwlock;
	long		obj_id;
	uintptr_t	alloc_ip;
	uintptr_t	va_ptr;
	uintptr_t	pa_ptr;
	size_t		size;
	unsigned long	alloc_jiffies;
	unsigned long	free_jiffies;
	pid_t		pid;
	char comm[TASK_COMM_LEN];
	struct list_head access_counts;
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
//DEFINE_PER_CPU(struct mem_access_worklists, mem_access_wls = {.selector = 0, .head = 0, .tail = 0 });
DEFINE_PER_CPU(struct mem_access_worklists, mem_access_wls);

/* flag to keep track of whether or not to track writes */
bool memorizer_enabled = false;

/* flag enable/disable memory access logging */
bool memorizer_log_access = false;

/* object cache for memorizer kobjects */
static struct kmem_cache *kobj_cache;

/* object cache for access count objects */
static struct kmem_cache *access_from_counts_cache;

/* active kobj metadata rb tree */
static struct rb_root active_kobj_rbtree_root = RB_ROOT;

/* global object id reference counter */
atomic_long_t global_kobj_id_count = ATOMIC_INIT(0);

atomic_t in_ma = ATOMIC_INIT(0);

//==-- Locks --=//
/* RW Spinlock for access to rb tree */
DEFINE_RWLOCK(active_kobj_rbtree_spinlock);

/* mask to apply to memorizer allocations TODO: verify the list */
#define gfp_memorizer_mask(gfp)	(((gfp) & (		\
					 | GFP_ATOMIC		\
					 | __GFP_NOACCOUNT))	\
					 | __GFP_NORETRY	\
					 | __GFP_NOMEMALLOC	\
					 | __GFP_NOWARN		\
					 | __GFP_NOTRACK	\
				 )

//==-- Temporary test code --==//
atomic_long_t memorizer_num_stale_accesses = ATOMIC_INIT(0);
atomic_long_t memorizer_num_accesses = ATOMIC_INIT(0);
int __memorizer_get_opsx(void)
{
    return atomic_long_read(&memorizer_num_accesses);
}
EXPORT_SYMBOL(__memorizer_get_opsx);

atomic_long_t memorizer_num_untracked_allocs = ATOMIC_INIT(0);
atomic_long_t memorizer_num_tracked_allocs = ATOMIC_INIT(0);
int __memorizer_get_allocs(void)
{
    return atomic_long_read(&memorizer_num_tracked_allocs);
}
EXPORT_SYMBOL(__memorizer_get_allocs);

/**
 * __print_memorizer_kobj() - print out the object for debuggin
 *
 * Grab reader lock if you want to  make sure things don't get modified while we
 * are printing
 */
static void __print_memorizer_kobj(struct memorizer_kobj * kobj, char * title)
{
	struct list_head * listptr;
	struct access_from_counts *entry;

	pr_info("%s: \n", title);
	pr_info("\tkobj_id: %ld\n", kobj->obj_id);
	pr_info("\talloc_ip: 0x%p\n", (void*) kobj->alloc_ip);
	pr_info("\tva: 0x%p\n", (void*) kobj->va_ptr);
	pr_info("\tpa: 0x%p\n", (void*) kobj->pa_ptr);
	pr_info("\tsize: %lu\n", kobj->size);
	pr_info("\talloc jiffies: %lu\n", kobj->alloc_jiffies);
	pr_info("\tfree jiffies: %lu\n", kobj->free_jiffies);
	pr_info("\tpid: %d\n", kobj->pid);
	pr_info("\texecutable: %s\n", kobj->comm);

	list_for_each(listptr, &(kobj->access_counts)){
		entry = list_entry(listptr, struct access_from_counts, list);
		pr_info("\t  Access IP: %p, PID: %d, Writes: %llu, Reads: %llu\n",
			(void *) entry->ip, entry->pid, (unsigned long long) entry->writes,
			(unsigned long long) entry->reads);
	}
}

/**
 * read_locking_print_memorizer_kobj() - grap the reader spinlock then print
 */
void read_locking_print_memorizer_kobj(struct memorizer_kobj * kobj, char *
				       title)
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

	pr_info("\n\n***Memorizer Num Accesses: %ld, Stale due to free: %ld\n",
		atomic_long_read(&memorizer_num_accesses),
		atomic_long_read(&memorizer_num_stale_accesses)
		);
	pr_info("***Memorizer Num Allocs Tracked: %ld Untracked: %ld\n",
		atomic_long_read(&memorizer_num_tracked_allocs),
		atomic_long_read(&memorizer_num_untracked_allocs));

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
}
EXPORT_SYMBOL(__memorizer_print_events);

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
 * add_to_access_count_list() - Add a new entry to the access count list
 * @src_ip:	the address of the instance
 * @list_head: 
 */

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
int find_and_update_kobj_access(struct memorizer_mem_access *ma)
{
	struct memorizer_kobj *kobj = NULL;
	struct access_from_counts *afc = NULL;

	/* Get the kernel object associated with this VA */
	read_lock(&active_kobj_rbtree_spinlock);
	kobj = unlocked_lookup_kobj_rbtree(ma->access_addr,
					   &active_kobj_rbtree_root);
	read_unlock(&active_kobj_rbtree_spinlock);

	/* 
	 * If this is null then we didn't find it, for now just skip TODO: add
	 * the second queue to find it after free.
	 */
	if(!kobj){
		atomic_long_inc(&memorizer_num_stale_accesses);
		return -1;
	}

	/* Grab the object lock here */
	write_lock(&kobj->rwlock);
	if(kobj->alloc_jiffies <= ma->jiffies)
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
void drain_and_process_access_queue(struct mem_access_worklists * ma_wls)
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
	for(i=0; i<sizeof(comm); i++)
		ma->comm[i] = comm[i];
	ma->comm[i] = '\0';
}

/**
 * memorize_mem_access() - record associated data with the load or store
 * @addr:	The virtual address being accessed
 * @size:	The number of bits for the load/store
 * @write:	True if the memory access is a write (store)
 * @ip:		IP of the invocing instruction
 *
 * Memorize, ie. log, the particular data access by inserting it into a percpu
 * queue. 
 */
void memorize_mem_access(uintptr_t addr, size_t size, bool write, uintptr_t ip)
{
	unsigned long flags;
	struct memorizer_mem_access * ma;
	struct mem_access_worklists * ma_wls;

	atomic_long_inc(&memorizer_num_accesses);

	if(!memorizer_enabled || !memorizer_log_access)
		return;

#if PROTECT_MEM_ACCESS_REENTRY
	if(atomic_read(&in_ma))
		return;
	atomic_inc(&in_ma);
#endif
	local_irq_save(flags);

	/* Get the local cpu data structure */
	ma_wls = &get_cpu_var(mem_access_wls);
	/* Head points to the last inserted element, except for -1 on init */
	if(ma_wls->head >= MEM_ACC_L_SIZE - 1){
		drain_and_process_access_queue(ma_wls);
	}
	++ma_wls->head;

	/* if producer caught consumer overwrite, losing the oldest events */
	if(ma_wls->head == ma_wls->tail)
		++ma_wls->tail;
	ma = &(ma_wls->wls[ma_wls->selector][ma_wls->head]);

	/* Initialize the event data */
	set_comm_and_pid(ma);
	ma->access_type = write;
	ma->access_addr = addr;
	ma->access_size = size;
	ma->src_ip = ip;
	ma->jiffies = jiffies;

	/* put the cpu vars and reenable interrupts */
	put_cpu_var(mem_access_wls);
	local_irq_restore(flags);
#if PROTECT_MEM_ACCESS_REENTRY
	atomic_dec(&in_ma);
#endif
}

//==-- Memorizer kernel object tracking -----------------------------------==//

/**
 * init_kobj() - Initalize the metadata to track the recent allocation
 */
void init_kobj(struct memorizer_kobj * kobj, uintptr_t call_site, uintptr_t
	      ptr_to_kobj, size_t bytes_alloc)
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
	memset(kobj->comm, '\0', sizeof(kobj->comm));
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
 * add_kobj_to_rb_tree - add the object to the tree
 * @kobj:	Pointer to the object to add to the tree
 *
 * Standard rb tree insert. The key is the range. So if the object is allocated
 * < than the active node's region then traverse left, if greater than traverse
 * right, and if not that means we have an overlap and have a problem in
 * overlapping allocations. 
 */
struct memorizer_kobj * unlocked_insert_kobj_rbtree(struct memorizer_kobj *kobj,
						    struct rb_root
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
static void move_kobj_to_free_list(uintptr_t call_site, uintptr_t kobj_ptr)
{
	struct memorizer_kobj *kobj;

	unsigned long flags;

	read_lock_irqsave(&active_kobj_rbtree_spinlock, flags);
	kobj = unlocked_lookup_kobj_rbtree(kobj_ptr, &active_kobj_rbtree_root);
	read_unlock_irqrestore(&active_kobj_rbtree_spinlock, flags);

	/* 
	 * If this is null it means we are freeing something we did not insert
	 * into our tree and we have a missed alloc track
	 */
	if(kobj){
		/* remove from the active_kobj_rbtree */
		write_lock_irqsave(&active_kobj_rbtree_spinlock, flags);
		rb_erase(&(kobj->rb_node), &active_kobj_rbtree_root);
		write_unlock_irqrestore(&active_kobj_rbtree_spinlock, flags);

		/* Update the free_jiffies for the object */
		write_lock_irqsave(&kobj->rwlock, flags);
		kobj->free_jiffies = jiffies;
#if MEMORIZER_DEBUG >= 1
		__print_memorizer_kobj(kobj, "Free'd kobject");
#endif
		write_unlock_irqrestore(&kobj->rwlock, flags);


		/* Insert into the process queue */
	}

}

/**
 * free_kobj_kmem_cache() - free the object from the kmem_cache
 * @kobj:	The kernel object metadata to free
 * @kmemcache:	The cache to free from
 */


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
	unsigned long flags;
	struct memorizer_kobj *kobj;

	//unlikely(IS_ERR(ptr)))
	//if(object > crypto_code_region.b && object < crypto_code_region.e)
	if(unlikely(ptr==NULL))
		return;

	if(unlikely(!memorizer_enabled))
	{
		atomic_long_inc(&memorizer_num_untracked_allocs);
		return;
	}

	atomic_long_inc(&memorizer_num_tracked_allocs);

#if MEMORIZER_DEBUG >= 3
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
	write_lock_irqsave(&active_kobj_rbtree_spinlock, flags);
	unlocked_insert_kobj_rbtree(kobj, &active_kobj_rbtree_root);
	write_unlock_irqrestore(&active_kobj_rbtree_spinlock, flags);
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

	move_kobj_to_free_list((uintptr_t) call_site, (uintptr_t) ptr);
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
 * create_obj_kmem_cache() - create the kernel object kmem_cache
 */
void create_obj_kmem_cache(void)
{
	kobj_cache = KMEM_CACHE(memorizer_kobj,
				SLAB_PANIC
				//| SLAB_TRACE | SLAB_NOLEAKTRACE
			       );
}

/**
 * create_access_counts_kmem_cache() - create the kmem_cache for access_counts
 */
void create_access_counts_kmem_cache(void)
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

	init_mem_access_wls();
	create_obj_kmem_cache();
	create_access_counts_kmem_cache();
	local_irq_save(flags);
	memorizer_enabled = true;
	local_irq_restore(flags);
}

/*
 * Late initialization function.
 */
static int memorizer_late_init(void)
{
	unsigned long flags;
	//struct dentry *dentry;

	//dentry = debugfs_create_file("memorizer", S_IRUGO, NULL, NULL,
				     //&kmemleak_fops);
	//if (!dentry)
		//pr_warning("Failed to create the debugfs kmemleak file\n");

	local_irq_save(flags);
	memorizer_enabled = true;
	memorizer_log_access = true;
	local_irq_restore(flags);

	//__memorizer_print_events(10);

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
	unsigned long flags;

	pr_info("Running test from driver...");

	local_irq_save(flags);
	memorizer_enabled = true;
	memorizer_log_access = true;
	local_irq_restore(flags);

	read_lock_irqsave(&active_kobj_rbtree_spinlock, flags);
	pr_info("The live kernel object tree now:");
	__print_active_rb_tree(active_kobj_rbtree_root.rb_node);
	read_unlock_irqrestore(&active_kobj_rbtree_spinlock, flags);

	return 0;
}
EXPORT_SYMBOL(memorizer_init_from_driver);
