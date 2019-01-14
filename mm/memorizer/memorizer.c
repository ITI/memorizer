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
 *		- object_list_spinlock:
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
#include <linux/gfp.h>
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
#include <asm/page_64.h>
#include <linux/rbtree.h>
#include <linux/rwlock.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/smp.h>
#include <linux/workqueue.h>
#include <asm/atomic.h>
#include <asm/bitops.h>
#include <asm/percpu.h>
#include <linux/relay.h>
#include <asm-generic/bug.h>
#include <linux/cdev.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/bootmem.h>
#include <linux/kasan-checks.h>
#include <linux/mempool.h>

#include "kobj_metadata.h"
#include "event_structs.h"
#include "FunctionHashTable.h"
#include "memorizer.h"
#include "stats.h"
#include "util.h"
#include "memalloc.h"
#include "../slab.h"

//==-- Debugging and print information ------------------------------------==//
#define MEMORIZER_DEBUG		1
#define FIXME			0

#define INLINE_EVENT_PARSE  1
#define WORKQUEUES          0

//==-- Prototype Declarations ---------------------------------------------==//
static struct memorizer_kobj * unlocked_lookup_kobj_rbtree(uintptr_t kobj_ptr,
							   struct rb_root *
							   kobj_rbtree_root);
static void inline __memorizer_kmalloc(unsigned long call_site, const void *ptr,
				       uint64_t bytes_req, uint64_t bytes_alloc,
				       gfp_t gfp_flags, enum AllocType AT);
void __always_inline wq_push(uintptr_t addr, size_t size, enum AccessType
        access_type, uintptr_t ip, char * tsk_name);
static inline struct memorizer_kernel_event * wq_top(void);
void __drain_active_work_queue(void);
void switch_to_next_work_queue(void);
//==-- Data types and structs for building maps ---------------------------==//

/* Size of the memory access recording worklist arrays */
#define MEM_ACC_L_SIZE 1

/* Defining the maximum length for the event lists along with variables for character device driver */
// NB refers to the number of buffers being vmalloced
#define ML 500000
#define NB 16

#define BUFF_MUTEX_LOCK { \
		while(*buff_mutex)\
		yield(); \
		*buff_mutex = *buff_mutex + 1;\
	}

#define BUFF_MUTEX_UNLOCK {*buff_mutex = *buff_mutex - 1;}


#define BUFF_FILL_SET {*buff_fill = 1;}

static dev_t *dev[NB];
static struct cdev *cd[NB];
static void *pages1;
static void *pages2;
static char *buff_end;
static char *buff_start;
static char *buff_write_end;
static char *buff_fill;
static char *buff_mutex;
static unsigned int *buff_free_size;
static bool buff_init = false;
static unsigned int curBuff = 0;
static char *buffList[NB];

static dev_t *dev1;
static dev_t *dev2;
static struct cdev *cd1;
static struct cdev *cd2;

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
}cdList[NB];

struct memorizer_cdev {
	char idx;
	struct cdev charDev;
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

/*
 * switchBuffer - switches the the buffer being written to, when the buffer is full
 */
void __always_inline switchBuffer()
{
	buff_end = (char *)buffList[curBuff] + ML*4096-1;
	buff_write_end = (char *)buffList[curBuff];
	buff_fill = buff_write_end;
	buff_write_end = buff_write_end + 1;
	buff_mutex = buff_write_end;
	buff_write_end = buff_write_end + 1;
	buff_free_size = (unsigned int *)buff_write_end;
	buff_write_end = buff_write_end + sizeof(unsigned int);
	buff_start = buff_write_end;
}

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

//==-- PER CPU data structures and control flags --------------------------==//

/* TODO make this dynamically allocated based upon free memory */
//DEFINE_PER_CPU(struct mem_access_worklists, mem_access_wls = {.selector = 0, .head = 0, .tail = 0 });
DEFINE_PER_CPU(struct mem_access_worklists, mem_access_wls);

// memorizer atomic flag: when set it means we are operating in memorizer. The
// point of the flag is so that if we use code outside of memorizer or an
// interrupt occurs, it won't reenter and go down an infinite loop of
// recursion.
DEFINE_PER_CPU(int, recursive_depth = 0);

/*
 * Flags to keep track of whether or not to track writes
 *
 * Make this and the next open for early boot param manipulation via bootloader
 * kernel args: root=/hda1 memorizer_enabled=[yes|no]
 */
static bool memorizer_enabled = false;
static bool memorizer_enabled_boot = true;
static int __init early_memorizer_enabled(char *arg){
    if(!arg)
        return 0;
    if(strcmp(arg,"yes") == 0) {
        pr_info("Enabling boot alloc logging\n");
        memorizer_enabled_boot = true;
    }
    if(strcmp(arg,"no") == 0) {
        pr_info("Disable boot alloc logging\n");
        memorizer_enabled_boot = false;
    }
}
early_param("memorizer_enabled_boot", early_memorizer_enabled);

/* flag enable/disable memory access logging */
static bool memorizer_log_access = false;
static bool mem_log_boot = false;
static int __init early_mem_log_boot(char *arg){
    if(!arg)
        return 0;
    if(strcmp(arg,"yes") == 0) {
        pr_info("Enabling boot accessing logging\n");
        mem_log_boot= true;
    }
    if(strcmp(arg,"no") == 0) {
        pr_info("Disabling boot accessing logging\n");
        mem_log_boot= false;
    }
}
early_param("mem_log_boot", early_mem_log_boot);

/* flag enable/disable memory access logging */
static bool cfg_log_on = false;
static bool cfg_log_boot = false;
static int __init early_cfg_log_boot(char *arg){
    if(!arg)
        return 0;
    if(strcmp(arg,"yes") == 0) {
        pr_info("Enabling boot accessing logging\n");
        cfg_log_boot= true;
    }
    if(strcmp(arg,"no") == 0) {
        pr_info("Disabling boot accessing logging\n");
        cfg_log_boot= false;
    }
}
early_param("cfg_log_boot", early_cfg_log_boot);

/* flag enable/disable printing of live objects */
static bool print_live_obj = true;
static bool test_obj = false;

/* Function has table */
struct FunctionHashTable * cfgtbl;

/* Object Cache for Serialized KObjects to be printed out to the RelayFS */
//static struct kmem_cache *kobj_serial_cache = kmem_cache_create("Serial", sizeof(struct memorizer_kobj), 0, SLAB_PANIC,  NULL);

/* active kobj metadata rb tree */
static struct rb_root active_kobj_rbtree_root = RB_ROOT;

/* full list of freed kobjs */
static LIST_HEAD(object_list);

/* global object id reference counter */
static atomic_long_t global_kobj_id_count = ATOMIC_INIT(0);

/* General kobj for catchall object references */
static struct memorizer_kobj * general_kobjs[NumAllocTypes];

//==-- Locks --=//
/* RW Spinlock for access to rb tree */
DEFINE_RWLOCK(active_kobj_rbtree_spinlock);

/* RW Spinlock for access to freed kobject list */
DEFINE_RWLOCK(object_list_spinlock);

/* System wide Spinlock for the aggregating thread so nothing else interrupts */
DEFINE_RWLOCK(aggregator_spinlock);

//--- MEMBLOCK Allocator Tracking ---//
/* This is somewhat challenging because these blocks are allocated on physical
 * addresses. So we need to transition them.
 */
typedef struct {
	uintptr_t loc;
	uint64_t size;
} memblock_alloc_t;
memblock_alloc_t memblock_events[10000];
size_t memblock_events_top = 0;
bool in_memblocks(uintptr_t va_ptr)
{
	int i;
	uintptr_t pa = __pa(va_ptr);
	for(i=0;i<memblock_events_top;i++)
	{
		uintptr_t base = memblock_events[i].loc;
		uintptr_t end = memblock_events[i].loc + memblock_events[i].loc;
		if(pa > base && pa < end)
			return true;
	}
	return false;
}

//int test_and_set_bit(unsigned long nr, volatile unsigned long *addr);
volatile unsigned long inmem;

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
static inline int __memorizer_enter(void)
{
    return test_and_set_bit_lock(0,&inmem);
}

static __always_inline void __memorizer_exit(void)
{
    return clear_bit_unlock (0,&inmem);
}

/**
 * in_memorizer() - check if this thread has already entered memorizer
 */
static __always_inline bool in_memorizer(void)
{
    return test_bit(0,&inmem);
}

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
	//pr_info("\talloc_mod:	%s\n", *kobj->modsymb);
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
			//(void *) entry->ip, entry->pid,
			(void *) entry->ip, 0,
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

	read_lock_irqsave(&object_list_spinlock, flags);

	list_for_each(p, &object_list){
		unsigned int write_deg = 0, read_deg = 0;

		kobj = list_entry(p, struct memorizer_kobj, object_list);

		access_degree(&kobj->access_counts, &write_deg, &read_deg);

		pr_info("%s %d %s %u %u\n", kobj->funcstr, kobj->pid, kobj->comm,
			write_deg, read_deg);

	}
	read_unlock_irqrestore(&object_list_spinlock, flags);

	/* same for live objects */
	print_rb_tree_access_counts(active_kobj_rbtree_root.rb_node);
}

/**
 * __memorizer_print_events - print the last num events
 * @num_events:		The total number of events to print
 *
 * Simple print assuming an array log. Only tricky thing is to wrap around the
 * circular buffer when hitting the end or printing the last set of events if
 * some of them are at the end of the linear buffer. 
 */
/* TODO: LEGACY CODE SHOULD BE REMOVED */
void __memorizer_print_events(unsigned int num_events)
{
	int i, e, log_index;
	struct mem_access_worklists * ma_wls;
	struct memorizer_mem_access *mal, *ma; /* mal is the list ma is the
						  instance */
	__memorizer_enter();

	print_stats(KERN_INFO);

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


void memorizer_print_stats(void)
{
    print_stats(KERN_CRIT);
}
EXPORT_SYMBOL(memorizer_print_stats);


/**
 * dump_object_list() - print out the list of free'd objects
 */
static void dump_object_list(void)
{
	unsigned long flags;
	struct list_head *p;
	struct memorizer_kobj *kobj;
	read_lock_irqsave(&object_list_spinlock, flags);
	list_for_each(p, &object_list){
		kobj = list_entry(p, struct memorizer_kobj, object_list);
		read_locking_print_memorizer_kobj(kobj, "Dump Free'd kobj");
	}
	read_unlock_irqrestore(&object_list_spinlock, flags);
}

//----
//==-- Memorizer Access Processing ----------------------------------------==//
//----

static struct access_from_counts *
__alloc_afc(void)
{
	struct access_from_counts * afc = NULL;
	afc = (struct access_from_counts *)
		memalloc(sizeof(struct access_from_counts));
	return afc;
}

/**
 * init_access_counts_object() - initialize data for the object
 * @afc:	object to init
 * @ip:		ip of access
 */
static inline void
init_access_counts_object(struct access_from_counts *afc, uint64_t ip, pid_t
			  pid)
{
	INIT_LIST_HEAD(&(afc->list));
	afc->ip = ip;
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
        afc = __alloc_afc();
        init_access_counts_object(afc, ip, pid);
        track_access_counts_alloc();
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
 *
 * Here we insert a new entry for each (ip,threadid) tuple.
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
                if(src_ip == entry->ip){
                        return entry;
                } else if(src_ip < entry->ip){
                        break;
                }
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
 * @src_va_ptr: PC for source of operation
 * @va_ptr: the virtual address being written to
 * @pid: pid of access
 * @access_type: type of access (read/write)
 *
 * Find the object associated with this memory write, search for the src ip in
 * the access structures, incr if found or alloc and add new if not.
 *
 * Executes from the context of memorizer_mem_access and therefore we are
 * already operating with interrupts off and preemption disabled, and thus we
 * cannot sleep.
 */
static inline int find_and_update_kobj_access(uintptr_t src_va_ptr,
        uintptr_t va_ptr, pid_t pid, size_t access_type, size_t size)
{
        struct memorizer_kobj *kobj = NULL;
        struct access_from_counts *afc = NULL;

	if(in_pool(va_ptr))
	{
		track_access(MEM_MEMORIZER,size);
		return;
	}

        /* Get the kernel object associated with this VA */
        kobj = lt_get_kobj(va_ptr);

        if(!kobj){
                if(is_induced_obj(va_ptr))
                {
                        kobj = general_kobjs[MEM_INDUCED];
                        track_access(MEM_INDUCED,size);
                }
		else if(in_memblocks(va_ptr))
		{
			kobj = general_kobjs[MEM_MEMBLOCK];
			track_access(MEM_MEMBLOCK,size);
		}
                else{
                        enum AllocType AT = kasan_obj_type(va_ptr,size);
                        kobj = general_kobjs[AT];
                        if(AT == MEM_STACK_PAGE)
                                track_access(AT,size);
                        else
                                track_untracked_access(AT,size);
                }
        }
        else
        {
                /* track access by type of object accessed */
                track_access(kobj->alloc_type,size);
        }

        /* Grab the object lock here */
        write_lock(&kobj->rwlock);

        /* Search access queue to the entry associated with src_ip */
        afc = unlckd_insert_get_access_counts(src_va_ptr, pid, kobj);

        /* increment the counter associated with the access type */
        if(afc)
                access_type ? ++(afc->writes) : ++(afc->reads);

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
/*
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
*/
//==-- Memorizer memory access tracking -----------------------------------==//

/**
 * set_comm_and_pid - Find the execution context of the ld/st
 *
 * Set the pid and the task name. These are together because we want to optimize
 * the number of branches in this to make it faster.
 */
static inline void set_comm_and_pid(struct memorizer_mem_access *ma)
{
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
	int i;
	for(i=0; i<sizeof(comm); i++)
		ma->comm[i] = comm[i];
	ma->comm[i] = '\0';
#endif
}

/**
 * memorizer_call() - trace function call
 *
 * @from: the PC virtual address of the call site
 * @to: the PC virtual address of the called function entry point
 *
 */
void __always_inline
memorizer_call(uintptr_t to, uintptr_t from)
{
        unsigned long flags;
        if(!cfg_log_on)
                return;
        //if(current->kasan_depth > 0)
        //        return;
        if(__memorizer_enter())
                return;
        local_irq_save(flags);
#if INLINE_EVENT_PARSE 
        cfg_update_counts(cfgtbl, from, to);
#else
        //trace_printk("%p->%p,%d,%d\n",ip,addr,size,write);
        //wq_push(addr, size, write, ip, 0);
#endif
        local_irq_restore(flags);
        __memorizer_exit();
}
EXPORT_SYMBOL(memorizer_call);

/**
 * memorizer_mem_access() - record associated data with the load or store
 * @addr:	The virtual address being accessed
 * @size:	The number of bits for the load/store
 * @write:	True if the memory access is a write (store)
 * @ip:		IP of the invocing instruction
 *
 * Memorize, ie. log, the particular data access.
 */
void __always_inline memorizer_mem_access(uintptr_t addr, size_t size, bool
					  write, uintptr_t ip)
{
        unsigned long flags;
        if(unlikely(!memorizer_log_access) || unlikely(!memorizer_enabled))
        {
                track_disabled_access();
                return;
        }

        if(current->kasan_depth > 0)
        {
                track_induced_access();
                return;
        }

        if(__memorizer_enter())
        {
                track_induced_access();
                return;
        }


#if INLINE_EVENT_PARSE 
        local_irq_save(flags);
        find_and_update_kobj_access(ip,addr,-1,write,size);
        local_irq_restore(flags);
#else
        //trace_printk("%p->%p,%d,%d\n",ip,addr,size,write);
        //wq_push(addr, size, write, ip, 0);
#endif

        __memorizer_exit();

#if 0
        if(buff_init)
        {
                while(*buff_fill)
                {
                        curBuff = (curBuff + 1)%NB;
                        pr_info("Trying Buffer %u\n",curBuff);
                        switchBuffer();
                }

                local_irq_save(flags);

                if(write)
                        mke.event_type = Memorizer_Mem_Write;
                else
                        mke.event_type = Memorizer_Mem_Read;

                mke.pid = task_pid_nr(current);
                mke.event_size = size;
                mke.event_ip = ip;
                mke.src_va_ptr = addr;
                mke.event_jiffies = jiffies;

                mke_ptr = (struct memorizer_kernel_access *)buff_write_end;
                *mke_ptr = mke;
                buff_write_end = buff_write_end + sizeof(struct memorizer_kernel_access);
                *buff_free_size = *buff_free_size - sizeof(struct memorizer_kernel_access);

                /* Check after writing the event to the buffer if there is any more
                 * space for the next entry to go in - Need to choose the struct with
                 * the biggest size for this otherwise it may lead to a problem wherein
                 * the write pointer still points to the end of the buffer and there is
                 * another event ready to be written which might be bigger than the
                 * size of the struct that could have reset the pointer 
                 */
                if(*buff_free_size < sizeof(struct memorizer_kernel_event))
                {

                        pr_info("Current Buffer Full, Setting the fill bit\n");
                        *buff_fill = 1;
                        buff_write_end = buff_start;
                }
                local_irq_restore(flags);
                //*buff_end = (unsigned long long)0xbb;
        }
        //}
#endif
}

void __always_inline memorizer_fork(struct task_struct *p, long nr){
	
	unsigned long flags;

    return;
	if(unlikely(!memorizer_enabled))
		return;
	if(__memorizer_enter())
        return;

    
#if 0
    struct memorizer_kernel_event * evtptr = wq_top();
    evtptr->event_type = Memorizer_Fork;

    local_irq_save(flags);
    if (in_irq()) {
        evtptr->pid = 0;
        strncpy(evtptr->data.comm, "hardirq", sizeof(evtptr->data.comm));
    } else if (in_softirq()) {
        evtptr->pid = 0;
        strncpy(evtptr->data.comm, "softirq", sizeof(evtptr->data.comm));
    } else {
        evtptr->pid = task_pid_nr(p);
        /*
         * There is a small chance of a race with set_task_comm(),
         * however using get_task_comm() here may cause locking
         * dependency issues with current->alloc_lock. In the worst
         *	 case, the command line is not correct.
         */
        strncpy(evtptr->data.comm, p->comm, sizeof(evtptr->data.comm));
    }
    //wq_push(0,0,Memorizer_Fork,0,p->comm);
    //trace_printk("%p->%s,%d,%c\n",p,p->comm,0,Memorizer_Mem_Free);
    trace_printk("fork:%s,PID:%d\n",p->comm,nr);

    local_irq_restore(flags);
#endif 
    /* check to see if stack is allocated */
    //if(lt_get_kobj(p->stack))
    {
        //pr_crit("Forked: Is stack in live objs? TRUE\n");
    }
    //else
    {
        //pr_crit("Forked: Is stack in live objs? FALSE\n");
    }

	__memorizer_exit();

#if 0
	if(buff_init)
	{
		while(*buff_fill)
		{
			curBuff = (curBuff + 1)%NB;
			switchBuffer();
		}
		
		local_irq_save(flags);
		mke.event_type = Memorizer_Fork;
		if (in_irq()) {
			mke.pid = 0;
			strncpy(mke.comm, "hardirq", sizeof(mke.comm));
		} else if (in_softirq()) {
			mke.pid = 0;
			strncpy(mke.comm, "softirq", sizeof(mke.comm));
		} else {
			mke.pid = nr;
		/*
		 * There is a small chance of a race with set_task_comm(),
		 * however using get_task_comm() here may cause locking
		 * dependency issues with current->alloc_lock. In the worst
		 *	 case, the command line is not correct.
		 */
		strncpy(mke.comm, p->comm, sizeof(mke.comm));
		}
	
		mke_ptr = (struct memorizer_kernel_fork *)buff_write_end;
		*mke_ptr = mke;
		buff_write_end = buff_write_end +sizeof(struct memorizer_kernel_fork);	
		*buff_free_size = *buff_free_size - sizeof(struct memorizer_kernel_fork);
		
		
		if(*buff_free_size < sizeof(struct memorizer_kernel_event))
		{

			*buff_fill = 1;
			buff_write_end = buff_start;
		}



		local_irq_restore(flags);
	}

#endif
}

//==-- Memorizer kernel object tracking -----------------------------------==//

/**
 * init_kobj() - Initalize the metadata to track the recent allocation
 */
static void init_kobj(struct memorizer_kobj * kobj, uintptr_t call_site,
		      uintptr_t ptr_to_kobj, size_t bytes_alloc, enum AllocType AT)
{
	rwlock_init(&kobj->rwlock);

	if(atomic_long_inc_and_test(&global_kobj_id_count)){
		pr_warn("Global kernel object counter overlapped...");
	}

	/* Zero out the whole object including the comm */
	memset(kobj, 0, sizeof(struct memorizer_kobj));
	kobj->alloc_ip = call_site;
	kobj->va_ptr = ptr_to_kobj;
	kobj->pa_ptr = __pa(ptr_to_kobj);
	kobj->size = bytes_alloc;
	kobj->alloc_jiffies = get_ts();
	kobj->free_jiffies = 0;
	kobj->free_ip = 0;
	kobj->obj_id = atomic_long_read(&global_kobj_id_count);
	kobj->printed = false;
	kobj->alloc_type = AT;
	INIT_LIST_HEAD(&kobj->access_counts);
	INIT_LIST_HEAD(&kobj->object_list);
	/* Some of the call sites are not tracked correctly so don't try */
	if(call_site)
		kallsyms_lookup((unsigned long) call_site, NULL, NULL,
				//&(kobj->modsymb), kobj->funcstr);
				NULL, kobj->funcstr);
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
 * free_access_from_entry() --- free the entry from the kmem_cache
 */
static void free_access_from_entry(struct access_from_counts *afc)
{
	//TODO clean up all the kmem_cache_free stuff
	//kmem_cache_free(access_from_counts_cache, afc);
	//TODO Create Free function here with new memalloc allocator
}

/**
 * free_access_from_list() --- for each element remove from list and free
 */
static void free_access_from_list(struct list_head *afc_lh)
{
	struct access_from_counts *afc;
	struct list_head *p;
	struct list_head *tmp;
	list_for_each_safe(p, tmp, afc_lh)
	{
		afc = list_entry(p, struct access_from_counts, list);
		list_del(&afc->list);
		free_access_from_entry(afc);
	}
}

/**
 * free_kobj() --- free the kobj from the kmem_cache
 * @kobj:	The memorizer kernel object metadata
 *
 * FIXME: there might be a small race here between the write unlock and the
 * kmem_cache_free. If another thread is trying to read the kobj and is waiting
 * for the lock, then it could get it. I suppose the whole *free_kobj operation
 * needs to be atomic, which might be proivded by locking the list in general.
 */
static void free_kobj(struct memorizer_kobj * kobj)
{
	write_lock(&kobj->rwlock);
	free_access_from_list(&kobj->access_counts);
	write_unlock(&kobj->rwlock);
	//kmem_cache_free(kobj_cache, kobj);
	//TODO add new free function here from memalloc allocator
        track_kobj_free();
}


/**
 * clear_free_list() --- remove entries from free list and free kobjs
 */
static void clear_dead_objs(void)
{
	struct memorizer_kobj *kobj;
	struct list_head *p;
	struct list_head *tmp;
	unsigned long flags;
	pr_info("Clearing the free'd kernel objects\n");
        /* Avoid rentrance while freeing the list */
        while(!__memorizer_enter())
               yield();
	write_lock_irqsave(&object_list_spinlock, flags);
	list_for_each_safe(p, tmp, &object_list)
	{
		kobj = list_entry(p, struct memorizer_kobj, object_list);
		/* If free_jiffies is 0 then this object is live */
		if(kobj->free_jiffies > 0) {
			/* remove the kobj from the free-list */
			list_del(&kobj->object_list);
			/* Free the object data */
			free_kobj(kobj);
		}
	}
	write_unlock_irqrestore(&object_list_spinlock, flags);
	__memorizer_exit();
}

/**
 * clear_printed_objects() --- remove entries from free list and free kobjs
 */
static void clear_printed_objects(void)
{
	struct memorizer_kobj *kobj;
	struct list_head *p;
	struct list_head *tmp;
	unsigned long flags;
	pr_info("Clearing the free'd and printed kernel objects\n");
	__memorizer_enter();
	write_lock_irqsave(&object_list_spinlock, flags);
	list_for_each_safe(p, tmp, &object_list)
	{
		kobj = list_entry(p, struct memorizer_kobj, object_list);
		/* If free_jiffies is 0 then this object is live */
		if(kobj->free_jiffies > 0 && kobj->printed) {
			/* remove the kobj from the free-list */
			list_del(&kobj->object_list);
			/* Free the object data */
			free_kobj(kobj);
		}
	}
	write_unlock_irqrestore(&object_list_spinlock, flags);
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
			//kmem_cache_free(kobj_cache, kobj);
			//TODO add free here
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
 * __memorizer_free_kobj - move the specified objec to free list
 *
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
 * 0xvv
 */
void static __memorizer_free_kobj(uintptr_t call_site, uintptr_t kobj_ptr)
{

        struct memorizer_kobj *kobj;
        unsigned long flags;

        /* find and remove the kobj from the lookup table and return the
         * kobj */
        kobj = lt_remove_kobj(kobj_ptr);

        /*
         *   * If this is null it means we are freeing something we did
         *   not insert
         *       * into our tree and we have a missed alloc track,
         *       otherwise we update
         *           * some of the metadata for free.
         *               */
        if(kobj){
                /* Update the free_jiffies for the object */
                write_lock_irqsave(&kobj->rwlock, flags);
                kobj->free_jiffies = get_ts();
                kobj->free_ip = call_site;
                write_unlock_irqrestore(&kobj->rwlock, flags);
                track_free();
		//TODO add free function here
        }
        else
                track_untracked_obj_free();
}

/**
 * memorizer_free_kobj - move the specified objec to free list
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
 * 0xvv
 */
void static memorizer_free_kobj(uintptr_t call_site, uintptr_t kobj_ptr)
{

        struct memorizer_kobj *kobj;
        unsigned long flags;

        if(__memorizer_enter())
        {
                track_induced_free();
                return;
        }

        local_irq_save(flags);
        //wq_push(kobj_ptr, 0, Memorizer_Mem_Free, call_site, 0);
        //trace_printk("%p->%p,%d,%d\n",call_site,kobj_ptr,0,Memorizer_Mem_Free);
        __memorizer_free_kobj(call_site, kobj_ptr);

        local_irq_restore(flags);
        __memorizer_exit();

#if 0
        if(buff_init)
	{

		while(*buff_fill)
		{
			curBuff = (curBuff + 1)%NB;
			switchBuffer();
		}



		local_irq_save(flags);
		// Set up the event Struct and Dump it to the Buffer
		mke.event_type = Memorizer_Mem_Free;
		mke.pid = task_pid_nr(current);
		mke.src_va_ptr = call_site;
		mke.event_ip = kobj_ptr;
		mke.event_jiffies = jiffies;

		mke_ptr = (struct memorizer_kernel_free *)buff_write_end;
		*mke_ptr = mke;
		buff_write_end = buff_write_end + sizeof(struct memorizer_kernel_free);
		*buff_free_size = *buff_free_size - sizeof(struct memorizer_kernel_free);

		if(*buff_free_size < sizeof(struct memorizer_kernel_event))
		{
			*buff_fill = 1;
			buff_write_end = buff_start;
		}


		local_irq_restore(flags);
	}
//	}
#endif
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
static void inline __memorizer_kmalloc(unsigned long call_site, const void
        *ptr, uint64_t bytes_req, uint64_t bytes_alloc, gfp_t gfp_flags, enum AllocType AT)
{

        unsigned long flags;
        struct memorizer_kobj *kobj;

        if(unlikely(ptr==NULL))
                return;

        if(unlikely(!memorizer_enabled)) {
                track_disabled_alloc();
                return;
        }

        if(__memorizer_enter())
        {
                /* link in lookup table with dummy event */
                local_irq_save(flags);
                lt_insert_induced((uintptr_t)ptr,bytes_alloc);
                track_induced_alloc();
                local_irq_restore(flags);
                return;
        }

#if 0
        pid_t pid;
        if (in_irq()) {
                pid = 0;
        } else if (in_softirq()) {
                pid = 0;
        } else {
                pid = current->pid;
        }

        /* workqueue style */
        wq_push(ptr, bytes_alloc, Memorizer_Mem_Alloc, call_site, current->comm);

        /* ftrace event queue style */
        trace_printk("%p->%p,%d,%d\n",call_site,ptr,bytes_alloc,Memorizer_Mem_Alloc);
#endif 

        local_irq_save(flags);

        /* inline parsing */
        kobj = memalloc(sizeof(struct memorizer_kobj));
        if(!kobj){
		//pr_crit("Cannot allocate a memorizer_kobj structure\n");
		track_failed_kobj_alloc();
		goto out;
	}

        /* initialize all object metadata */
        init_kobj(kobj, (uintptr_t) call_site, (uintptr_t) ptr, bytes_alloc, AT);

        /* memorizer stats tracking */
        track_alloc(AT);

        /* mark object as live and link in lookup table */
        lt_insert_kobj(kobj);

        /* Grab the writer lock for the object_list and insert into object list */
        write_lock(&object_list_spinlock);
        list_add_tail(&kobj->object_list, &object_list);
        write_unlock(&object_list_spinlock);

out:
        local_irq_restore(flags);
        __memorizer_exit();

#if 0
        if(buff_init)
        {

                while(*buff_fill)
                {
                        curBuff = (curBuff + 1)%NB;
                        switchBuffer();
                }

                local_irq_save(flags);
                mke.event_type = Memorizer_Mem_Alloc;
                mke.event_ip = call_site;
                mke.src_va_ptr = (uintptr_t)ptr;
                mke.src_pa_ptr = __pa((uintptr_t)ptr);
                mke.event_size = bytes_alloc;
                mke.event_jiffies = jiffies;
                /* Some of the call sites are not tracked correctly so don't try */
                if(call_site)
                        kallsyms_lookup((unsigned long) call_site, NULL, NULL,
                                        //&(kobj->modsymb), kobj->funcstr);
                                NULL, mke.funcstr);
                /* task information */
                if (in_irq()) {
                        mke.pid = 0;
                        strncpy(mke.comm, "hardirq", sizeof(mke.comm));
                } else if (in_softirq()) {
                        mke.pid = 0;
                        strncpy(mke.comm, "softirq", sizeof(mke.comm));
                } else {
                        mke.pid = current->pid;
                        /*
                         * There is a small chance of a race with set_task_comm(),
                         * however using get_task_comm() here may cause locking
                         * dependency issues with current->alloc_lock. In the worst
                         *	 case, the command line is not correct.
                         */
                        strncpy(mke.comm, current->comm, sizeof(mke.comm));
                }

                mke_ptr = (struct memorizer_kernel_alloc *)buff_write_end;
                *mke_ptr = mke;
                buff_write_end = buff_write_end + sizeof(struct memorizer_kernel_alloc);
                *buff_free_size = *buff_free_size - sizeof(struct memorizer_kernel_alloc);

                if(*buff_free_size < sizeof(struct memorizer_kernel_event))
                {
                        *buff_fill = 1;
                        buff_write_end = buff_start;
                }
                local_irq_restore(flags);
        }
        else
        {
                track_disabled_alloc();
        }

#endif

        //*buff_end = (unsigned long long)0xaa;
}

/*** HOOKS similar to the kmem points ***/
void memorizer_kmalloc(unsigned long call_site, const void *ptr, size_t
		      bytes_req, size_t bytes_alloc, gfp_t gfp_flags)
{
    __memorizer_kmalloc(call_site, ptr, bytes_req, bytes_alloc, gfp_flags,
            MEM_KMALLOC);
}

void memorizer_kmalloc_node(unsigned long call_site, const void *ptr, size_t
			   bytes_req, size_t bytes_alloc, gfp_t gfp_flags, int
			   node)
{
    __memorizer_kmalloc(call_site, ptr, bytes_req, bytes_alloc, gfp_flags,
            MEM_KMALLOC_ND);
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

	memorizer_free_kobj((uintptr_t) call_site, (uintptr_t) ptr);
}

void __init memorizer_memblock_alloc(phys_addr_t base, phys_addr_t size)
{
	track_alloc(MEM_MEMBLOCK);
	memblock_alloc_t * evt = &memblock_events[memblock_events_top++];
	evt->loc = base;
	evt->size = size;
}

void __init memorizer_memblock_free(phys_addr_t base, phys_addr_t size)
{
}

void memorizer_alloc_bootmem(unsigned long call_site, void * v, uint64_t size)
{
        //track_alloc(MEM_BOOTMEM);
	__memorizer_kmalloc(call_site, v, size, size, 0, MEM_BOOTMEM);
	return;
}

const char * l1str = "lt_l1_tbl";
const char * l2str = "lt_l2_tbl";
const char * memorizer_kobjstr = "memorizer_kobj";
const char * access_from_countsstr = "access_from_counts";
bool is_memorizer_cache_alloc(char * cache_str)
{
        if(!memstrcmp(l1str,cache_str))
                return true;
        if(!memstrcmp(l2str,cache_str))
                return true;
        if(!memstrcmp(memorizer_kobjstr,cache_str))
                return true;
        if(!memstrcmp(access_from_countsstr,cache_str))
                return true;
        return false;
}

void memorizer_kmem_cache_alloc(unsigned long call_site, const void *ptr,
                struct kmem_cache *s, gfp_t gfp_flags)
{
        if (unlikely(ptr == NULL))
                return;
        if(!is_memorizer_cache_alloc(s->name))
                __memorizer_kmalloc(call_site, ptr, s->object_size, s->size,
                                gfp_flags, MEM_KMEM_CACHE);
}

void memorizer_kmem_cache_alloc_node (unsigned long call_site, const void *ptr,
        struct kmem_cache *s, gfp_t gfp_flags, int node)
{
        if (unlikely(ptr == NULL))
                return;
        if(!is_memorizer_cache_alloc(s->name))
                __memorizer_kmalloc(call_site, ptr, s->object_size, s->size,
                                gfp_flags, MEM_KMEM_CACHE_ND);
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
	memorizer_free_kobj((uintptr_t) call_site, (uintptr_t) ptr);
}


void memorizer_alloc_pages(unsigned long call_site, struct page *page, unsigned
			   int order, gfp_t gfp_flags)
{
    __memorizer_kmalloc(call_site, page_address(page),
            (uintptr_t) PAGE_SIZE * (2 << order),
            (uintptr_t) PAGE_SIZE * (2 << order),
            gfp_flags, MEM_ALLOC_PAGES);
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
	memorizer_free_kobj((uintptr_t) call_site, (uintptr_t)
			       page_address(page));
}

/**
 *
 * Thread should have allocated and this stack should be in the table
 */
void memorizer_stack_page_alloc(struct task_struct *task)
{
        /* get the object */
        struct memorizer_kobj * stack_kobj = lt_get_kobj(task->stack);
        /* if there then just mark it, but it appears to be filtered out */
        if(!stack_kobj)
        {
                void *base = task_stack_page(task);
                __memorizer_kmalloc(_RET_IP_, base, THREAD_SIZE, THREAD_SIZE,
                                0, MEM_STACK_PAGE);
        }
        else
        {
                /* change alloc type to stack page alloc */
                stack_kobj->alloc_type = MEM_STACK_PAGE;
        }
}

void memorizer_stack_alloc(unsigned long call_site, const void *ptr, size_t
                size)
{
        __memorizer_kmalloc(call_site, ptr, size, size, 0, MEM_STACK);
}

void memorizer_register_global(const void *ptr, size_t size)
{
	__memorizer_kmalloc(0, ptr, size, size, 0, MEM_GLOBAL);
}

//==-- Memorizer Data Export ----------------------------------------------==//
static unsigned long seq_flags;
static bool sequence_done = false;
extern struct list_head *seq_list_start(struct list_head *head, loff_t pos);
extern struct list_head *seq_list_next(void *v, struct list_head *head, loff_t
				       *ppos);

/*
 * kmap_seq_start() --- get the head of the free'd kobj list
 *
 * Grab the lock here and give back on close. There is an interesting problem
 * here in that when the data gets to the page size limit for printing, the
 * sequence file closes the file and opens up again by coming to the start
 * location having processed a subset of the list already. The problem with this
 * is that without having __memorizer_enter() it will add objects to the list
 * between the calls to show and next opening the potential for an infinite
 * loop. It also adds elements in between start and stop operations.
 *
 * For some reason the start is called every time after a *stop*, which allows
 * more entries to be added to the list thus requiring the extra sequence_done
 * flag that I added to detect the end of the list. So we add this flag so that
 * any entries added after won't make the sequence continue forever in an
 * infinite loop.
 */
static void *kmap_seq_start(struct seq_file *seq, loff_t *pos)
{
	__memorizer_enter();
	write_lock_irqsave(&object_list_spinlock, seq_flags);

	if(list_empty(&object_list))
		return NULL;

	if(*pos == 0){
		sequence_done = false;
		return object_list.next;
	}

	/* 
	 * Second call back even after return NULL to stop. This must occur
	 * after the check to (*pos == 0) otherwise it won't continue after the
	 * first time a read is executed in userspace. The specs didn't mention
	 * this but my experiments showed its occurrence. 
	 */
	if(sequence_done == true)
		return NULL;

	return seq_list_start(&object_list, *pos);
}

/*
 * kmap_seq_next() --- move the head pointer in the list or return null
 */
static void *kmap_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return seq_list_next(v, &object_list, pos);
}

/*
 * kmap_seq_show() - print out the object including access info
 */
static int kmap_seq_show(struct seq_file *seq, void *v)
{
	struct access_from_counts *afc;
	struct memorizer_kobj *kobj = list_entry(v, struct memorizer_kobj,
						 object_list);
	read_lock(&kobj->rwlock);
	/* If free_jiffies is 0 then this object is live */
	if(!print_live_obj && kobj->free_jiffies == 0) {
		read_unlock(&kobj->rwlock);
		return 0;
	}
	kobj->printed = true;
	/* Print object allocation info */
	seq_printf(seq,"%-p,%d,%p,%lu,%lu,%lu,%p,%s,%s\n",
		   (void*) kobj->alloc_ip, kobj->pid, (void*) kobj->va_ptr,
		   kobj->size, kobj->alloc_jiffies, kobj->free_jiffies, (void*)
		   kobj->free_ip, alloc_type_str(kobj->alloc_type), kobj->comm);

	/* print each access IP with counts and remove from list */
	list_for_each_entry(afc, &kobj->access_counts, list)
	{
		seq_printf(seq, "  %p,%llu,%llu\n",
			   (void *) afc->ip, 
			   (unsigned long long) afc->writes,
			   (unsigned long long) afc->reads);
	}

	read_unlock(&kobj->rwlock);
	return 0;
}

/*
 * kmap_seq_stop() --- clean up on sequence file stopping
 *
 * Must release locks and ensure that we can re-enter. Also must set the
 * sequence_done flag to avoid an infinit loop, which is required so that we
 * guarantee completions without reentering due to extra allocations between
 * this invocation of stop and the start that happens.
 */
static void kmap_seq_stop(struct seq_file *seq, void *v)
{
	if(!v)
		sequence_done = true;
	write_unlock_irqrestore(&object_list_spinlock, seq_flags);
	__memorizer_exit();
}

static const struct seq_operations kmap_seq_ops = {
	.start = kmap_seq_start,
	.next  = kmap_seq_next,
	.stop  = kmap_seq_stop,
	.show  = kmap_seq_show,
};

static int kmap_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &kmap_seq_ops);
}

static ssize_t kmap_write(struct file *file, const char __user *user_buf,
			       size_t size, loff_t *ppos)
{
#if 0
	char buf[64];
	int buf_size;
	int ret;

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

static const struct file_operations kmap_fops = {
	.owner		= THIS_MODULE,
	.open		= kmap_open,
	.write		= kmap_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/* 
 * clear_free_list_write() - call the function to clear the free'd kobjs
 */
static ssize_t clear_dead_objs_write(struct file *file, const char __user
				   *user_buf, size_t size, loff_t *ppos)
{
	clear_dead_objs();
	*ppos += size;
	return size;
}

static const struct file_operations clear_dead_objs_fops = {
	.owner		= THIS_MODULE,
	.write		= clear_dead_objs_write,
};

/* 
 * clear_free_list_write() - call the function to clear the free'd kobjs
 */
static ssize_t drain_active_work_queue_write(struct file *file, const char __user
				   *user_buf, size_t size, loff_t *ppos)
{
	__drain_active_work_queue();
	*ppos += size;
	return size;
}

static const struct file_operations drain_active_work_queue_fops = {
	.owner		= THIS_MODULE,
	.write		= drain_active_work_queue_write,
};

/* 
 * clear_printed_free_list_write() - call the function to clear the printed free'd kobjs
 */
static ssize_t clear_printed_list_write(struct file *file, const char __user
				   *user_buf, size_t size, loff_t *ppos)
{
	clear_printed_objects();
	*ppos += size;
	return size;
}

static const struct file_operations clear_printed_list_fops = {
	.owner		= THIS_MODULE,
	.write		= clear_printed_list_write,
};

static ssize_t cfgmap_write(struct file *file, const char __user
				   *user_buf, size_t size, loff_t *ppos)
{
    unsigned long flags;
	__memorizer_enter();
    local_irq_save(flags);
    cfgmap_clear(cfgtbl);
    local_irq_restore(flags);
	__memorizer_exit();
	*ppos += size;
	return size;
}

//static ssize_t cfgmap_read(struct file *file, const char __user *user_buf,
        //size_t size, loff_t *ppos)
static ssize_t cfgmap_read(struct file *fp, char __user *user_buffer, size_t
        size, loff_t *ppos)
{
    console_print(cfgtbl);
	*ppos += size;
	return size;
}

static int cfgmap_seq_show(struct seq_file *seq, void *v)
{
    struct EdgeBucket * b;    
    int index;
    for (index = 0; index < cfgtbl -> number_buckets; index++){
        b = cfgtbl -> buckets[index];
        while (b != NULL){
            seq_printf(seq,"%lx %lx %ld\n", b -> from, b -> to, b -> count);
            b = b -> next;
        }
    }  
}

static int cfgmap_open(struct inode *inode, struct file *file)
{
	return single_open(file, &cfgmap_seq_show, NULL);
}

static const struct file_operations cfgmap_fops = {
	.owner		= THIS_MODULE,
	.write		= cfgmap_write,
	.open		= cfgmap_open,
	.read		= seq_read,
};

static int stats_seq_show(struct seq_file *seq, void *v)
{
    return seq_print_stats(seq);
}

static int show_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, &stats_seq_show, NULL);
}

static const struct file_operations show_stats_fops = {
	.owner		= THIS_MODULE,
	.open		= show_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

//==-- Memorizer Initializtion --------------------------------------------==//

static int create_buffers(void)
{
	int i;
	unsigned int *temp_size;
	for(i=0;i<NB;i++)
	{
		buffList[i] = (char *)vmalloc(ML*4096);
		if(!buffList[i])
			return 0;

		memset(buffList[i],0,ML*4096);
		temp_size = (unsigned int *)(buffList[i]+2);
		*temp_size = ML*4096 - 6;

	}
	return 1;
}

/* 2^32 = 4.29 GB */
/* number of entries at 2^5 / entry 2^25 ~~ 1 GB */
//const size_t num_entries_perwq = 2^22;
//#define num_entries_perwq (_AC(1,UL) << 26)
#if INLINE_EVENT_PARSE == 0
#define num_entries_perwq (_AC(1,UL) << 22)
#else
#define num_entries_perwq (_AC(1,UL) << 0)
#endif

struct event_list_wq_data {
    struct work_struct work;
    struct memorizer_kernel_event data[num_entries_perwq];
};

#define num_queues 2
size_t wq_index = 0;
size_t wq_selector = 0;
size_t wq_process_me = 0;
struct event_list_wq_data mem_events_wq_data[num_queues];

/*
 * parse_events() - take the event list @data and parse to object cmap
 *
 * Note this function makes no assumptions about the calling context. This
 * function is not an external entry point, and therefore expects it's caller
 * to manage "in_memorizer" as well as any other global memorizer based locking
 * required.
 */
static void
parse_events(struct event_list_wq_data * data)
{
    unsigned long i, flags;
    bool old_access, old_enabled;

    // Saving the old config before disabling the memorizer for aggregation
    old_enabled = memorizer_enabled;
    old_access = memorizer_log_access;

    // Disabling the memorizer for aggregation
    memorizer_enabled = false;
    memorizer_log_access = false;

    //spin_lock_irqsave(&aggregator_spinlock,flags);
    gfp_t gfp_flags = GFP_ATOMIC;
    struct memorizer_kobj *kobj;
    struct memorizer_kernel_event *mke;

    pr_info("processing workqueue %d\n", wq_selector);

    /* Process the event queue */
    for(i = 0; i<num_entries_perwq; i++)
    {
        mke = &data->data[i];
#ifdef DEBUG > 5
        if(i % (int)(num_entries_perwq*.5) == 0)
            pr_cont("\rQueue Processing: %d/%d", i,num_entries_perwq);
#endif

        switch(mke->event_type)
        {
        case Memorizer_READ: find_and_update_kobj_access((uintptr_t) mke->data.et.src_va_ptr,
					     (uintptr_t) mke->data.et.va_ptr,(pid_t)mke->pid, 
					     (size_t) mke->event_type, mke->data.et.event_size);
			     			break;
        case Memorizer_WRITE:find_and_update_kobj_access((uintptr_t) mke->data.et.src_va_ptr,
					     (uintptr_t) mke->data.et.va_ptr,(pid_t)mke->pid, 
					     (size_t) mke->event_type,mke->data.et.event_size);
			     			break;
        case Memorizer_Mem_Alloc:
		kobj = memalloc(sizeof(struct memorizer_kobj));
            if(!kobj){ 
                pr_err("Cannot allocate a memorizer_kobj structure\n"); 
            }
            init_kobj(kobj, (uintptr_t) mke->data.et.src_va_ptr,
                    (uintptr_t) mke->data.et.va_ptr, mke->data.et.event_size, 
                    MEM_NONE); 
            /* Grab the writer lock for the object_list */
            // We are single threaded here don't need to lock
            //write_lock_irqsave(&object_list_spinlock, flags);
            lt_insert_kobj(kobj);
            list_add_tail(&kobj->object_list, &object_list);
            //write_unlock_irqrestore(&object_list_spinlock, flags);
            break;
        case Memorizer_Mem_Free:
            __memorizer_free_kobj((uintptr_t) mke->data.et.src_va_ptr,
                    (uintptr_t) mke->data.et.va_ptr);
            break;
        case Memorizer_Fork:
	    // Add in the code to Handle Forks
	    // Push the data as a struct into the pid_table
	    
            break;
        case Memorizer_NULL:
            break;
        //default:
                //pr_info("Handling default case for event dequeue");
        }
        mke->event_type = Memorizer_NULL;
    }
    //spin_lock_irqrestore(&aggregator_spinlock, flags);

    //pr_info("Finished aggregating event queue.\n");

    // Restoring the old configuration after aggregation
    memorizer_enabled = old_enabled;
    memorizer_log_access = old_access;
    
    // set first entry to Memorizer_NULL for queue selection check */
    //data->data[0].event_type = Memorizer_NULL;
}

struct workqueue_struct *wq;

static void
mem_events_workhandler(struct work_struct *work)
{
    unsigned long flags;
	__memorizer_enter();
    local_irq_save(flags);
    parse_events(container_of(work,struct event_list_wq_data, work));
    local_irq_restore(flags);
	__memorizer_exit();
}

/*
 * Switch the active work queue to the next one and queue the work up.
 */
bool work_deferred = false;
size_t next_to_parse = 0;
void 
switch_to_next_work_queue(void)
{
    size_t full = wq_selector;
    wq_selector = (++wq_selector) % num_queues;
    pr_info("Queueing work and switching to buffer %u\n", wq_selector);

#if WORKQUEUES == 1
    queue_work(wq, &(mem_events_wq_data[full].work));
#else // DEFER with check on irq contexts
    unsigned long flags;
	if (unlikely(in_irq()) || unlikely(in_softirq())) {
        work_deferred = true;
        next_to_parse = full;
    } else {
        local_irq_save(flags);
        parse_events(&mem_events_wq_data[full]);
        local_irq_restore(flags);
    }
#endif
    
    /* check to see if the new queue is empty */
    if(mem_events_wq_data[wq_selector].data[0].event_type !=
            Memorizer_NULL) 
    {
        panic("memorizer: tried to switch to non-empty queue\n");
    }

    /* reset current top to 0 */
    wq_index = 0;
}
    
/* 
 * wq_top() - return the next open slot in the active wq
 */
static inline struct memorizer_kernel_event * 
wq_top(void)
{
    return &(mem_events_wq_data[wq_selector].data[wq_index]);
}

/* 
 * wq_push() - add event to the workqueue
 *
 * @addr:       destination of operation
 * @size:       size of the operation
 * @AccessType: operation type
 * @ip:         src address of the instruction pointer
 * @tsk_name:   if this is a fork add the task name
 *
 * This function moves the workqueue top in addition to adding
 *
 */
void __always_inline wq_push(uintptr_t addr, size_t size, enum AccessType
        access_type, uintptr_t ip, char * tsk_name)
{
    struct memorizer_kernel_event * evtptr = wq_top();
    evtptr->event_type = access_type;
    evtptr->pid = task_pid_nr(current);

    if(access_type < Memorizer_Fork) {
        evtptr->data.et.src_va_ptr = ip;
        evtptr->data.et.va_ptr = addr;
        evtptr->data.et.event_size = size;
    }
    else {
        strncpy(evtptr->data.comm, tsk_name, sizeof(evtptr->data.comm));
    }
    
    /* If we are at the end of the queue swap out and schedule work */
    if(unlikely(wq_index == num_entries_perwq-1)) {
        switch_to_next_work_queue();
    } else {
        ++wq_index;
    }

    /* 
     * This is an approach to avoid using workqueues and drain the queue the
     * first time we are in process context.
     *
     * TODO: There is a bug: our consumer is too slow and gets caught on some
     * workloads: so we overflow
     */
    if(unlikely(work_deferred)){
        if (!(in_irq()) || !(in_softirq())) {
            unsigned long flags;
            local_irq_save(flags);
            parse_events(&mem_events_wq_data[next_to_parse]);
            local_irq_restore(flags);
            work_deferred = false;
        }
    }
}

void __drain_active_work_queue()
{
    switch_to_next_work_queue();
}

static void
wq_exit(void)
{
    //printd();
    //flush_workqueue(wq);
    //destroy_workqueue(wq);
    //printd();
}


/**
 * init_mem_access_wl - initialize the percpu data structures
 *
 * Init all the values to 0 for the selector, head, and tail
 */
static void init_mem_access_wls(void)
{
    int i, j = 0;
    //struct memorizer_kernel_event * data = NULL;
#if 0
	struct mem_access_worklists * wls;
	size_t cpu;
	for_each_possible_cpu(cpu){
		wls = &per_cpu(mem_access_wls, cpu);
		wls->selector = 0;
		wls->head = -1;
		wls->tail = 0;
	}
#endif
    for(;i<num_queues;i++)
    {
        /* initialize the event queue to NULL for properer ring buffer */
        for(j=0;j<num_entries_perwq;j++)
        {
            mem_events_wq_data[i].data[j].event_type = Memorizer_NULL;
        }

#if WORKQUEUES == 1
        /* Setup the workqueue structures */
        INIT_WORK(&mem_events_wq_data[i].work, &mem_events_workhandler);
#endif
    }
}

/* Fops and Callbacks for char_driver */

static int char_open(struct inode *inode, struct file* file){
	   return 0;
};

static int char_close(struct inode *inode, struct file* file){
	   return 0;
};

static int char_mmap(struct file *file, struct vm_area_struct * vm_struct){
	__memorizer_enter();
	unsigned long pfn;
	int i = 0;
	int bufNum = 252-imajor(file->f_inode);
	for(i=0; i<ML;i++)
	{
		pfn = vmalloc_to_pfn(buffList[bufNum]+i*PAGE_SIZE);
		remap_pfn_range(vm_struct, vm_struct->vm_start+i*PAGE_SIZE, pfn, PAGE_SIZE, PAGE_SHARED);
	}
	__memorizer_exit();
	return 0;

};

static const struct file_operations char_driver={
	.owner = THIS_MODULE,
	.open = char_open,
	.release = char_close,
	.mmap = char_mmap,
};

static int create_char_devs(void)
{
	int i = 0;
	for (i = 0; i<NB; i++)
	{
		dev[i] = kmalloc(sizeof(dev_t), GFP_KERNEL);
		cd[i] = kmalloc(sizeof(struct cdev), GFP_KERNEL);

		char devName[12];
		sprintf(devName,"char_dev%u",i);
		pr_info("%s\n",devName);

		if(alloc_chrdev_region(dev[i],0,1,devName)<0)
		{
			pr_warning("Something Went Wrong with allocating char device\n");
		}
		else
		{
			pr_info("Allocated Region for char device\n");
		}
		cdev_init(cd[i],&char_driver);
		if(cdev_add(cd[i], *dev[i], 1)<0)
		{
			pr_warning("Couldn't add the char device\n");
		}
		else
		{
			pr_info("Added the char device\n");
		}


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
	int i = 0;

	__memorizer_enter();
#if INLINE_EVENT_PARSE == 0
	init_mem_access_wls();
#endif
	/* allocate and initialize memorizer internal allocator */
	memorizer_alloc_init();

	/* initialize the lookup table */
	lt_init();

	/* initialize the table tracking CFG edges */
	func_hash_tbl_init();
	cfgtbl = create_function_hashtable();

	/* Create default catch all objects for types of allocated memory */
	for(i=0;i<NumAllocTypes;i++)
	{
		general_kobjs[i] = memalloc(sizeof(struct memorizer_kobj));
		init_kobj(general_kobjs[i], 0, 0, 0, i);
		write_lock(&object_list_spinlock);
		list_add_tail(&general_kobjs[i]->object_list, &object_list);
		write_unlock(&object_list_spinlock);
	}

	local_irq_save(flags);
	if(memorizer_enabled_boot){
		memorizer_enabled = true;
	} else {
		memorizer_enabled = false;
	}
	if(mem_log_boot){
		memorizer_log_access = true;
	} else {
		memorizer_log_access = false;
	}
	if(cfg_log_boot){
		cfg_log_on = true;
	} else {
		cfg_log_on = false;
	}
	print_live_obj = true;

	local_irq_restore(flags);
	__memorizer_exit();
}

/*
 * Late initialization function.
 */
static int memorizer_late_init(void)
{
    wq = create_workqueue("wq_memorizer_events");

	unsigned long flags;
	struct dentry *dentry, *dentryMemDir;

	__memorizer_enter();

	dentryMemDir = debugfs_create_dir("memorizer", NULL);
	if (!dentryMemDir)
		pr_warning("Failed to create debugfs memorizer dir\n");

	dentry = debugfs_create_file("kmap", S_IRUGO, dentryMemDir,
				     NULL, &kmap_fops);
	if (!dentry)
		pr_warning("Failed to create debugfs kmap file\n");

	/* stats interface */
	dentry = debugfs_create_file("show_stats", S_IRUGO, dentryMemDir,
				     NULL, &show_stats_fops);
	if (!dentry)
		pr_warning("Failed to create debugfs show stats\n");

	dentry = debugfs_create_file("clear_dead_objs", S_IWUGO, dentryMemDir,
				     NULL, &clear_dead_objs_fops);
	if (!dentry)
		pr_warning("Failed to create debugfs clear_dead_objs\n");

	dentry = debugfs_create_file("clear_printed_list", S_IWUGO, dentryMemDir,
				     NULL, &clear_printed_list_fops);
	if (!dentry)
		pr_warning("Failed to create debugfs clear_printed_list\n");

	dentry = debugfs_create_file("cfgmap", S_IRUGO|S_IWUGO, dentryMemDir,
				     NULL, &cfgmap_fops);
	if (!dentry)
		pr_warning("Failed to create debugfs cfgmap\n");

	dentry = debugfs_create_bool("memorizer_enabled", S_IRUGO|S_IWUGO,
				     dentryMemDir, &memorizer_enabled);
	if (!dentry)
		pr_warning("Failed to create debugfs memorizer_enabled\n");

	dentry = debugfs_create_bool("memorizer_log_access", S_IRUGO|S_IWUGO,
				     dentryMemDir, &memorizer_log_access);
	if (!dentry)
		pr_warning("Failed to create debugfs memorizer_log_access\n");

	dentry = debugfs_create_bool("cfg_log_on", S_IRUGO|S_IWUGO,
				     dentryMemDir, &cfg_log_on);
	if (!dentry)
		pr_warning("Failed to create debugfs cfg_log_on\n");

	dentry = debugfs_create_bool("print_live_obj", S_IRUGO | S_IWUGO,
				     dentryMemDir, &print_live_obj);
	if (!dentry)
		pr_warning("Failed to create debugfs print_live_obj\n");

	dentry = debugfs_create_file("drain_active_work_queue", S_IWUGO, dentryMemDir,
				     NULL, &drain_active_work_queue_fops);
	if (!dentry)
		pr_warning("Failed to create debugfs drain_active_work_queue\n");

	pr_info("Memorizer initialized\n");
	pr_info("Size of memorizer_kobj:%d\n",sizeof(struct memorizer_kobj));
	pr_info("Size of memorizer_kernel_event:%d\n",sizeof(struct memorizer_kernel_event));
	print_pool_info();
	print_stats(KERN_INFO);
	
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
       cfg_log_on = true;
       local_irq_restore(flags);

        print_stats(KERN_INFO);

#if MEMORIZER_DEBUG >= 5
        //read_lock_irqsave(&active_kobj_rbtree_spinlock, flags);

        pr_info("The free'd Kobj list");
        dump_object_list();

        pr_info("The live kernel object tree now:");
        __print_active_rb_tree(active_kobj_rbtree_root.rb_node);

        //read_unlock_irqrestore(&active_kobj_rbtree_spinlock, flags);
#endif

        print_stats(KERN_INFO);

        __memorizer_exit();
        return 0;
}
EXPORT_SYMBOL(memorizer_init_from_driver);
