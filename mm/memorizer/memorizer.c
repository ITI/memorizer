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
 *	Memorizer has global and a percpu data structure:
 *
 *		- global rbtree of active kernel objects - queue for holding
 *		  free'd objects that haven't logged - A percpu event queue to
 *		  track memory access events (Not used in current version, ignore)
 *
 * 		- Global objects: object_list, memorizer_kobj, pool_next_avail_byte,
 * 		  function hash table, and lookup table.
 *
 *     Therefore, we have the following locks:
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
 *		- mem_rwlock:
 *
 * 			Lock for memory's next available byte pointer.
 *
 * 		- fht_rwlock:
 *
 * 			Lock for function hash table. This lock is to protect
 * 			the function list when a new bucket is inserted. Note,
 * 			we don't need a read or write lock for updating the function
 * 			count because we use an atomic variable for the count.
 *
 * 		- lookup_tbl_rw_lock:
 *
 * 			TODO: Need investigate whether we need this lock.
 *
 *===-----------------------------------------------------------------------===

 * Per-CPU data:
 *  	- inmem:
 *
 * 			inmem makes sure we don't have re-entrance problem. We make this
 * 			a per-cpu data so that each core can execute Memorizer in parallel.
 *
 *===-----------------------------------------------------------------------===
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
#include <linux/mm_types.h>
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

#include<asm/fixmap.h>

#include "kobj_metadata.h"
#include "event_structs.h"
#include "FunctionHashTable.h"
#include "memorizer.h"
#include "stats.h"
#include "util.h"
#include "memalloc.h"
#include "../slab.h"
#include "../kasan/kasan.h"



//==-- Debugging and print information ------------------------------------==//
#define MEMORIZER_DEBUG		1
#define FIXME			0

#define INLINE_EVENT_PARSE	1
#define WORKQUEUES		0

#define CALL_SITE_STRING	1
#define TASK_STRING		1

//==-- Prototype Declarations ---------------------------------------------==//
static void inline __memorizer_kmalloc(unsigned long call_site, const void *ptr,
		uint64_t bytes_req, uint64_t bytes_alloc,
		gfp_t gfp_flags, enum AllocType AT);
static inline struct memorizer_kobj * __create_kobj(uintptr_t call_site, uintptr_t
		ptr, uint64_t size, enum AllocType AT);
static struct memorizer_kobj * add_heap_UFO(uintptr_t va);
//==-- Data types and structs for building maps ---------------------------==//
#define global_table_text_size 1024 * 1024 * 10
char * global_table_text;
char * global_table_ptr;

//==-- PER CPU data structures and control flags --------------------------==//
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
static int __init early_memorizer_enabled(char *arg)
{
	if (!arg)
		return 0;
	if (strcmp(arg,"yes") == 0) {
		pr_info("Enabling boot alloc logging\n");
		memorizer_enabled_boot = true;
	}
	if (strcmp(arg,"no") == 0) {
		pr_info("Disable boot alloc logging\n");
		memorizer_enabled_boot = false;
	}
	return 1;
}
early_param("memorizer_enabled_boot", early_memorizer_enabled);

/* flag enable/disable memory access logging */
static bool memorizer_log_access = false;
static bool mem_log_boot = false;
static int __init early_mem_log_boot(char *arg)
{
	if (!arg)
		return 0;
	if (strcmp(arg,"yes") == 0) {
		pr_info("Enabling boot accessing logging\n");
		mem_log_boot= true;
	}
	if (strcmp(arg,"no") == 0) {
		pr_info("Disabling boot accessing logging\n");
		mem_log_boot= false;
	}
	return 1;
}
early_param("mem_log_boot", early_mem_log_boot);

/* flag enable/disable memory access logging */
static bool cfg_log_on = false;
static bool cfg_log_boot = false;
static int __init early_cfg_log_boot(char *arg)
{
	if (!arg)
		return 0;
	if (strcmp(arg,"yes") == 0) {
		pr_info("Enabling boot accessing logging\n");
		cfg_log_boot= true;
	}
	if (strcmp(arg,"no") == 0) {
		pr_info("Disabling boot accessing logging\n");
		cfg_log_boot= false;
	}
	return 1;
}
early_param("cfg_log_boot", early_cfg_log_boot);

static bool track_calling_context = false;
static int __init track_cc(char *arg){
    if(!arg)
        return 0;
    if(strcmp(arg,"yes") == 0) {
        pr_info("Enabling boot accessing logging\n");
        track_calling_context = true;
    }
	return 1;
}
early_param("mem_track_cc", track_cc);

static bool stack_trace_on = false;
static bool stack_trace_boot = false;
static int __init early_stack_trace_boot(char *arg)
{
	if (!arg)
		return 0;
	if (strcmp(arg,"yes") == 0) {
		pr_info("Enabling boot accessing logging\n");
		stack_trace_boot = true;
	}
	if (strcmp(arg,"no") == 0) {
		pr_info("Disabling boot accessing logging\n");
		stack_trace_boot= false;
	}
	return 1;
}
early_param("stack_trace_boot", early_stack_trace_boot);

/* flag enable/disable printing of live objects */
static bool print_live_obj = true;

/* Function has table */
struct FunctionHashTable * cfgtbl;

/* full list of freed kobjs */
static LIST_HEAD(object_list);

/* global object id reference counter */
static atomic_long_t global_kobj_id_count = ATOMIC_INIT(0);

/* General kobj for catchall object references */
static struct memorizer_kobj * general_kobjs[NumAllocTypes];

//==-- Locks --=//
/* RW Spinlock for access to freed kobject list */
DEFINE_RWLOCK(object_list_spinlock);

/* Monitor variable to prevent Memorizer from entering itself */
DEFINE_PER_CPU(unsigned long, inmem);

volatile unsigned long in_getfreepages;

uintptr_t cur_caller = 0;

//--- MEMBLOCK Allocator Tracking ---//
/* This is somewhat challenging because these blocks are allocated on physical
 * addresses. So we need to transition them.
 */
typedef struct {
	uintptr_t loc;
	uint64_t size;
} memblock_alloc_t;
memblock_alloc_t memblock_events[100000];
size_t memblock_events_top = 0;
bool in_memblocks(uintptr_t va_ptr)
{
	int i;
	uintptr_t pa = __pa(va_ptr);
	for(i=0;i<memblock_events_top;i++)
	{
		uintptr_t base = memblock_events[i].loc;
		uintptr_t end = memblock_events[i].loc + memblock_events[i].loc;
		if(pa >= base && pa < end)
			return true;
	}
	return false;
}

/* global timestamp counter */
atomic_t timestamp = ATOMIC_INIT(0);
long get_ts(void) { return atomic_fetch_add(1,&timestamp); }

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
    return this_cpu_cmpxchg(inmem, 0, 1);
}

static __always_inline void __memorizer_exit(void)
{
    this_cpu_write(inmem, 0);
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

void memorizer_print_stats(void)
{
    print_stats((size_t)KERN_CRIT);
}
EXPORT_SYMBOL(memorizer_print_stats);

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
	if (track_calling_context)
		afc->caller = cur_caller;
	else
		afc->caller = 0;
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
	list_for_each (listptr, &(kobj->access_counts)) {
		entry = list_entry(listptr, struct access_from_counts, list);
		if (src_ip == entry->ip) {
			if (kobj->alloc_type == MEM_NONE) {
				if (entry->caller == cur_caller)
					return entry;
				else if (cur_caller < entry->caller)
					break;
			} else {
				return entry;
			}
		} else if (src_ip < entry->ip) {
			break;
		}
	}
	/* allocate the new one and initialize the count none in list */
	afc = alloc_and_init_access_counts(src_ip, pid);
	if (afc)
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

static int reports_shown = 0;

static inline int find_and_update_kobj_access(uintptr_t src_va_ptr,
		uintptr_t va_ptr, pid_t pid, size_t access_type, size_t size)
{
	struct memorizer_kobj *kobj = NULL;
	struct access_from_counts *afc = NULL;

	if (in_pool(va_ptr)) {
		track_access(MEM_MEMORIZER,size);
		return -1;
	}

	/* Get the kernel object associated with this VA */
	kobj = lt_get_kobj(va_ptr);

	if (!kobj) {
		if (is_induced_obj(va_ptr)) {
			kobj = general_kobjs[MEM_INDUCED];
			track_access(MEM_INDUCED,size);
		} else if (in_memblocks(va_ptr)) {
			kobj = __create_kobj(MEM_UFO_MEMBLOCK, va_ptr, size,
					MEM_UFO_MEMBLOCK);
			if (!kobj) {
				kobj = general_kobjs[MEM_MEMBLOCK];
				track_untracked_access(MEM_MEMBLOCK,size);
			} else {
				track_access(MEM_MEMBLOCK,size);
			}
		} else {
			enum AllocType AT = kasan_obj_type((void *)va_ptr,size);
			kobj =  general_kobjs[AT];
			switch(AT){
				case MEM_STACK_PAGE:
					kobj = __create_kobj(MEM_STACK_PAGE, va_ptr,
							size, MEM_UFO_GLOBAL);
					track_access(MEM_STACK_PAGE,size);
					break;
                case MEM_HEAP:
#if 1
                    // Debugging feature to print a KASAN report for missed heap accesses.
                        // Only prints up to 5 reports.
                    if (reports_shown < 5){
                        kasan_report((unsigned long) va_ptr, size, 1, (unsigned long)&kasan_report);
                        reports_shown++;
                    }
#endif
                    kobj = add_heap_UFO(va_ptr);

                    track_access(MEM_UFO_HEAP,size);
                    break;
                case MEM_GLOBAL:
                    kobj = __create_kobj(MEM_UFO_GLOBAL, va_ptr,
                                 size, MEM_UFO_GLOBAL);
                    track_access(MEM_UFO_GLOBAL,size);
                    break;
                case MEM_NONE:
                    kobj = __create_kobj(MEM_UFO_NONE, va_ptr,
                                 size, MEM_UFO_NONE);
                    track_access(MEM_UFO_NONE,size);
                    break;
                default:
                    track_untracked_access(AT,size);
			}
		}
	} else {
		track_access(kobj->alloc_type, size);
	}

	/* Grab the object lock here */
	write_lock(&kobj->rwlock);

	/* Search access queue to the entry associated with src_ip */
	afc = unlckd_insert_get_access_counts(src_va_ptr, pid, kobj);

	/* increment the counter associated with the access type */
	if (afc)
		access_type ? ++(afc->writes) : ++(afc->reads);

	write_unlock(&kobj->rwlock);
	return afc ? 0 : -1;
}

//==-- Memorizer memory access tracking -----------------------------------==//

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
	if (unlikely(!memorizer_log_access) || unlikely(!memorizer_enabled)) {
		track_disabled_access();
		return;
	}

	if (current->kasan_depth > 0) {
		track_induced_access();
		return;
	}

	if (__memorizer_enter()) {
		track_induced_access();
		return;
	}

	local_irq_save(flags);
	find_and_update_kobj_access(ip,addr,-1,write,size);
	local_irq_restore(flags);

	__memorizer_exit();
}

//==-- Memorizer kernel object tracking -----------------------------------==//

/**
 * Requires: Calculate the callee's stack frame size
 * and callee's arg size if arg registers are full.
 * @ip: is the callee's virtual address.
 * @parent_ip: is the caller's virtual address.
 */
void __cyg_profile_func_enter(void *ip, void *parent_ip)
{
	unsigned long flags;
	struct pt_regs pt_regs;

	if (!cfg_log_on && !stack_trace_on)
		return;
	/* Prevent infinete loop */
	if (__memorizer_enter())
		return;

	if (track_calling_context)
		cur_caller = (uintptr_t)parent_ip;

	/* Disable interrupt */

	local_irq_save(flags);
#if defined(__x86_64__)
#if INLINE_EVENT_PARSE
	/**
	 * | caller sp |
	 * | ret addr  |
	 * | callee bp |
	 * | ...       |
	 * | callee sp |
	 * | cyg bp    |
	 *
	 * In order to calculate func bp, we need to dereference
	 * the callee bp and callee bp + 0x10 is the func sp.
	 */

	if (stack_trace_on) {
		uintptr_t callee_bp = 0, callee_sp = 0;
		register uintptr_t cyg_rbp asm("rbp");
		callee_bp = *(uintptr_t *)cyg_rbp; // deference callee bp
		callee_sp = cyg_rbp + 0x10; // Prologue pushes the return address (0x8) and RBP (0x8)
		/* Store function bp and sp into pt_regs structure */
		pt_regs.bp = callee_bp;
		pt_regs.sp = callee_sp;
	}

	/* cfg_update_counts creates <from, to, callee kobj, args kobj> tuple */
	cfg_update_counts(cfgtbl, (uintptr_t)parent_ip, (uintptr_t)ip, &pt_regs, stack_trace_on);
#endif

#else
	pr_info("Memorizer stack frame tracing only support x86_64 arch.");
#endif

	local_irq_restore(flags);
	__memorizer_exit();
}
EXPORT_SYMBOL(__cyg_profile_func_enter);

/**
 * Future work: The stack frame kobjs are never free and there are lots
 * of these kobjs. In the future, we can free the kobjs here and restore
 * the lookup table pointing to the MEM_STACK_PAGE kobj.
 * @ip: is the callee's virtual address.
 * @parent_ip: is the caller's virtual address.
 */
void __cyg_profile_func_exit(void *ip, void *parent_ip)
{

}
EXPORT_SYMBOL(__cyg_profile_func_exit);

static struct kmem_cache * get_slab_cache(const void * addr)
{
	if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory)) {
		struct page *page = virt_to_head_page(addr);
		if (PageSlab(page)) {
			return page->slab_cache;
		}
		return NULL;
	}
	return NULL;
}

/*
 * If we miss lookup the object from the cache.  Note that the init_kobj will
 * preset a string for the slab name. So these UFOs are aggregated in an
 * intelligent and still useful way. We've missed the alloc (and thereofre the
 * alloc site) but we've at least grouped them by type. Assume we get a page
 * because we are in this case.
 */
static struct memorizer_kobj * add_heap_UFO(uintptr_t va)
{
	struct memorizer_kobj *kobj = NULL;
	if ((va >= (uintptr_t)PAGE_OFFSET) && (va < (uintptr_t)high_memory)) {
		struct page *page = virt_to_head_page((void *)va);
		if (PageSlab(page)) {
			void *object;
			struct kmem_cache *cache = page->slab_cache;
			object = nearest_obj(cache, page, (void *)va);
			//pr_err("Object at %p, in cache %s size: %d\n", object,
			//cache->name, cache->object_size);
			kobj = __create_kobj(MEM_UFO_HEAP, (uintptr_t)object,
					cache->object_size,
					MEM_UFO_HEAP);
		}
	}
	return kobj;
}

/**
 * init_kobj() - Initalize the metadata to track the recent allocation
 */
static void init_kobj(struct memorizer_kobj * kobj, uintptr_t call_site,
		uintptr_t ptr_to_kobj, size_t bytes_alloc,
		enum AllocType AT)
{
	struct kmem_cache * cache;

	rwlock_init(&kobj->rwlock);
	if (atomic_long_inc_and_test(&global_kobj_id_count)) {
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
	kobj->args_kobj = NULL;
	INIT_LIST_HEAD(&kobj->access_counts);
	INIT_LIST_HEAD(&kobj->object_list);

	/* get the slab name */
	cache = get_slab_cache((void *)(kobj->va_ptr));
	if (cache) {
		kobj->slabname = memalloc(strlen(cache->name)+1);
		strncpy(kobj->slabname, cache->name, strlen(cache->name));
		kobj->slabname[strlen(cache->name)]='\0';
	} else {
		kobj->slabname = "no-slab";
	}

#if CALL_SITE_STRING == 1
	/* Some of the call sites are not tracked correctly so don't try */
	if (call_site)
		kallsyms_lookup((unsigned long) call_site, NULL, NULL,
				//&(kobj->modsymb), kobj->funcstr);
			NULL, kobj->funcstr);
#endif
#if TASK_STRING == 1
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
#endif

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
	list_for_each_safe(p, tmp, afc_lh) {
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
	list_for_each_safe(p, tmp, &object_list) {
		kobj = list_entry(p, struct memorizer_kobj, object_list);
		/* If free_jiffies is 0 then this object is live */
		if (kobj->free_jiffies > 0) {
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
	list_for_each_safe(p, tmp, &object_list) {
		kobj = list_entry(p, struct memorizer_kobj, object_list);
		/* If free_jiffies is 0 then this object is live */
		if (kobj->free_jiffies > 0 && kobj->printed) {
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
	if (kobj) {
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
	unsigned long flags;

	if (__memorizer_enter()) {
		track_induced_free();
		return;
	}

	local_irq_save(flags);
	__memorizer_free_kobj(call_site, kobj_ptr);

	local_irq_restore(flags);
	__memorizer_exit();
}

struct memorizer_kobj *create_kobj(uintptr_t call_site, uintptr_t ptr, uint64_t size, enum AllocType AT) {
	return __create_kobj(call_site, ptr, size, AT);
}

/**
 * __create_kobj() - allocate and init kobj assuming locking and rentrance
 *	protections already enabled.
 * @call_site:  Address of the call site to the alloc
 * @ptr:	Pointer to location of data structure in memory
 * @size:	Size of the allocation
 * @AT:		Type of allocation
 */
static inline struct memorizer_kobj * __create_kobj(uintptr_t call_site,
		uintptr_t ptr, uint64_t
		size, enum AllocType AT)
{
	struct memorizer_kobj *kobj;

	/* inline parsing */
	kobj = memalloc(sizeof(struct memorizer_kobj));
	if (!kobj) {
		track_failed_kobj_alloc();
		return NULL;
	}

	/* initialize all object metadata */
	init_kobj(kobj, call_site, ptr, size, AT);

	/* memorizer stats tracking */
	track_alloc(AT);

	/* mark object as live and link in lookup table */
	lt_insert_kobj(kobj);

	/* Grab the writer lock for the object_list and insert into object list */
	write_lock(&(list_first_entry(&object_list, struct memorizer_kobj,
				      object_list))->rwlock);
	list_add_tail(&kobj->object_list, &object_list);
	write_unlock(&(list_first_entry(&object_list, struct memorizer_kobj,
					object_list))->rwlock);
	return kobj;
}

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

	if (unlikely(ptr==NULL))
		return;

	if (unlikely(!memorizer_enabled)) {
		track_disabled_alloc();
		return;
	}

	if (__memorizer_enter()) {
		/* link in lookup table with dummy event */
		local_irq_save(flags);
		lt_insert_induced((void *)ptr,bytes_alloc);
		track_induced_alloc();
		local_irq_restore(flags);
		return;
	}

	local_irq_save(flags);
	__create_kobj((uintptr_t) call_site, (uintptr_t) ptr, bytes_alloc, AT);
	local_irq_restore(flags);
	__memorizer_exit();
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
	if (unlikely(!cpu_online(raw_smp_processor_id())) || !memorizer_enabled) {
		return;
	}

	memorizer_free_kobj((uintptr_t) call_site, (uintptr_t) ptr);
}

void memorizer_memblock_alloc(phys_addr_t base, phys_addr_t size)
{
	memblock_alloc_t * evt = &memblock_events[memblock_events_top++];
	evt->loc = base;
	evt->size = size;
	track_alloc(MEM_MEMBLOCK);
}

void memorizer_memblock_free(phys_addr_t base, phys_addr_t size)
{
}

void memorizer_alloc_bootmem(unsigned long call_site, void * v, uint64_t size)
{
	track_alloc(MEM_BOOTMEM);
	__memorizer_kmalloc(call_site, v, size, size, 0, MEM_BOOTMEM);
	return;
}

const char * l1str = "lt_l1_tbl";
const char * l2str = "lt_l2_tbl";
const char * memorizer_kobjstr = "memorizer_kobj";
const char * access_from_countsstr = "access_from_counts";
bool is_memorizer_cache_alloc(char * cache_str)
{
	if (!memstrcmp(l1str,cache_str))
		return true;
	if (!memstrcmp(l2str,cache_str))
		return true;
	if (!memstrcmp(memorizer_kobjstr,cache_str))
		return true;
	if (!memstrcmp(access_from_countsstr,cache_str))
		return true;
	return false;
}


void memorizer_vmalloc_alloc(unsigned long call_site, const void *ptr,
		unsigned long size, gfp_t gfp_flags)
{
	if (unlikely(ptr == NULL))
		return;
	__memorizer_kmalloc(call_site, ptr, size, size,
			gfp_flags, MEM_VMALLOC);
}

void memorizer_vmalloc_free(unsigned long call_site, const void *ptr)
{
	memorizer_free_kobj((uintptr_t) call_site, (uintptr_t) ptr);
}


// Update the allocation site of a kmem_cache object, only if has current special
// value of MEMORIZER_PREALLOCED.
bool memorizer_kmem_cache_set_alloc(unsigned long call_site, const void * ptr){

  struct memorizer_kobj * kobj = lt_get_kobj((uintptr_t)ptr);

  if (kobj == NULL){
    return false;
  } else {
    if (kobj -> alloc_ip == MEMORIZER_PREALLOCED){
      kobj -> alloc_ip = call_site;
    }
    return true;
  }
}

void memorizer_kmem_cache_alloc(unsigned long call_site, const void *ptr,
		struct kmem_cache *s, gfp_t gfp_flags)
{
	if (unlikely(ptr == NULL))
		return;
	if (!is_memorizer_cache_alloc((char *)s->name))
		__memorizer_kmalloc(call_site, ptr, s->object_size, s->size,
				gfp_flags, MEM_KMEM_CACHE);
}

void memorizer_kmem_cache_alloc_node (unsigned long call_site, const void *ptr,
		struct kmem_cache *s, gfp_t gfp_flags, int node)
{
	if (unlikely(ptr == NULL))
		return;
	if (!is_memorizer_cache_alloc((char *)s->name))
		__memorizer_kmalloc(call_site, ptr, s->object_size, s->size,
				gfp_flags, MEM_KMEM_CACHE_ND);
}

void memorizer_kmem_cache_free(unsigned long call_site, const void *ptr)
{
	/*
	 * Condition for ensuring free is from online cpu: see trace point
	 * condition from include/trace/events/kmem.h for reason
	 */
	if (unlikely(!cpu_online(raw_smp_processor_id())) || !memorizer_enabled) {
		return;
	}

	memorizer_free_kobj((uintptr_t) call_site, (uintptr_t) ptr);
}


void memorizer_alloc_pages(unsigned long call_site, struct page *page, unsigned
		int order, gfp_t gfp_flags)
{

  if (test_bit(0,&in_getfreepages)){
    return;
  }
    __memorizer_kmalloc(call_site, page_address(page),
            (uintptr_t) PAGE_SIZE * (1 << order),
            (uintptr_t) PAGE_SIZE * (1 << order),
            gfp_flags, MEM_ALLOC_PAGES);

}

/* This is a slight variation to memorizer_alloc_pages(). Alloc_pages() can only return
 * a power-of-two number of pages, whereas alloc_pages_exact() can return
 * any specific number of pages. We don't want Memorizer to track the gap
 * between the two, so use this special memorizer hook for this case. */
void memorizer_alloc_pages_exact(unsigned long call_site, void * ptr, unsigned
			   int size, gfp_t gfp_flags)
{

  // Compute the actual number of bytes that will be allocated
  unsigned long alloc_size = PAGE_ALIGN(size);

  __memorizer_kmalloc(call_site, ptr,
		      alloc_size, alloc_size,
		      gfp_flags, MEM_ALLOC_PAGES);

}


void memorizer_start_getfreepages(){
  test_and_set_bit_lock(0,&in_getfreepages);
}

void memorizer_alloc_getfreepages(unsigned long call_site, struct page *page, unsigned
			   int order, gfp_t gfp_flags)
{
    //TODO: Conflict here where one version used 1 << order, other used 2 << order.
    __memorizer_kmalloc(call_site, page_address(page),
            (uintptr_t) PAGE_SIZE * (1 << order),
            (uintptr_t) PAGE_SIZE * (1 << order),
            gfp_flags, MEM_ALLOC_PAGES);

    clear_bit_unlock(0,&in_getfreepages);
}

void memorizer_free_pages(unsigned long call_site, struct page *page, unsigned
		int order)
{
	/*
	 * Condition for ensuring free is from online cpu: see trace point
	 * condition from include/trace/events/kmem.h for reason
	 */
	if (unlikely(!cpu_online(raw_smp_processor_id())) || !memorizer_enabled) {
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
	struct memorizer_kobj * stack_kobj = lt_get_kobj((uintptr_t)task->stack);
	/* if there then just mark it, but it appears to be filtered out */
	if (!stack_kobj) {
		void *base = task_stack_page(task);
		__memorizer_kmalloc(_RET_IP_, base, THREAD_SIZE, THREAD_SIZE,
				0, MEM_STACK_PAGE);
	} else {
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

void memorizer_alloc(unsigned long call_site, const void *ptr, size_t size,
		enum AllocType AT)
{
	//__memorizer_kmalloc(call_site, ptr, size, size, 0, AT);
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

	if (list_empty(&object_list))
		return NULL;

	if (*pos == 0) {
		sequence_done = false;
		return object_list.next;
	}

	/*
	 * Second call back even after return NULL to stop. This must occur
	 * after the check to (*pos == 0) otherwise it won't continue after the
	 * first time a read is executed in userspace. The specs didn't mention
	 * this but my experiments showed its occurrence.
	 */
	if (sequence_done == true)
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
	if (!print_live_obj && kobj->free_jiffies == 0) {
		read_unlock(&kobj->rwlock);
		return 0;
	}
	kobj->printed = true;
	/* Print object allocation info */
	seq_printf(seq,"%-p,%d,%p,%lu,%lu,%lu,%p,%s,%s,%s\n",
			(void*) kobj->alloc_ip, kobj->pid, (void*) kobj->va_ptr,
			kobj->size, kobj->alloc_jiffies, kobj->free_jiffies, (void*)
			kobj->free_ip, alloc_type_str(kobj->alloc_type), kobj->comm,
			kobj->slabname);

	/* print each access IP with counts and remove from list */
	list_for_each_entry(afc, &kobj->access_counts, list) {
		if (kobj->alloc_type == MEM_NONE && track_calling_context) {
			seq_printf(seq, "  from:%p,caller:%p,%llu,%llu\n",
					(void *) afc->ip, (void *)afc->caller,
					(unsigned long long) afc->writes,
					(unsigned long long) afc->reads);
		} else
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
	if (!v)
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

static int cfgmap_seq_show(struct seq_file *seq, void *v)
{
	struct EdgeBucket * b;
	int index;
	for (index = 0; index < cfgtbl -> number_buckets; index++) {
		b = cfgtbl -> buckets[index];
		while (b != NULL) {
			seq_printf(seq,"%lx %lx %ld\n", b -> from, b -> to, atomic_long_read(&b -> count));
			b = b -> next;
		}
	}
	return 0;
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

/* The debugging info generated by gcc doesn't quite include *everything*,
 * even when using -g3 for most debugging info. As far as I can tell, the
 * only things missing are some string constants, etc that are not very
 * interesting. However, on the uSCOPE analysis side, we really want to map
 * these back to files / folders for analysis. This interface lets you print
 * the entire global table exactly as KASAN sees it, so that everything matches
 * up and we get complete debug info for all globals. */
static int globaltable_seq_show(struct seq_file *seq, void *v)
{
  seq_printf(seq, "%s\n", global_table_text);
  return 0;
}

static int globaltable_open(struct inode *inode, struct file *file)
{
	return single_open(file, &globaltable_seq_show, NULL);
}

static const struct file_operations globaltable_fops = {
	.owner		= THIS_MODULE,
	.open		= globaltable_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

//==-- Memorizer Initializtion --------------------------------------------==//
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
	cfgtbl = create_function_hashtable();

	/* Create default catch all objects for types of allocated memory */
	for (i = 0; i < NumAllocTypes; i++) {
		general_kobjs[i] = memalloc(sizeof(struct memorizer_kobj));
		init_kobj(general_kobjs[i], 0, 0, 0, i);
		write_lock(&object_list_spinlock);
		list_add_tail(&general_kobjs[i]->object_list, &object_list);
		write_unlock(&object_list_spinlock);
	}

	/* Allocate memory for the global metadata table.
	 * Not used by Memorizer, but used in processing globals offline. */
	global_table_text = memalloc(global_table_text_size);
	global_table_ptr = global_table_text;

	local_irq_save(flags);
	if (memorizer_enabled_boot) {
		memorizer_enabled = true;
	} else {
		memorizer_enabled = false;
	}
	if (mem_log_boot) {
		memorizer_log_access = true;
	} else {
		memorizer_log_access = false;
	}
	if (cfg_log_boot) {
		cfg_log_on = true;
	} else {
		cfg_log_on = false;
	}
	if (stack_trace_boot && !cfg_log_on) {
		stack_trace_on = true;
	} else {
		stack_trace_on = false;
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
	struct dentry *dentry, *dentryMemDir;

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

	dentry = debugfs_create_bool("stack_trace_on", S_IRUGO|S_IWUGO,
			dentryMemDir, &stack_trace_on);
	if (!dentry)
		pr_warning("Failed to create debugfs stack_trace_on\n");

	dentry = debugfs_create_bool("print_live_obj", S_IRUGO | S_IWUGO,
			dentryMemDir, &print_live_obj);
	if (!dentry)
		pr_warning("Failed to create debugfs print_live_obj\n");

	dentry = debugfs_create_file("global_table", S_IRUGO, dentryMemDir,
				     NULL, &globaltable_fops);
	if (!dentry)
		pr_warning("Failed to create debugfs show stats\n");

	pr_info("Memorizer initialized\n");
	pr_info("Size of memorizer_kobj:%d\n",(int)(sizeof(struct memorizer_kobj)));
	pr_info("FIXADDR_START: %p,  FIXADDR_SIZE %p", (void *)FIXADDR_START, (void *)FIXADDR_SIZE);
	print_pool_info();
	print_stats((size_t)KERN_INFO);

	return 0;
}
late_initcall(memorizer_late_init);
