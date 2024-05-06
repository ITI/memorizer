/*===-- LICENSE ------------------------------------------------------------===
 * Developed by:
 *
 *    Research Group of Professor Vikram Adve in the Department of Computer
 *    Science The University of Illinois at Urbana-Champaign
 *    http://web.engr.illinois.edu/~vadve/Home.html
 *
 * Copyright (c) 2015, Nathan Dautenhahn
 * Copyright (c) 2024, Board of Trustees of the University of Illinois
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
 *	TODO robadams@illinois.edu write up how memorizer_enter is used as a lock.
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
#include <linux/sched/task_stack.h>
// #include <linux/bootmem.h>
#include <linux/kasan-checks.h>
#include <linux/mempool.h>
#include <linux/delay.h>

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

//==-- Naming information for debugfs --==//
#define BOOL_DECL(name, value) struct bool_name name = { value, # name }

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
int memorizer_enabled = 0;
static pid_t memorizer_enabled_pid;
static BOOL_DECL(memorizer_enabled_boot, true);
static int __init early_memorizer_enabled(char *arg)
{
	if (!arg)
		return 0;
	if (strcmp(arg,"yes") == 0) {
		pr_info("Enabling boot alloc logging\n");
		memorizer_enabled_boot.value = true;
	}
	if (strcmp(arg,"no") == 0) {
		pr_info("Disable boot alloc logging\n");
		memorizer_enabled_boot.value = false;
	}
	return 1;
}
early_param("memorizer_enabled_boot", early_memorizer_enabled);

/* flag enable/disable memory access logging */
static BOOL_DECL(memorizer_log_access, false); 
static BOOL_DECL(mem_log_boot, false);
static int __init early_mem_log_boot(char *arg)
{
	if (!arg)
		return 0;
	if (strcmp(arg,"yes") == 0) {
		pr_info("Enabling boot accessing logging\n");
		mem_log_boot.value = true;
	}
	if (strcmp(arg,"no") == 0) {
		pr_info("Disabling boot accessing logging\n");
		mem_log_boot.value = false;
	}
	return 1;
}
early_param("mem_log_boot", early_mem_log_boot);

/* flag enable/disable memory access logging */
static BOOL_DECL(cfg_log_on, false);
static BOOL_DECL(cfg_log_boot, false);
static int __init early_cfg_log_boot(char *arg)
{
	if (!arg)
		return 0;
	if (strcmp(arg,"yes") == 0) {
		pr_info("Enabling boot accessing logging\n");
		cfg_log_boot.value = true;
	}
	if (strcmp(arg,"no") == 0) {
		pr_info("Disabling boot accessing logging\n");
		cfg_log_boot.value = false;
	}
	return 1;
}
early_param("cfg_log_boot", early_cfg_log_boot);

BOOL_DECL(track_calling_context, false);
static int __init track_cc(char *arg){
    if(!arg)
        return 0;
    if(strcmp(arg,"yes") == 0) {
        pr_info("Enabling boot accessing logging\n");
        track_calling_context.value = true;
    }
	return 1;
}
early_param("mem_track_cc", track_cc);

static BOOL_DECL(stack_trace_on, false);
static BOOL_DECL(stack_trace_boot, false);
static int __init early_stack_trace_boot(char *arg)
{
	if (!arg)
		return 0;
	if (strcmp(arg,"yes") == 0) {
		pr_info("Enabling boot accessing logging\n");
		stack_trace_boot.value = true;
	}
	if (strcmp(arg,"no") == 0) {
		pr_info("Disabling boot accessing logging\n");
		stack_trace_boot.value = false;
	}
	return 1;
}
early_param("stack_trace_boot", early_stack_trace_boot);

enum column_type index_column_type = COLUMN_SERIAL;
static int __init early_index_column_type(char *arg)
{
	if (!arg)
		return 1;
	if (strcmp(arg,"serial") == 0) {
		pr_info("Enabling serial number index\n");
		index_column_type = COLUMN_SERIAL;
		return 0;
	}
	if (strcmp(arg,"time") == 0) {
		pr_info("Enabling time index\n");
		index_column_type = COLUMN_TIME;
		return 0;
	}
	return 1;
}
early_param("memorizer_index_type", early_index_column_type);

/* flag enable/disable printing of live objects */
BOOL_DECL(print_live_obj, true);

/* Use WARN() macros if true */
BOOL_DECL(verbose_warnings, false);

/* Function has table */
struct FunctionHashTable * cfgtbl;

/* Either a kobj represents an allocated
 * memory range, or it represents a free'd
 * memory range, or it is, itself, free'd
 * and ready for re-use.
 */
LIST_HEAD(memorizer_object_allocated_list);
LIST_HEAD(memorizer_object_freed_list);
LIST_HEAD(memorizer_object_reuse_list);

/* Either an afc is stitched into a kobj
 * or it isn't. If it isn't, then it lives
 * on the cache list. */
LIST_HEAD(memorizer_afc_reuse_list);


/*
 * A wait queue that gets poked every time the lists change in a
 * non-atomic context.
 */
DECLARE_WAIT_QUEUE_HEAD(object_list_wq);


/* global object id reference counter */
static atomic_long_t global_kobj_id_count = ATOMIC_INIT(0);

/* General kobj for catchall object references */
static struct memorizer_kobj * general_kobjs[NumAllocTypes];

//==-- Locks --=//
/* RW Spinlock for access to any kobject list */
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

/* global index counter */
atomic64_t index_stamp = ATOMIC_INIT(0);

/*
 * Provides an increasing function to mark the allocation lifecycle events.
 * Alterntive number streams are available, but by default
 * returns a strictly-increasing stream based on `index_stamp`.
 * 
 * Note that COLUMN_TIME is increasing, but not strictly increasing, 
 * i.e. multiple events can share a single time value.
 */
unsigned long get_index(void) {
	if(unlikely(index_column_type == COLUMN_TIME))
		return get_jiffies_64();
	return atomic64_fetch_add(1, &index_stamp);
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
	pr_info("\talloc index: %lu\n", kobj->alloc_index);
	pr_info("\tfree index:  %lu\n", kobj->free_index);
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
	struct list_head *p;

	/* First try the recycle bin */
	p = pop_or_null(&memorizer_afc_reuse_list);
	if(p) {
		track_afc_alloc_reuse();
		return list_entry(p, struct access_from_counts, list);
	}

	track_afc_alloc_memalloc();
	return memalloc(sizeof(struct access_from_counts));
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
#ifdef CONFIG_MEMORIZER_TRACKPIDS
	afc->pid = pid;
#else
	afc->pid = -1;
#endif
	if (track_calling_context.value)
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
	if (afc) {
		init_access_counts_object(afc, ip, pid);
		track_access_counts_alloc();
	}
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
			if (pid == entry->pid) {
				if (kobj->alloc_type == MEM_NONE) {
					if (entry->caller == cur_caller) {
						return entry;
					} else if (cur_caller < entry->caller) {
						break;
					}
				} else {
					return entry;
				}
			} else if (pid < entry->pid) {
				break;
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
                        kasan_report((const void*) va_ptr, size, 1, (unsigned long)&kasan_report);
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

	/* TODO robadams@illinois.edu - is rwlock redundant here? Doesn't mementer() cover this case? */
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
 * memorizer_is_enabled - return the current logical state of memorizer_enabled
 *
 * The memorizer_enabled variable has four states. 0 and 1 mean unconditionally
 * false and true, respectively. 2 and 3 both filter out uninteresting processes,
 * while 3 also filters out non-process contexts.
 */
static bool __always_inline memorizer_is_enabled(bool filter) {
	if(memorizer_enabled && !filter)
		return true;

	switch(memorizer_enabled) {
	case 1: 
		return true;
	case 2: 
		return (!in_task()) || current->memorizer_enabled;
	case 3: 
		return in_task() && current->memorizer_enabled;
	default:
		return false;
	}
}

/**
 * memorizer_mem_access() - record associated data with the load or store
 * @addr:	The virtual address being accessed
 * @size:	The number of bits for the load/store
 * @write:	True if the memory access is a write (store)
 * @ip:		IP of the invocing instruction
 *
 * Memorize, ie. log, the particular data access.
 *
 * Note that this can be called from any code stream, regardless of
 * process state. We return quickly if @inmem is already taken, both to
 * protect our data structures and to ignore induced results.
 */
void __always_inline memorizer_mem_access(const void* addr, size_t size, bool
		write, uintptr_t ip)
{
	unsigned long flags;
	if (unlikely(!memorizer_log_access.value) || unlikely(!memorizer_is_enabled(true))) {
		track_disabled_access();
		return;
	}

	if (current->kasan_depth > 0) {
		track_induced_access();
		return;
	}

	if (__memorizer_enter()) {
		/* Can't sleep, have to punt */
		track_induced_access();
		return;
	}

	local_irq_save(flags);
	find_and_update_kobj_access(ip,(uintptr_t)addr,
#ifdef CONFIG_MEMORIZER_TRACKPIDS
		in_task() ? task_pid_nr(current) : -1,
#else
		-1,
#endif
		write,size);
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

	if (!cfg_log_on.value && !stack_trace_on.value)
		return;
	/* Prevent infinete loop */
	if (__memorizer_enter())
		return;

	if (track_calling_context.value)
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

	if (stack_trace_on.value) {
		uintptr_t callee_bp = 0, callee_sp = 0;
		register uintptr_t cyg_rbp asm("rbp");
		callee_bp = *(uintptr_t *)cyg_rbp; // deference callee bp
		callee_sp = cyg_rbp + 0x10; // Prologue pushes the return address (0x8) and RBP (0x8)
		/* Store function bp and sp into pt_regs structure */
		pt_regs.bp = callee_bp;
		pt_regs.sp = callee_sp;
	}

	/* cfg_update_counts creates <from, to, callee kobj, args kobj> tuple */
	cfg_update_counts(cfgtbl, (uintptr_t)parent_ip, (uintptr_t)ip, &pt_regs, stack_trace_on.value);
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
			return page_slab(page)->slab_cache;
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
			struct kmem_cache *cache = page_slab(page)->slab_cache;
			object = nearest_obj(cache, virt_to_slab((void *)va), (void *)va);
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
	kobj->alloc_index = get_index();
	kobj->free_index = 0;
	kobj->free_ip = 0;
	kobj->obj_id = atomic_long_read(&global_kobj_id_count);
	kobj->printed = false;
	kobj->alloc_type = AT;
	kobj->args_kobj = NULL;
	INIT_LIST_HEAD(&kobj->access_counts);
	INIT_LIST_HEAD(&kobj->object_list);
	kobj->state = KOBJ_STATE_ALLOCATED;

	/* get the slab name */
	cache = get_slab_cache((void *)(kobj->va_ptr));
	if (cache) {
		kobj->slabname = memalloc(strlen(cache->name)+1);
		if (kobj->slabname) {
			strncpy(kobj->slabname, cache->name, strlen(cache->name));
			kobj->slabname[strlen(cache->name)]='\0';
		} else {
			kobj->slabname = "no-slab";
		}
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
 * __memorizer_discard_kobj()
 * @kobj:	The memorizer kernel object to discard.
 *
 * This must be called with @inmem locked.
 */
void __memorizer_discard_kobj(struct memorizer_kobj * kobj)
{
	BUG_ON(kobj->state != KOBJ_STATE_FREED);
	BUG_ON(kobj->object_list.next == LIST_POISON1);
	BUG_ON(kobj->object_list.prev == LIST_POISON2);
	BUG_ON(kobj->access_counts.next == LIST_POISON1);
	BUG_ON(kobj->access_counts.prev == LIST_POISON2);

	/* Remove from (likely) memorizer_object_freed_list */
	list_del(&kobj->object_list);

	/* Add afc to the cache list */
	list_splice_init(&kobj->access_counts, &memorizer_afc_reuse_list);
	kobj->access_counts.next = LIST_POISON1;
	kobj->access_counts.prev = LIST_POISON2;

	/* Add kernel object to the cache list */
	kobj->state = KOBJ_STATE_REUSE;
	list_add_tail(&kobj->object_list, &memorizer_object_reuse_list);

	/* stats */
	track_kobj_free();
}

void memorizer_discard_kobj(struct memorizer_kobj * kobj)
{
	int err = __memorizer_enter_wait(1);
	if(!err) {
		__memorizer_discard_kobj(kobj);
		__memorizer_exit();
		return;
	}
	return;
}


/**
 * clear_dead_objs --- remove entries from freed list and free kobjs
 *
 * @only_printed_items - limit clearance to certain dead items.
 * 
 * This must be called in process context, without acquiring inmem.
 */
static int clear_dead_objs(bool only_printed_items)
{
	struct memorizer_kobj *kobj;
	LIST_HEAD(object_list);
	struct list_head *tmp;
	struct list_head *p;
	int err;

	/* Move all of the dead items from freed list to our local copy */
	err = __memorizer_enter_wait(1);
	if(err)
		return err;
	list_replace_init(&memorizer_object_freed_list, &object_list);
	__memorizer_exit();

	wake_up_interruptible(&object_list_wq);

	
	/* Now we can take all the time in the world with no locks to worry about */
	list_for_each_safe(p, tmp, &object_list) {
		/* TODO robadams@illinois.edu - do we need to lock kobj->rwlock? */
		kobj = list_entry(p, struct memorizer_kobj, object_list);
		if(kobj->state != KOBJ_STATE_FREED) {
			pr_err("Object %p: state(%x) != KOBJ_STATE_FREED\n", kobj, kobj->state);
			BUG();
		}
		if((!only_printed_items) || kobj->printed) {
			memorizer_discard_kobj(kobj);
		}
	}

	/* Move free'd-but-not-printed objects back to global list */
	err = __memorizer_enter_wait(1);
	if(err)
		return err;
	list_splice(&object_list, &memorizer_object_freed_list);
	__memorizer_exit();

	wake_up_interruptible(&object_list_wq);

	return 0;
}

/**
 * __memorizer_free_kobj - move the specified object to free list
 *
 * @call_site:	Call site requesting the original free
 * @ptr:	Address of the object to be freed
 *
 * Algorithm:
 *	1) find and remove object in rbtree
 *	2) record free details in the kobj
 *	3) move kobj from allocated list to free'd list
 *
 * The caller should have already acquired @inmem.
 *
 */
void static __memorizer_free_kobj(uintptr_t call_site, uintptr_t kobj_ptr)
{

	struct memorizer_kobj *kobj;
	unsigned long flags;

	/* find and remove the kobj from the lookup table and return the
	 * kobj */
	kobj = lt_remove_kobj(kobj_ptr);

	/*
	 * If this is null it means we are freeing something we did not insert
	 * into our tree and we have a missed alloc track, otherwise we update
	 * some of the metadata for free.
	 */
	if (kobj) {
		BUG_ON(kobj->state != KOBJ_STATE_ALLOCATED);
		BUG_ON(kobj->access_counts.next == LIST_POISON1);
		BUG_ON(kobj->access_counts.prev == LIST_POISON2);
		if(verbose_warnings.value) {
			WARN(kobj->va_ptr != kobj_ptr,
				"kobj(%p)->va_ptr(%p) != kobj_ptr(%p)",
				kobj,
				(void*)kobj->va_ptr,
				(void*)kobj_ptr);
		} else {
			if(kobj->va_ptr != kobj_ptr) {
				pr_warn("kobj(%p)->va_ptr(%p) != kobj_ptr(%p)",
					kobj,
					(void*)kobj->va_ptr,
					(void*)kobj_ptr);
			}
		}

		/* Update the free_index for the object */
		write_lock_irqsave(&kobj->rwlock, flags);
		kobj->free_index = get_index();
		kobj->free_ip = call_site;

		/* Move the object from (likely) allocated list to freed list */
		list_del(&kobj->object_list);
		kobj->state = KOBJ_STATE_FREED;
		list_add(&kobj->object_list, &memorizer_object_freed_list);
		write_unlock_irqrestore(&kobj->rwlock, flags);

		track_free();
	}
	else
		track_untracked_obj_free();
}

/**
 * memorizer_free_kobj - move the specified objec to free list
 * @call_site:	Call site requesting the original free
 * @ptr:	Address of the object to be freed
 *
 * Wrapper for __memorizer_free_obj that aquires @inmem first.
 */
void static memorizer_free_kobj(uintptr_t call_site, uintptr_t kobj_ptr)
{
	if (__memorizer_enter()) {
		track_induced_free();
		return;
	}

	__memorizer_free_kobj(call_site, kobj_ptr);

	__memorizer_exit();
}

struct memorizer_kobj *create_kobj(uintptr_t call_site, uintptr_t ptr, uint64_t size, enum AllocType AT) {
	return __create_kobj(call_site, ptr, size, AT);
}

/**
 * __alloc_kobj() - alloc the memory for a kobj.
 *
 * Must be called with @inmem locked.
 */
static inline struct memorizer_kobj *__alloc_kobj(void)
{
	struct list_head *p;

	/* First try the recycle bin */
	p = pop_or_null(&memorizer_object_reuse_list);
	if(p) {
		track_kobj_alloc_reuse();
		return list_entry(p, struct memorizer_kobj, object_list);
	}

	track_kobj_alloc_memalloc();
	return memalloc(sizeof(struct memorizer_kobj));
}

/**
 * __create_kobj() - allocate and init kobj assuming locking and rentrance
 *	protections already enabled.
 * @call_site:  Address of the call site to the alloc
 * @ptr:	Pointer to location of data structure in memory
 * @size:	Size of the allocation
 * @AT:		Type of allocation
 *
 */
static inline struct memorizer_kobj * __create_kobj(uintptr_t call_site,
		uintptr_t ptr, uint64_t
		size, enum AllocType AT)
{
	struct memorizer_kobj *kobj;
	unsigned long flags;

	kobj = __alloc_kobj();
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

	write_lock_irqsave(&object_list_spinlock, flags);
	list_add_tail(&kobj->object_list, &memorizer_object_allocated_list);
	write_unlock_irqrestore(&object_list_spinlock, flags);

	/*
	 * We can't call @wake_up_interruptible(&object_list_wq) from
	 * memorizer context. But, if we could, we would.
	 */

	return kobj;
}

static void inline __memorizer_kmalloc(unsigned long call_site, const void
		*ptr, uint64_t bytes_req, uint64_t bytes_alloc, gfp_t gfp_flags, enum AllocType AT)
{

	unsigned long flags;

	if (unlikely(ptr==NULL))
		return;

	if (unlikely(!memorizer_is_enabled(true))) {
		track_disabled_alloc();
		return;
	}

	if (__memorizer_enter()) {
		/* link in lookup table with dummy event */
		/* TODO robadams@illinois.edu - why is local_irq necessary? */
		local_irq_save(flags);
		lt_insert_induced((void *)ptr,bytes_alloc);
		track_induced_alloc();
		local_irq_restore(flags);
		return;
	}

	__create_kobj((uintptr_t) call_site, (uintptr_t) ptr, bytes_alloc, AT);
	__memorizer_exit();
}

/*** HOOKS similar to the kmem points ***/

/**
 * memorizer_alloc() - record allocation event
 * @object:	Pointer to the beginning of hte object
 * @size:	Size of the object
 *
 * Track the allocation and add the object to the set of active object tree.
 */
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
	/* TODO robadams@illinois.edu should *free* depend on is_enabled? */
	if (unlikely(!cpu_online(raw_smp_processor_id())) || !memorizer_is_enabled(true)) {
		return;
	}

	memorizer_free_kobj((uintptr_t) call_site, (uintptr_t) ptr);
}

void memorizer_slab_free(unsigned long call_site, const void *ptr)
{
	memorizer_kfree(call_site, ptr);
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
void memorizer_kmem_cache_alloc_bulk(unsigned long call_site, const void *ptr,
		struct kmem_cache *s, gfp_t gfp_flags)
{
	if (unlikely(ptr == NULL))
		return;
	if (!is_memorizer_cache_alloc((char *)s->name))
		__memorizer_kmalloc(call_site, ptr, s->object_size, s->size,
				gfp_flags, MEM_KMEM_CACHE_BULK);
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
	if (unlikely(!cpu_online(raw_smp_processor_id())) || !memorizer_is_enabled(true)) {
		return;
	}

	memorizer_free_kobj((uintptr_t) call_site, (uintptr_t) ptr);
}

void memorizer_kmem_cache_free_bulk(unsigned long call_site, size_t size, void**p)
{
	/* TODO robadams@illinois.edu */
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
		      gfp_flags, MEM_ALLOC_PAGES_EXACT);

}
void memorizer_free_pages_exact (unsigned long call_site, struct page *page, unsigned
		int order)
{
	/*
	 * Condition for ensuring free is from online cpu: see trace point
	 * condition from include/trace/events/kmem.h for reason
	 */
	if (unlikely(!cpu_online(raw_smp_processor_id())) || !memorizer_is_enabled(true)) {
		return;
	}
	memorizer_free_kobj((uintptr_t) call_site, (uintptr_t)
			page_address(page));
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
            gfp_flags, MEM_ALLOC_PAGES_GETFREEPAGES);

    clear_bit_unlock(0,&in_getfreepages);
}

void memorizer_alloc_folio(unsigned long call_site, struct page *page, unsigned
			   int order, gfp_t gfp_flags)
{
    //TODO: Conflict here where one version used 1 << order, other used 2 << order.
    __memorizer_kmalloc(call_site, page_address(page),
            (uintptr_t) PAGE_SIZE * (1 << order),
            (uintptr_t) PAGE_SIZE * (1 << order),
            gfp_flags, MEM_ALLOC_PAGES_FOLIO);

    clear_bit_unlock(0,&in_getfreepages);
}

void memorizer_end_getfreepages() {
	clear_bit_unlock(0, &in_getfreepages);
}

void memorizer_free_pages(unsigned long call_site, struct page *page, unsigned
		int order)
{
	/*
	 * Condition for ensuring free is from online cpu: see trace point
	 * condition from include/trace/events/kmem.h for reason
	 */
	if (unlikely(!cpu_online(raw_smp_processor_id())) || !memorizer_is_enabled(true)) {
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

/*
 * clear_free_list_write() - call the function to clear the free'd kobjs
 */
static ssize_t clear_dead_objs_write(struct file *file, const char __user
		*user_buf, size_t size, loff_t *ppos)
{
	int err;
	pr_info("clear_dead_objs: Clearing the free'd kernel objects\n");
	err = clear_dead_objs(false);
	if(err)
		return err;
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
	int err;
	pr_info("clear_printed_list: Clearing the free'd and printed kernel objects\n");
	err = clear_dead_objs(true);
	if(err)
		return err;
	*ppos += size;
	return size;
}

static const struct file_operations clear_printed_list_fops = {
	.owner		= THIS_MODULE,
	.write		= clear_printed_list_write,
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

static ssize_t memorizer_enabled_read(struct file *filp, char __user *usr_buf, size_t size, loff_t *ppos)
{
	char buf[128];
	int count;

	if (*ppos != 0)
		return 0;

	switch(memorizer_enabled) {
	case 0:
	default:
		count = snprintf(buf, sizeof buf, "0 - memorizer disabled\n");
		break;
	case 1:
		count = snprintf(buf, sizeof buf, "1 - memorizer enabled, all processes\n");
		break;
	case 2:
		count = snprintf(buf, sizeof buf, "2 - memorizer enabled, proc root = %d\n", memorizer_enabled_pid);
		break;
	case 3:
		count = snprintf(buf, sizeof buf, "3 - memorizer_enabled, no irq, proc root = %d\n", memorizer_enabled_pid);
		break;
	}

	return simple_read_from_buffer(usr_buf, size, ppos, buf, count);
}

static ssize_t memorizer_enabled_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos)
{
    int ret;
    int value;

    ret = kstrtoint_from_user(buf, count, 10, &value);
    if (ret)
        return ret;

    if (value < 0 || value > 3)
        return -EINVAL;

    pr_info("memorizer_enabled: %d -> %d\n", memorizer_enabled, value);
    memorizer_enabled = value;

    if (value == 2 || value == 3) {
	memorizer_enabled_pid = task_pid_nr(current);
	current->memorizer_enabled = 1;
	pr_info("memorizer_enabled_pid: %d\n", memorizer_enabled_pid);
    }

    return count;
}

static const struct file_operations memorizer_enabled_fops = {
	.owner		= THIS_MODULE,
	.read		= memorizer_enabled_read,
	.write		= memorizer_enabled_write,
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

	/*
	 * Don't need to consider the return code.
	 */
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
		if (!general_kobjs[i])
			panic("Memorizer could not allocate catch-all kobjs");
		init_kobj(general_kobjs[i], 0, 0, 0, i);
		write_lock(&object_list_spinlock);
		list_add_tail(&general_kobjs[i]->object_list, &memorizer_object_allocated_list);
		write_unlock(&object_list_spinlock);
	}

	/* Allocate memory for the global metadata table.
	 * Not used by Memorizer, but used in processing globals offline. */
	global_table_text = memalloc(global_table_text_size);
	global_table_ptr = global_table_text;
	if (!global_table_text)
		panic("Memorizer could not allocate global table");

	local_irq_save(flags);
	if (memorizer_enabled_boot.value) {
		memorizer_enabled = 1;
	} else {
		memorizer_enabled = 0;
	}
	if (mem_log_boot.value ) {
		memorizer_log_access.value = true;
	} else {
		memorizer_log_access.value = false;
	}
	if (cfg_log_boot.value ) {
		cfg_log_on.value = true;
	} else {
		cfg_log_on.value = false;
	}
	if (stack_trace_boot.value && !cfg_log_on.value) {
		stack_trace_on.value = true;
	} else {
		stack_trace_on.value = false;
	}
	print_live_obj.value = true;

	local_irq_restore(flags);
	__memorizer_exit();
}


ssize_t memorizer_write_file_bool(struct file *file, const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct bool_name *bn = file->private_data;
	char buf[256];
	ssize_t result;
	bool old = bn->value;
	long res = strncpy_from_user(buf, user_buf, min(count, (size_t)31));

	if (res < 0) {
		strncpy(buf, "ERROR", 31);
	} else {
		buf[res] = 0;
	}

	result = debugfs_write_file_bool(file, user_buf, count, ppos);

	pr_info("%s(\"%*pEscn\"): %s -> %s\n",
		bn->name,
		(int)(strlen(buf)), buf,
		old ? "Y" : "N",
		bn->value ? "Y" : "N");

	return result;
}

static const struct file_operations memorizer_bool_fops = {
	.read =		debugfs_read_file_bool,
	.write =	memorizer_write_file_bool,
	.open =		simple_open,
	.llseek =	default_llseek,
};

static 
void memorizer_create_bool(const char *name, umode_t mode,
			struct dentry *parent, struct bool_name *value)
{
	debugfs_create_file(name, mode, parent, value, &memorizer_bool_fops);
}

/*
 * Late initialization function.
 */
static int memorizer_late_init(void)
{
	struct dentry *dentryMemDir;

	dentryMemDir = debugfs_create_dir("memorizer", NULL);
	if (!dentryMemDir)
		pr_warn("Failed to create debugfs memorizer dir\n");

	// TODO upcoming feature robadams@illinois.edu memorizer_stats_late_init(dentryMemDir);
	memorizer_data_late_init(dentryMemDir);
	// TODO upcoming feature robadams@illinois.edu memorizer_control_late_init(dentryMemDir);

	// stats interface 
	debugfs_create_file("show_stats", S_IRUGO, dentryMemDir,
			NULL, &show_stats_fops);
	
	// control lnterfaces
	debugfs_create_file("clear_dead_objs", S_IWUGO, dentryMemDir,
			NULL, &clear_dead_objs_fops);
	debugfs_create_file("clear_printed_list", S_IWUGO, dentryMemDir,
			NULL, &clear_printed_list_fops);
	debugfs_create_file("memorizer_enabled", S_IRUGO|S_IWUGO,
			dentryMemDir, NULL, &memorizer_enabled_fops);
	memorizer_create_bool("memorizer_log_access", S_IRUGO|S_IWUGO,
			dentryMemDir, &memorizer_log_access);
	memorizer_create_bool("cfg_log_on", S_IRUGO|S_IWUGO,
			dentryMemDir, &cfg_log_on);
	memorizer_create_bool("stack_trace_on", S_IRUGO|S_IWUGO,
			dentryMemDir, &stack_trace_on);
	memorizer_create_bool("print_live_obj", S_IRUGO | S_IWUGO,
			dentryMemDir, &print_live_obj);
	memorizer_create_bool("verbose_warnings", S_IRUGO | S_IWUGO,
			dentryMemDir, &verbose_warnings);

#ifdef CONFIG_MEMORIZER_DEBUGFS_RAM
	{
		extern uintptr_t pool_base;
		extern uintptr_t pool_end;
		static struct debugfs_blob_wrapper memalloc_blob;

		memalloc_blob.data = (void*)pool_base;
		memalloc_blob.size = pool_end - pool_base;
		debugfs_create_blob("memalloc_ram", S_IRUGO, dentryMemDir,
					&memalloc_blob);
	}
#endif

	

	pr_info("Memorizer initialized\n");
	pr_info("Size of memorizer_kobj:%d\n",(int)(sizeof(struct memorizer_kobj)));
	pr_info("FIXADDR_START: %p,  FIXADDR_SIZE %p", (void *)FIXADDR_START, (void *)FIXADDR_SIZE);
	print_pool_info();
	print_stats((size_t)KERN_INFO);

	return 0;
}
late_initcall(memorizer_late_init);
