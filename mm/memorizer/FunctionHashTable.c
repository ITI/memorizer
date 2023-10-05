#ifndef FUNCTIONHASHTABLE_C
#define FUNCTIONHASHTABLE_C

#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include "FunctionHashTable.h"
#include "memalloc.h"
#include "kobj_metadata.h"
#include "memorizer.h"


#define NUMBUCKS 1000000

DEFINE_RWLOCK(fht_rwlock);

struct FunctionHashTable * create_function_hashtable() {

	struct FunctionHashTable * h = memalloc(sizeof(struct FunctionHashTable));
	h -> buckets = zmemalloc(NUM_BUCKETS * sizeof(struct EdgeBucket *));
	h -> number_buckets = NUM_BUCKETS;

	return h;
}

/* Check whether arguments have been pushed to the stack */
bool push_args_to_stack(struct pt_regs *pt_regs, struct memorizer_kobj*
last_edge_frame_kobj)
{
	/**
	 * The caller_bp might be 0, for example, entry_SYSCALL_64_fastpath ->
	 * sys_dup2 where entry_SYSCALL_64_fastpath the first entry function in
	 * the kernel, then its bp could be 0.
	 */
	if (last_edge_frame_kobj != NULL) {
		/*
		 * Before stack_trace is turned on, the caller's alloc type would be
		 * MEM_STACK_PAGE. In this case, we don't know the caller's stack
		 * frame shadow kobject information.
		 */
		if (last_edge_frame_kobj->alloc_type == MEM_STACK_FRAME) {
			/**
			 * There are cases that caller rbp and callee rbp's difference is
			 * larger than THREAD_SIZE, for exmaple, ret_from_intr -> do_IRQ,
			 * we need to understand how interrupt handle their rbp.
			 */
			if(abs(last_edge_frame_kobj->va_ptr - pt_regs->bp + 0x10) < THREAD_SIZE) {
				/**
				 * If the caller's sp is not equal to callee's bp, we should
				 * allocate an argument kobj.
				 */
				if(last_edge_frame_kobj->va_ptr != pt_regs->bp + 0x10) {
					return true;
				}
			}
		}
	}
	return false;
}

/* Update shadow stack frame and argument kobj's meta data and the lookup table. */
void update_stack_kobj(struct EdgeBucket *new_bucket, struct pt_regs *pt_regs)
{
	/** Interrupt confuses the kobj call stack, so we stop tracing interrupt for now */
#if defined(__x86_64__)
	uintptr_t caller_bp = *(uintptr_t *)pt_regs->bp;
	struct memorizer_kobj *last_edge_frame_kobj = lt_get_kobj(caller_bp);
	/**
	 * If we find a <caller, callee> pair exists, then update the function's kobj
	 * and argument kobj metadata type and lookup table.
	 */
	lt_insert_kobj(new_bucket->kobj);
	/**
	 * Update the function's argument kobj metadata and lookup table in case of
	 * variable length arguments
	 */
	if (push_args_to_stack(pt_regs, last_edge_frame_kobj)) {
		new_bucket->kobj->args_kobj->size = last_edge_frame_kobj->va_ptr - pt_regs->bp + 0x10;
		lt_insert_kobj(new_bucket->kobj->args_kobj);
	}
#else
	pr_info("Memorizer stack frame tracing only support x86_64 arch.");
#endif
}

/* Create shadow stack frame and argument kobj's meta data and update the lookup table. */
void create_stack_kobj(uintptr_t to, struct EdgeBucket *new_bucket, struct pt_regs *pt_regs)
{
#if defined(__x86_64__)
	/* Allocate callee's stack frame */
	uintptr_t caller_bp;
	struct memorizer_kobj *last_edge_frame_kobj;
	new_bucket->kobj = create_kobj(to, pt_regs->sp,
			0x10 + pt_regs->bp - pt_regs->sp, MEM_STACK_FRAME);

	/* Allocate arg_kobj and its size is the difference of the caller's sp and callee's bp*/
	caller_bp = *(uintptr_t *)pt_regs->bp;
	last_edge_frame_kobj = lt_get_kobj(caller_bp);
	if (push_args_to_stack(pt_regs, last_edge_frame_kobj)) {
		new_bucket->kobj->args_kobj = create_kobj(to, pt_regs->bp + 0x10,
				last_edge_frame_kobj->va_ptr - pt_regs->bp + 0x10, MEM_STACK_ARGS);
	} else {
		/* If no arguments are pushed to the stack, create an argument kobj with size 0 */
		new_bucket->kobj->args_kobj = create_kobj(to, pt_regs->bp + 0x10,
				0, MEM_STACK_ARGS);
	}
#else
	pr_info("Memorizer stack frame tracing only support x86_64 arch.");
#endif
}

/**
 * This function puts the <from, to, stack frame kobj, function argument kobj>
 * tuple into the hash table. When stack_trace_on is disabled, stack frame kobj
 * points to NULL value. If a stack frame kobj already exists, we use allocation
 * promotion to overide the existing one.
 * @ht: hash table pointer
 * @from: caller's virtual address
 * @to: callee's virtual address
 * @pt_regs: a structure for base pointer and stack pointer, calculated at
 * cyg_profile_function_enter.
 * @stack_trace_on: if turned on, allocate the stack frame kobj and argument
 * kobj.
 */
void cfg_update_counts(struct FunctionHashTable * ht, uintptr_t from, uintptr_t to,
		struct pt_regs *pt_regs, bool stack_trace_on)
{
	int index;
	struct EdgeBucket *search, *prev, *new_bucket;

	/* TODO: index might be changed in multi-core env? */
	write_lock(&fht_rwlock);
	// pr_crit("Entering: %p -> %p", from,to);
	// Compute index by xoring the from and to fields then masking away high bits
	index = (from ^ to) & (ht -> number_buckets - 1);

	// Search for edge. If found, increment count and return
	search = ht -> buckets[index];
	prev = ht->buckets[index];
	new_bucket = NULL;

	while (search != NULL) {
		if (search -> from == from && search -> to == to) {
			atomic_long_inc(&search -> count);
			/**
			 * Need to check if search-kobj is null or not. If a bucket is
			 * created before we enable stack trace, then we will get a null for
			 * kobj.
			 */
			if (stack_trace_on && search->kobj != NULL) {
				update_stack_kobj(search, pt_regs);
			} else if (stack_trace_on && search->kobj == NULL) {
				/**
				 * If a (caller, callee) pair exists before we enabled the stack trace,
				 * then we need to create a new stack kobj for this frame.
				 */
				create_stack_kobj(to, search, pt_regs);
			}
			write_unlock(&fht_rwlock);
			return;
		} else {
			// Collision, loop through the linked list
			prev = search;
			search = search -> next;
		}
	}

	/**
	 * If we can't find the match, there are two scenarios:
	 * 1. The hash bucket does not have an entry yet.
	 * 2. The hash bucket already have an entry (which is a colloision)
	 * and prev points to that location. The new entry will be appended to
	 * the end of the linked list.
	 */
	if (ht -> buckets[index] == NULL) {
		// 1) Create new bucket if empty root
		ht -> buckets[index] = memalloc(sizeof(struct EdgeBucket));
		new_bucket = ht -> buckets[index];
	} else if (prev -> next == NULL) {
		// 2) Insert item onto end of existing chain
		prev -> next = memalloc(sizeof(struct EdgeBucket));
		new_bucket = prev -> next;
	}

	// Update bucket information
	new_bucket -> from = from;
	new_bucket -> to = to;
	atomic_long_set(&ht -> buckets[index] -> count, 1);
	new_bucket -> next = NULL;
	new_bucket -> kobj = NULL;

	// Create new stack frame kobj and arguments kobj for callee
	if (stack_trace_on) {
		create_stack_kobj(to, new_bucket, pt_regs);
	}
	write_unlock(&fht_rwlock);

	return;
}

// Write hashtable contents (edge hits) to file
void console_print(struct FunctionHashTable * ht)
{
	struct EdgeBucket * b;
	int index;
	for (index = 0; index < ht -> number_buckets; index++) {
		b = ht -> buckets[index];
		while (b != NULL) {
			pr_crit("%lx %lx %ld\n", b -> from, b -> to, atomic_long_read(&b -> count));
			b = b -> next;
		}
	}
}

// Clear the entries
void cfgmap_clear(struct FunctionHashTable * ht)
{
	struct EdgeBucket * b;
	int index;
	for (index = 0; index < ht -> number_buckets; index++) {
		b = ht -> buckets[index];
		while (b != NULL) {
			struct EdgeBucket * prev = b;
			b = b -> next;
			memset(prev, 0, sizeof(struct EdgeBucket));
		}
		ht -> buckets[index] = NULL;
	}
}

// Release all allocated memory
void destroy_function_hashtable(struct FunctionHashTable * ht)
{
	struct EdgeBucket * b;
	int index;
	for (index = 0; index < ht -> number_buckets; index++) {
		b = ht -> buckets[index];
		while (b != NULL) {
			struct EdgeBucket * prev = b;
			b = b -> next;
			memset(prev, 0, sizeof(struct EdgeBucket));
		}
	}
	kfree(ht->buckets);
	kfree(ht);
}

#endif
