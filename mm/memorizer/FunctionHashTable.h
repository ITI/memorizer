// FunctionHashTable is a lightweight hashtable implementation for tracking
// call/return edges in uSCOPE.

#ifndef FUNCTIONHASHTABLE_H
#define FUNCTIONHASHTABLE_H

#include <linux/types.h>

#define NUM_BUCKETS (_AC(1,UL) << 19)

struct EdgeBucket {
  uintptr_t from, to;
  atomic_long_t count;
  struct memorizer_kobj *kobj;
  struct EdgeBucket * next;
};

struct FunctionHashTable {
  struct EdgeBucket ** buckets;
  int number_buckets;
  int full_buckets;
  int stored_items;
};

// Initialization for the table data structures
void func_hash_tbl_init(void);

// Create a new FunctionHashTable
struct FunctionHashTable * create_function_hashtable(void);

// Update the counts for an edge, adding to table if not already there
void cfg_update_counts(struct FunctionHashTable * ht, uintptr_t from, uintptr_t to, struct pt_regs *pt_regs, bool stack_trace_on);

// Clear entries and reset
void cfgmap_clear(struct FunctionHashTable * ht);

// Print directly to console TODO: this is just temp hack for check
void console_print(struct FunctionHashTable * ht);

// Release memory
void destroy_function_hashtable(struct FunctionHashTable * ht);

#endif
