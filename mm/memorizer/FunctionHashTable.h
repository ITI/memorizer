// FunctionHashTable is a lightweight hashtable implementation for tracking 
// call/return edges in uSCOPE.

#ifndef FUNCTIONHASHTABLE_H
#define FUNCTIONHASHTABLE_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define START_SIZE 1024 * 1024

struct EdgeBucket {
  uintptr_t from, to;
  long count;
  struct EdgeBucket * next;
};

struct FunctionHashTable {
  struct EdgeBucket ** buckets;
  int number_buckets;
  int full_buckets;
  int stored_items;
};

// Create a new FunctionHashTable
struct FunctionHashTable * create_function_hashtable();

// Update the counts for an edge, adding to table if not already there
void update_counts(struct FunctionHashTable * ht, uintptr_t from, uintptr_t to);

// Write the found edges to a file
void write_to_file(struct FunctionHashTable * ht, FILE * fd);

// Release memory
void destroy_function_hashtable(struct FunctionHashTable * ht);

#endif
