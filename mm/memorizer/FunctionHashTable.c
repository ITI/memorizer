#ifndef FUNCTIONHASHTABLE_C
#define FUNCTIONHASHTABLE_C

#include "FunctionHashTable.h"

struct FunctionHashTable * create_function_hashtable(){

  struct FunctionHashTable * h = malloc(sizeof(struct FunctionHashTable));
  h -> buckets = calloc(START_SIZE, sizeof(struct EdgeBucket *));
  h -> number_buckets = START_SIZE;
  h -> full_buckets = 0;
  h -> stored_items = 0;
  
  return h;
}

  
void update_counts(struct FunctionHashTable * ht, uintptr_t from, uintptr_t to){
  
  // Compute index by xoring the from and to fields then masking away high bits
  int index = (from ^ to) & (ht -> number_buckets - 1);

  // Search for edge. If found, increment count and return
  struct EdgeBucket * search = ht -> buckets[index];
  struct EdgeBucket * prev = NULL;
  while (search != NULL){
    if (search -> from == from && search -> to == to){
      search -> count += 1;
      return;
    } else {
      prev = search;
      search = search -> next;      
    }
  }

  // Edge was not found. Two cases:

  // 1) Create new bucket if empty root
  if (ht -> buckets[index] == NULL){
    ht -> buckets[index] = malloc(sizeof(struct EdgeBucket));
    ht -> buckets[index] -> from = from;
    ht -> buckets[index] -> to = to;
    ht -> buckets[index] -> count = 1;
    ht -> buckets[index] -> next = NULL;
    ht -> full_buckets += 1;
    ht -> stored_items += 1;
    return;
  }  

  // 2) Insert item onto end of existing chain
  prev -> next = malloc(sizeof(struct EdgeBucket));
  prev -> next -> from = from;
  prev -> next -> to = to;
  prev -> next -> count = 1;  
  prev -> next -> next = NULL;
  ht -> stored_items += 1;
  return;
 
}

// Write hashtable contents (edge hits) to file
void write_to_file(struct FunctionHashTable * ht, FILE * fd){
  struct EdgeBucket * b;    
  int index;
  for (index = 0; index < ht -> number_buckets; index++){
    b = ht -> buckets[index];
    while (b != NULL){
      fprintf(fd,"%lx %lx %ld\n", b -> from, b -> to, b -> count);
      b = b -> next;
    }
  }  
}

// Release all allocated memory
void destroy_function_hashtable(struct FunctionHashTable * ht){

  struct EdgeBucket * b;
  int index;
  for (index = 0; index < ht -> number_buckets; index++){
    b = ht -> buckets[index];
    while (b != NULL){
      struct EdgeBucket * prev = b;
      b = b -> next;
      free(prev);
    }
  }
  free(ht->buckets);
  free(ht);
}

#endif
