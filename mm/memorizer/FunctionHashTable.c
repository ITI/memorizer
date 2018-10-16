#ifndef FUNCTIONHASHTABLE_C
#define FUNCTIONHASHTABLE_C

#include "FunctionHashTable.h"
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/kernel.h>


#define NUMBUCKS 1000000
struct EdgeBucket eblist[NUMBUCKS];
int nexti =0;

/* object cache for Edge Buckets */
static struct kmem_cache *eb_cache;

/* Initialize the FHT global data */
void func_hash_tbl_init(void)
{
	//eb_cache = KMEM_CACHE(EdgeBucket, SLAB_PANIC);
}

struct FunctionHashTable * create_function_hashtable(){

  struct FunctionHashTable * h = kmalloc(sizeof(struct FunctionHashTable),GFP_KERNEL);
  h -> buckets = kzalloc(NUM_BUCKETS * sizeof(struct EdgeBucket *), GFP_KERNEL);
  h -> number_buckets = NUM_BUCKETS;
  h -> full_buckets = 0;
  h -> stored_items = 0;
  
  return h;
}
  
void 
cfg_update_counts(struct FunctionHashTable * ht, uintptr_t from, uintptr_t to)
{
  
  //pr_crit("Entering: %p -> %p", from,to);
  // Compute index by xoring the from and to fields then masking away high bits
  int index = (from ^ to) & (ht -> number_buckets - 1);

  // Search for edge. If found, increment count and return
  struct EdgeBucket * search = ht -> buckets[index];
  struct EdgeBucket * prev = NULL;
  while (search != NULL){
    if (search -> from == from && search -> to == to){
      search -> count += 1;
      //pr_crit("Returning: %p -> %p", from,to);
      return;
    } else {
      prev = search;
      search = search -> next;      
    }
  }

  // Edge was not found. Two cases:

  // 1) Create new bucket if empty root
  if (ht->buckets[index] == NULL){
    //ht -> buckets[index] = kmem_cache_alloc(eb_cache, GFP_ATOMIC);
    if(ht->buckets[index]==NULL)
    {
      ht -> buckets[index] = &eblist[nexti++];
      if(nexti>NUMBUCKS)
          panic("Ran out of preallocated buckets for tracing");
    }
    ht -> buckets[index] -> from = from;
    ht -> buckets[index] -> to = to;
    ht -> buckets[index] -> count = 1;
    ht -> buckets[index] -> next = NULL;
    ht -> full_buckets += 1;
    ht -> stored_items += 1;
    //pr_crit("Returning: %p -> %p", from,to);
    return;
  }  

  // 2) Insert item onto end of existing chain
  //prev -> next = kmem_cache_alloc(eb_cache, GFP_ATOMIC);
  if(prev->next==NULL)
  {
    prev -> next = &eblist[nexti++];
    if(nexti>NUMBUCKS)
        panic("ran out of preallocated buckets for tracing");
  }
  prev -> next -> from = from;
  prev -> next -> to = to;
  prev -> next -> count = 1;  
  prev -> next -> next = NULL;
  ht -> stored_items += 1;
  return;
}

// Write hashtable contents (edge hits) to file
void console_print(struct FunctionHashTable * ht){
  struct EdgeBucket * b;    
  int index;
  for (index = 0; index < ht -> number_buckets; index++){
    b = ht -> buckets[index];
    while (b != NULL){
      pr_crit("%lx %lx %ld\n", b -> from, b -> to, b -> count);
      b = b -> next;
    }
  }  
}

// Clear the entries
void cfgmap_clear(struct FunctionHashTable * ht)
{
  struct EdgeBucket * b;
  int index;
  for (index = 0; index < ht -> number_buckets; index++){
    b = ht -> buckets[index];
    while (b != NULL){
      struct EdgeBucket * prev = b;
      b = b -> next;
      memset(prev,NULL,sizeof(struct EdgeBucket));
      //kmem_cache_free(eb_cache, prev);
    }
    ht -> buckets[index] = NULL;
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
      memset(prev,NULL,sizeof(struct EdgeBucket));
      //kmem_cache_free(eb_cache, prev);
    }
  }
  kfree(ht->buckets);
  kfree(ht);
}

#endif
