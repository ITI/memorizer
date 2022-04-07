// SPDX-License-Identifier: GPL-2.0
/*
 * This file contains core generic KASAN code.
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
 *
 * Some code borrowed from https://github.com/xairy/kasan-prototype by
 *        Andrey Konovalov <andreyknvl@gmail.com>
 */

#include <linux/export.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/kasan.h>
#include <linux/kernel.h>
#include <linux/kfence.h>
#include <linux/kmemleak.h>
#include <linux/linkage.h>
#include <linux/memblock.h>
#include <linux/memory.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/bug.h>
#include <linux/memorizer.h>
#include <linux/memrz_alloc_type.h>

#include "kasan.h"
#include "../slab.h"

/*
 * All functions below always inlined so compiler could
 * perform better optimizations in each of __asan_loadX/__assn_storeX
 * depending on memory access size X.
 */

static __always_inline bool memory_is_poisoned_1(unsigned long addr)
{
	s8 shadow_value = *(s8 *)kasan_mem_to_shadow((void *)addr);

	if (unlikely(shadow_value)) {
		s8 last_accessible_byte = addr & KASAN_GRANULE_MASK;
		return unlikely(last_accessible_byte >= shadow_value);
	}

	return false;
}

static __always_inline bool memory_is_poisoned_2_4_8(unsigned long addr,
						unsigned long size)
{
	u8 *shadow_addr = (u8 *)kasan_mem_to_shadow((void *)addr);

	/*
	 * Access crosses 8(shadow size)-byte boundary. Such access maps
	 * into 2 shadow bytes, so we need to check them both.
	 */
	if (unlikely(((addr + size - 1) & KASAN_GRANULE_MASK) < size - 1))
		return *shadow_addr || memory_is_poisoned_1(addr + size - 1);

	return memory_is_poisoned_1(addr + size - 1);
}

static __always_inline bool memory_is_poisoned_16(unsigned long addr)
{
	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow((void *)addr);

	/* Unaligned 16-bytes access maps into 3 shadow bytes. */
	if (unlikely(!IS_ALIGNED(addr, KASAN_GRANULE_SIZE)))
		return *shadow_addr || memory_is_poisoned_1(addr + 15);

	return *shadow_addr;
}

static __always_inline unsigned long bytes_is_nonzero(const u8 *start,
					size_t size)
{
	while (size) {
		if (unlikely(*start))
			return (unsigned long)start;
		start++;
		size--;
	}

	return 0;
}

static __always_inline unsigned long memory_is_nonzero(const void *start,
						const void *end)
{
	unsigned int words;
	unsigned long ret;
	unsigned int prefix = (unsigned long)start % 8;

	if (end - start <= 16)
		return bytes_is_nonzero(start, end - start);

	if (prefix) {
		prefix = 8 - prefix;
		ret = bytes_is_nonzero(start, prefix);
		if (unlikely(ret))
			return ret;
		start += prefix;
	}

	words = (end - start) / 8;
	while (words) {
		if (unlikely(*(u64 *)start))
			return bytes_is_nonzero(start, 8);
		start += 8;
		words--;
	}

	return bytes_is_nonzero(start, (end - start) % 8);
}

static __always_inline bool memory_is_poisoned_n(unsigned long addr,
						size_t size)
{
	unsigned long ret;

	ret = memory_is_nonzero(kasan_mem_to_shadow((void *)addr),
			kasan_mem_to_shadow((void *)addr + size - 1) + 1);

	if (unlikely(ret)) {
		unsigned long last_byte = addr + size - 1;
		s8 *last_shadow = (s8 *)kasan_mem_to_shadow((void *)last_byte);

		if (unlikely(ret != (unsigned long)last_shadow ||
			((long)(last_byte & KASAN_GRANULE_MASK) >= *last_shadow)))
			return true;
	}
	return false;
}

static __always_inline bool memory_is_poisoned(unsigned long addr, size_t size)
{
	if (__builtin_constant_p(size)) {
		switch (size) {
		case 1:
			return memory_is_poisoned_1(addr);
		case 2:
		case 4:
		case 8:
			return memory_is_poisoned_2_4_8(addr, size);
		case 16:
			return memory_is_poisoned_16(addr);
		default:
			BUILD_BUG();
		}
	}

	return memory_is_poisoned_n(addr, size);
}

static __always_inline bool check_region_inline(unsigned long addr,
						size_t size, bool write,
						unsigned long ret_ip)
{
	if (!kasan_arch_is_ready())
		return true;
	memorizer_mem_access(addr, size, write, ret_ip);

	if (unlikely(size == 0))
		return true;

	if (unlikely(addr + size < addr))
		return !kasan_report(addr, size, write, ret_ip);

	if (unlikely((void *)addr <
		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
		return !kasan_report(addr, size, write, ret_ip);
	}

	if (likely(!memory_is_poisoned(addr, size)))
		return true;

	return !kasan_report(addr, size, write, ret_ip);
}

bool kasan_obj_alive(const void *p, unsigned int size)
{
	if (unlikely((void *)p <
		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
		return false;
    }
	if (likely(!memory_is_poisoned((unsigned long)p, size)))
		return true;
    return false;
}

/* Memorizer-introduced function to classify an access based on the
   metadata in shadow space made available by KASAN. It returns the
   shadow value type that it finds. See kasan.h for the possible
   values. With the current design, it will return 0x00 if the obj
   is larger than a page. This might make it unsuitable for heap
   objects, but for stacks and globals it should be very accurate.
   Now deprecated, see new implementation below.*/
u8 detect_access_kind(void * p){

    /* get shadow info for access address */
    u8 shadow_val = *(u8 *)kasan_mem_to_shadow(p);
    const void *first_poisoned_addr = p;

    /* We now search for a shadow value. We search both forwards and
       backwards without leaving the current page so we don't trigger
       any invalid accesses. This may fail if there really is an obj
       larger than a page, but for now we will accept these as losses.
       That should be very rare for stacks/globals. A possible
       extension is searching beyond 1 page, but first checking to see
       if that will be valid.  */
    // Calculate the page-aligned address we are on
    void * p_aligned = (void *)( (long) p & (~((1 << PAGE_SHIFT) - 1)));
    // Calculate the max forwards search distance
    long search_size = (long) (p_aligned + PAGE_SIZE - p);
    // Search forwards
    while (shadow_val < KASAN_GRANULE_SIZE && first_poisoned_addr < p + search_size) {
        first_poisoned_addr += KASAN_GRANULE_SIZE;
        shadow_val = *(u8 *)kasan_mem_to_shadow(first_poisoned_addr);
    }

    // If no hit, search backwards too. Stay higher than p_aligned
    first_poisoned_addr = p;
    while (shadow_val < KASAN_GRANULE_SIZE && first_poisoned_addr > (p_aligned + KASAN_GRANULE_SIZE)) {
        first_poisoned_addr -= KASAN_GRANULE_SIZE;
        shadow_val = *(u8 *)kasan_mem_to_shadow(first_poisoned_addr);
    }

    return shadow_val;
}

// Another variant of this logic. Still debugging.
u8 detect_access_kind_alt(void * p){

  // Calculate page-aligned address
  void * p_aligned = (void *) ((unsigned long) p & (~((1 << PAGE_SHIFT) - 1)));

  // Initialize shadow pointer and current shadow value
  u8* shadow_ptr = kasan_mem_to_shadow(p_aligned);
  u8 shadow_val = *shadow_ptr;

  // Set maximum search distance
  u8* search_max = kasan_mem_to_shadow(p_aligned + 1*PAGE_SIZE);
  /* Search until we (1) find a valid shadow type identifier, (2)
     exceed the max search distance, or (3) would go beyond end of
     shadow space.
     Note that shadow values that are nonzero but less than
     KASAN_SHADOW_SCALE encode a partial red zone, and you need
     to look at the next byte to get the kind. */
  while (shadow_val < KASAN_GRANULE_SIZE &&
	 shadow_ptr < search_max &&
	 shadow_ptr < (u8 *)KASAN_SHADOW_END){
    shadow_ptr++;
    shadow_val = *shadow_ptr;
  }
  return shadow_val;
}

enum AllocType kasan_obj_type(const void *p, unsigned int size)
{
    /* If we are below the Kernel address space */
	if (p < kasan_shadow_to_mem((void *)KASAN_SHADOW_START)) {
        /* our pointer is to page 0... null ptr */
		if ((unsigned long)p < PAGE_SIZE)
            return MEM_BUG;
        /* our pointer is in 0 to User space end addr range  */
		else if ((unsigned long)p < TASK_SIZE)
            return MEM_USER;
        /* crazy other stuff */
		else
            return MEM_BUG;
    } else {
        /* get shadow info for access address */
        u8 shadow_val = detect_access_kind((void *)p);
        switch(shadow_val)
        {
            case KASAN_PAGE_REDZONE:
                return MEM_ALLOC_PAGES;
            case KASAN_KMALLOC_REDZONE:
                return MEM_HEAP;
            case KASAN_GLOBAL_REDZONE:
                return MEM_GLOBAL;
            case KASAN_STACK_LEFT:
            case KASAN_STACK_MID:
            case KASAN_STACK_RIGHT:
            case KASAN_STACK_PARTIAL:
                return MEM_STACK_PAGE;
            default:
	      /* There are some global objects that are not registered by KASAN.
		 We can use the section that the address is in to classify it
		 as an unknown global. We'll count anything in rodata, data or bss.
		 Very strangely, only a few of the section starts and ends are defined
		 constants. I wish they were all defined...
		 For now, taking the beginning of rodata to the end of bss as unknown
		 global. There are some other sections in there, but we shouldn't
		 be getting data accesses to them. In the future we could split these
		 down more finely if we want to.
	      */
	      if (p >= (const void *)__start_rodata && p <= (const void *)(__bss_start + 0x01fea000)){
			return MEM_GLOBAL;
	      }
	      return MEM_NONE;
        }
    }
}

bool kasan_check_range(unsigned long addr, size_t size, bool write,
					unsigned long ret_ip)
{
	return check_region_inline(addr, size, write, ret_ip);
}

bool kasan_byte_accessible(const void *addr)
{
	s8 shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));

	return shadow_byte >= 0 && shadow_byte < KASAN_GRANULE_SIZE;
}

void kasan_cache_shrink(struct kmem_cache *cache)
{
	kasan_quarantine_remove_cache(cache);
}

void kasan_cache_shutdown(struct kmem_cache *cache)
{
	if (!__kmem_cache_empty(cache))
		kasan_quarantine_remove_cache(cache);
}

static void register_global(struct kasan_global *global)
{
	size_t aligned_size = round_up(global->size, KASAN_GRANULE_SIZE);

	kasan_unpoison(global->beg, global->size, false);

	kasan_poison(global->beg + aligned_size,
		     global->size_with_redzone - aligned_size,
		     KASAN_GLOBAL_REDZONE, false);
	#ifdef CONFIG_MEMORIZER
	memorizer_register_global(global->beg, global->size);
	int written = sprintf(global_table_ptr, "%p %d %s %s\n", global -> beg,
			      (int)(global -> size), (char *)(global -> name), (char *)(global -> module_name));
	global_table_ptr += written;
	#endif
}

void __asan_register_globals(struct kasan_global *globals, size_t size)
{
	int i;

	for (i = 0; i < size; i++)
		register_global(&globals[i]);
}
EXPORT_SYMBOL(__asan_register_globals);

void __asan_unregister_globals(struct kasan_global *globals, size_t size)
{
}
EXPORT_SYMBOL(__asan_unregister_globals);

#define DEFINE_ASAN_LOAD_STORE(size)					\
	void __asan_load##size(unsigned long addr)			\
	{								\
		check_region_inline(addr, size, false, _RET_IP_);	\
	}								\
	EXPORT_SYMBOL(__asan_load##size);				\
	__alias(__asan_load##size)					\
	void __asan_load##size##_noabort(unsigned long);		\
	EXPORT_SYMBOL(__asan_load##size##_noabort);			\
	void __asan_store##size(unsigned long addr)			\
	{								\
		check_region_inline(addr, size, true, _RET_IP_);	\
	}								\
	EXPORT_SYMBOL(__asan_store##size);				\
	__alias(__asan_store##size)					\
	void __asan_store##size##_noabort(unsigned long);		\
	EXPORT_SYMBOL(__asan_store##size##_noabort)

DEFINE_ASAN_LOAD_STORE(1);
DEFINE_ASAN_LOAD_STORE(2);
DEFINE_ASAN_LOAD_STORE(4);
DEFINE_ASAN_LOAD_STORE(8);
DEFINE_ASAN_LOAD_STORE(16);

void __asan_loadN(unsigned long addr, size_t size)
{
	kasan_check_range(addr, size, false, _RET_IP_);
}
EXPORT_SYMBOL(__asan_loadN);

__alias(__asan_loadN)
void __asan_loadN_noabort(unsigned long, size_t);
EXPORT_SYMBOL(__asan_loadN_noabort);

void __asan_storeN(unsigned long addr, size_t size)
{
	kasan_check_range(addr, size, true, _RET_IP_);
}
EXPORT_SYMBOL(__asan_storeN);

__alias(__asan_storeN)
void __asan_storeN_noabort(unsigned long, size_t);
EXPORT_SYMBOL(__asan_storeN_noabort);

/* to shut up compiler complaints */
void __asan_handle_no_return(void) {}
EXPORT_SYMBOL(__asan_handle_no_return);

/* Emitted by compiler to poison alloca()ed objects. */
void __asan_alloca_poison(unsigned long addr, size_t size)
{
	size_t rounded_up_size = round_up(size, KASAN_GRANULE_SIZE);
	size_t padding_size = round_up(size, KASAN_ALLOCA_REDZONE_SIZE) -
			rounded_up_size;
	size_t rounded_down_size = round_down(size, KASAN_GRANULE_SIZE);

	const void *left_redzone = (const void *)(addr -
			KASAN_ALLOCA_REDZONE_SIZE);
	const void *right_redzone = (const void *)(addr + rounded_up_size);

	WARN_ON(!IS_ALIGNED(addr, KASAN_ALLOCA_REDZONE_SIZE));

	kasan_unpoison((const void *)(addr + rounded_down_size),
			size - rounded_down_size, false);
	kasan_poison(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
		     KASAN_ALLOCA_LEFT, false);
	kasan_poison(right_redzone, padding_size + KASAN_ALLOCA_REDZONE_SIZE,
		     KASAN_ALLOCA_RIGHT, false);
}
EXPORT_SYMBOL(__asan_alloca_poison);

/* Emitted by compiler to unpoison alloca()ed areas when the stack unwinds. */
void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom)
{
	if (unlikely(!stack_top || stack_top > stack_bottom))
		return;

	kasan_unpoison(stack_top, stack_bottom - stack_top, false);
}
EXPORT_SYMBOL(__asan_allocas_unpoison);

/* Emitted by the compiler to [un]poison local variables. */
#define DEFINE_ASAN_SET_SHADOW(byte) \
	void __asan_set_shadow_##byte(const void *addr, size_t size)	\
	{								\
		__memset((void *)addr, 0x##byte, size);			\
	}								\
	EXPORT_SYMBOL(__asan_set_shadow_##byte)

DEFINE_ASAN_SET_SHADOW(00);
DEFINE_ASAN_SET_SHADOW(f1);
DEFINE_ASAN_SET_SHADOW(f2);
DEFINE_ASAN_SET_SHADOW(f3);
DEFINE_ASAN_SET_SHADOW(f5);
DEFINE_ASAN_SET_SHADOW(f8);

void kasan_record_aux_stack(void *addr)
{
	struct page *page = kasan_addr_to_page(addr);
	struct kmem_cache *cache;
	struct kasan_alloc_meta *alloc_meta;
	void *object;

	if (is_kfence_address(addr) || !(page && PageSlab(page)))
		return;

	cache = page->slab_cache;
	object = nearest_obj(cache, page, addr);
	alloc_meta = kasan_get_alloc_meta(cache, object);
	if (!alloc_meta)
		return;

	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
}

void kasan_set_free_info(struct kmem_cache *cache,
				void *object, u8 tag)
{
	struct kasan_free_meta *free_meta;

	free_meta = kasan_get_free_meta(cache, object);
	if (!free_meta)
		return;

	kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
	/* The object was freed and has free track set. */
	*(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREETRACK;
}

struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
				void *object, u8 tag)
{
	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_KMALLOC_FREETRACK)
		return NULL;
	/* Free meta must be present with KASAN_KMALLOC_FREETRACK. */
	return &kasan_get_free_meta(cache, object)->free_track;
}
