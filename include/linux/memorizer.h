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
 *===------------------------------------------------------------------------===
 *
 *       Filename:  memorizer.h
 *
 *    Description:  Memorizer records data for kernel object lifetime analysis.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _LINUX_MEMORIZER_H
#define _LINUX_MEMORIZER_H

#include <linux/types.h>

#if 1
#define FILTER_KASAN 1
#endif

/**
 * struct memorizer_kobj - metadata for kernel objects
 */
enum AllocType {
    MEM_STACK=0,
    MEM_STACK_FRAME,
    MEM_STACK_ARGS,
    MEM_STACK_PAGE,
    MEM_HEAP,
    MEM_UFO_HEAP,
    MEM_GLOBAL,
    MEM_KMALLOC,
    MEM_KMALLOC_ND,
    MEM_KMEM_CACHE,
    MEM_KMEM_CACHE_ND,
    MEM_VMALLOC,
    MEM_ALLOC_PAGES,
    MEM_INDUCED,
    MEM_BOOTMEM,
    MEM_MEMBLOCK,
    MEM_UFO_MEMBLOCK,
    MEM_MEMORIZER,
    MEM_MZ_USER,
    MEM_BUG,
    MEM_UFO_GLOBAL,
    MEM_UFO_NONE,
    /* TODO: Legacy type, fix in tracking code to not use */
    MEM_NONE,
    NumAllocTypes
};

/* Storage for global metadata table. Used for offline processing of globals */
extern char * global_table_text;
extern char * global_table_ptr;

/* Special value to indicate the alloc_ip of preallocated objects */
#define MEMORIZER_PREALLOCED 0xfeedbeef

#ifdef CONFIG_MEMORIZER /*----------- !CONFIG_MEMORIZER -------------------- */

/* Special codes */
enum MEMORIZER_CODES {
    /* Assume this is the compiler but don't know */
    MEM_KASAN_N = 0x5, /* for KASAN with no ret ip */
};

/* Init and Misc */
void __init memorizer_init(void);
void memorizer_alloc_init(void);

/* Memorize access */
void memorizer_mem_access(uintptr_t addr, size_t size, bool write, uintptr_t ip);

/* Allocation memorization */
void memorizer_kmalloc(unsigned long call_site, const void *ptr, size_t
              bytes_req, size_t bytes_alloc, gfp_t gfp_flags);
void memorizer_kmalloc_node(unsigned long call_site, const void *ptr, size_t
               bytes_req, size_t bytes_alloc, gfp_t gfp_flags, int
               node);
void memorizer_kfree(unsigned long call_site, const void *ptr);
void memorizer_alloc_pages(unsigned long call_site, struct page *page, unsigned
        int order, gfp_t gfp_flags);
void memorizer_alloc_pages_exact(unsigned long call_site, void * ptr, unsigned int size, gfp_t gfp_flags);
void memorizer_alloc_getfreepages(unsigned long call_site, struct page *page, unsigned
        int order, gfp_t gfp_flags);

void memorizer_start_getfreepages(void);

void memorizer_free_pages(unsigned long call_site, struct page *page, unsigned
              int order);

void memorizer_kmem_cache_alloc(unsigned long call_site, const void *ptr,
        struct kmem_cache *s, gfp_t gfp_flags);
void memorizer_kmem_cache_alloc_node (unsigned long call_site, const void *ptr,
        struct kmem_cache *s, gfp_t gfp_flags, int node);
bool memorizer_kmem_cache_set_alloc(unsigned long call_site, const void *ptr);

void memorizer_kmem_cache_free(unsigned long call_site, const void *ptr);
void memorizer_vmalloc_alloc(unsigned long call_site, const void *ptr, unsigned long size, gfp_t gfp_flags);
void memorizer_vmalloc_free(unsigned long call_site, const void *ptr);
void memorizer_register_global(const void *ptr, size_t size);
void memorizer_stack_alloc(unsigned long call_site, const void *ptr, size_t
        size);
void memorizer_alloc(unsigned long call_site, const void *ptr, size_t size,
             enum AllocType AT);
void memorizer_fork(struct task_struct *p, long nr);
void memorizer_print_stats(void);
void memorizer_stack_page_alloc(struct task_struct * task);
void memorizer_alloc_bootmem(unsigned long call_site, void * v, uint64_t size);
void memorizer_memblock_alloc(phys_addr_t base, phys_addr_t size);

/* Temporary Debug and test code */
int __memorizer_get_opsx(void);
int __memorizer_get_allocs(void);
void __memorizer_print_events(unsigned int num_events);

#else /*----------- !CONFIG_MEMORIZER ------------------------- */

static inline void __init memorizer_init(void) {}
static inline void memorizer_alloc_init(void) {}
static inline void memorizer_mem_access(uintptr_t addr, size_t size, bool write, uintptr_t ip) {}
static inline void __memorizer_get_opsx(void) {}
static inline void __memorizer_print_events(unsigned int num_events) {}
static inline void memorizer_kmalloc(unsigned long call_site, const void *ptr, size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags) {}
static inline void memorizer_kmalloc_node(unsigned long call_site, const void *ptr, size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags, int node) {}
static inline void memorizer_kfree(unsigned long call_site, const void *ptr) {}
static inline void memorizer_alloc_pages(unsigned long call_site, struct page *page, unsigned int order, gfp_t gfp_flags) {}
static inline void memorizer_alloc_pages_exact(unsigned long call_site, void * ptr, unsigned int size, gfp_t gfp_flags){}
static inline void memorizer_free_pages(unsigned long call_site, struct page *page, unsigned int order) {}
static inline void memorizer_kmem_cache_alloc(unsigned long call_site, const void *ptr, size_t bytes_alloc, gfp_t gfp_flags) {}
static inline bool memorizer_kmem_cache_set_alloc(unsigned long call_site, const void *ptr){return true;}
static inline void memorizer_kmem_cache_alloc_node (unsigned long call_site, const void *ptr, struct kmem_cache *s, gfp_t gfp_flags, int node) {}
static inline void memorizer_kmem_cache_free(unsigned long call_site, const void *ptr) {}
static inline void memorizer_vmalloc_alloc(unsigned long call_site, const void *ptr, unsigned long size, gfp_t gfp_flags) {}
static inline void memorizer_vmalloc_free(unsigned long call_site, const void *ptr) {}
static inline void memorizer_register_global(const void *ptr, size_t size) {}
static inline void memorizer_alloc(unsigned long call_site, const void *ptr,
                   size_t size, enum AllocType AT){}
static inline void memorizer_fork(struct task_struct *p, long nr) {}
static inline void memorizer_print_stats(void) {}
static inline void memorizer_stack_page_alloc(struct task_struct * task){}
static inline void memorizer_stack_alloc(unsigned long call_site, const void *ptr, size_t size){}
static inline void memorizer_alloc_bootmem(unsigned long call_site, void * v, uint64_t size){}
static inline void memorizer_memblock_alloc(unsigned long base, unsigned long size){}
static inline void memorizer_alloc_getfreepages(unsigned long call_site, struct page *page, unsigned
                        int order, gfp_t gfp_flags){}

static inline void memorizer_start_getfreepages(void){}

#endif /* CONFIG_MEMORIZER */

#endif /* __MEMORIZER_H_ */
