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

#ifdef CONFIG_MEMORIZER /*----------- !CONFIG_MEMORIZER -------------------- */

/* Init and Misc */
void __init memorizer_init(void);
int memorizer_init_from_driver(void);

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
			   int order);
void memorizer_free_pages(unsigned long call_site, struct page *page, unsigned
			  int order);

void memorizer_kmem_cache_alloc(unsigned long call_site, const void *ptr, size_t
				bytes_req, size_t bytes_alloc, gfp_t gfp_flags);
void memorizer_kmem_cache_alloc_node (unsigned long call_site, const void *ptr,
				      size_t bytes_req, size_t bytes_alloc,
				      gfp_t gfp_flags, int node);
void memorizer_kmem_cache_free(unsigned long call_site, const void *ptr);
void memorizer_register_global(const void *ptr, size_t size);

/* Temporary Debug and test code */
int __memorizer_get_opsx(void);
int __memorizer_get_allocs(void);
void __memorizer_print_events(unsigned int num_events);

#else /*----------- !CONFIG_MEMORIZER ------------------------- */

static inline void __init memorizer_init(void) {}
static inline void memorizer_init_from_driver(void) {}
static inline void memorizer_mem_access(uintptr_t addr, size_t size, bool write, uintptr_t ip) {}
static inline void __memorizer_get_opsx(void) {}
static inline void __memorizer_print_events(unsigned int num_events) {}
static inline void memorizer_kmalloc(unsigned long call_site, const void *ptr, size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags) {}
static inline void memorizer_kmalloc_node(unsigned long call_site, const void *ptr, size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags, int node) {}
static inline void memorizer_kfree(unsigned long call_site, const void *ptr) {}
static inline void memorizer_alloc_pages(unsigned long call_site, struct page *page, unsigned int order) {}
static inline void memorizer_free_pages(unsigned long call_site, struct page *page, unsigned int order) {}
static inline void memorizer_kmem_cache_alloc(unsigned long call_site, const void *ptr, size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags) {}
static inline void memorizer_kmem_cache_alloc_node (unsigned long call_site, const void *ptr, size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags, int node) {}
static inline void memorizer_kmem_cache_free(unsigned long call_site, const void *ptr) {}
static inline void memorizer_register_global(const void *ptr, size_t size) {}

#endif /* CONFIG_MEMORIZER */

#endif /* __MEMORIZER_H_ */

