/*===-- LICENSE -------------------------------------------------------------===
 *
 * University of Illinois/NCSA Open Source License
 *
 * Copyright (C) 2018, The Board of Trustees of Rice University.
 * All rights reserved.
 *
 * Developed by:
 *
 *    Research Group of Professor Nathan Dautenhahn in the Department of Computer
 *    Science at Rice Unversity
 *    http://nathandautenhahn.com
 *
 * Copyright (c) 2018, Nathan Dautenhahn
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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * WITH THE SOFTWARE.
 *
 *===------------------------------------------------------------------------===
 *
 *       Filename:  memalloc.c
 *
 *    Description:
 *
 *===------------------------------------------------------------------------===
 */

#include <linux/bootmem.h>
#include <linux/memorizer.h>

#include "memalloc.h"

uintptr_t pool_base = 0;
uintptr_t pool_end = 0;
uintptr_t pool_next_avail_byte = 0;
unsigned long memalloc_size = MEMORIZER_POOL_SIZE;

/* function to let the size be specified as a boot parameter */
static int __init early_memalloc_size(char *arg)
{
	unsigned long sizeGB;
	if(!arg || kstrtoul(arg, 0, &sizeGB))
		return 0;
	memalloc_size = sizeGB<<30;
	return 1;
}
early_param("memalloc_size", early_memalloc_size);

void __init memorizer_alloc_init(void)
{
	pool_base = alloc_bootmem(memalloc_size);
	if(!pool_base)
		panic("No memorizer pool");
	pool_end = pool_base + memalloc_size;
	pool_next_avail_byte = pool_base;
}

void * memalloc(unsigned long size)
{
	void * va = pool_next_avail_byte;
	if(!pool_next_avail_byte)
		return 0;
	if(pool_next_avail_byte + size > pool_end)
		panic("Memorizer ran out of internal heap");
	pool_next_avail_byte += size;
	return va;
}

void * zmemalloc(unsigned long size)
{
	unsigned long i = 0;
	void * va = memalloc(size);
	char * vatmp = va;
	for(i=0;i<size;i++)
		vatmp[i] = 0;
	return va;
}

void print_pool_info(void)
{
	pr_info("Mempool begin: 0x%p, end: 0x%p, size:%llu GB\n", pool_base,
		pool_end, (pool_end-pool_base)>>30);
}

bool in_pool(unsigned long va)
{
	return pool_base < va && va < pool_end;
}
