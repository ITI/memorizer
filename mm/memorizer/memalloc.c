/*===-- LICENSE -------------------------------------------------------------===
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
 * Filename: memalloc.c
 *
 * Description: Memorizer declares an isolated boot-time memory region and
 * use a lock before accessing the memory pointers.
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

DEFINE_RWLOCK(mem_rwlock);

/* function to let the size be specified as a boot parameter */
static int __init early_memalloc_size(char *arg)
{
	unsigned long sizeGB;
	if (!arg || kstrtoul(arg, 0, &sizeGB))
		return 0;
	memalloc_size = sizeGB << 30;
	return 1;
}
early_param("memalloc_size", early_memalloc_size);

void __init memorizer_alloc_init(void)
{
	pool_base = (uintptr_t)alloc_bootmem(memalloc_size);
	if (!pool_base)
		panic("No memorizer pool");
	pool_end = pool_base + memalloc_size;
	pool_next_avail_byte = pool_base;
}

void * memalloc(unsigned long size)
{
	unsigned long flags;
	void *va;
	write_lock_irqsave(&mem_rwlock, flags);
	va = (void *)pool_next_avail_byte;
	if (!pool_next_avail_byte)
		return 0;
	if (pool_next_avail_byte + size > pool_end)
		panic("Memorizer ran out of internal heap: add more with kernel boot flag (# is read as GB): memalloc_size=60");
	pool_next_avail_byte += size;
	write_unlock_irqrestore(&mem_rwlock, flags);
	return va;
}

void * zmemalloc(unsigned long size)
{
	unsigned long i = 0;
	void * va = memalloc(size);
	char * vatmp = va;
	for (i = 0; i < size; i++)
		vatmp[i] = 0;
	return va;
}

void print_pool_info(void)
{
	pr_info("Mempool begin: 0x%p, end: 0x%p, size:%llu GB\n", (void *)pool_base,
		(void *)pool_end, (long long unsigned int)(pool_end-pool_base)>>30);
}

bool in_pool(unsigned long va)
{
	return pool_base < va && va < pool_end;
}
