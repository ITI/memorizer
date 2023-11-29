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

// #include <linux/bootmem.h>
#include <linux/memblock.h>
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
	// pool_base = (uintptr_t)alloc_bootmem(memalloc_size);
	pool_base = (uintptr_t)memblock_alloc(memalloc_size, SMP_CACHE_BYTES);
	if (!pool_base)
		panic("No memorizer pool");
	pool_end = pool_base + memalloc_size;
	pool_next_avail_byte = pool_base;
}

bool is_mem_avail(unsigned long size)
{
	return !(pool_next_avail_byte + size > pool_end);
}

void * memalloc(unsigned long size)
{
	unsigned long flags;
	void *va;
	write_lock_irqsave(&mem_rwlock, flags);
	va = (void *)pool_next_avail_byte;
	if (!pool_next_avail_byte)
		return 0;
	if (pool_next_avail_byte + size > pool_end) {
		// TODO robadams@illinois.edu get rid of this extern.
		extern int memorizer_enabled;
		memorizer_enabled = 0;
		write_unlock_irqrestore(&mem_rwlock, flags);
		pr_warn("Memorizer ran out of internal heap: add more with kernel boot flag, e.g. memalloc_size=%lu", (memalloc_size>>30)*2);
		print_pool_info();
		return 0;
	}
	pool_next_avail_byte += size;
	write_unlock_irqrestore(&mem_rwlock, flags);
	return va;
}

void * zmemalloc(unsigned long size)
{
	void * va = memalloc(size);
	if (va)
		memset(va, 0, size);
	return va;
}

void print_pool_info(void)
{
	pr_info("Mempool begin: 0x%p, end: 0x%p, size:%llu GB, used=%llu MB\n",
		(void *)pool_base,
		(void *)pool_end,
		(long long unsigned int)(pool_end-pool_base)>>30,
		(long long unsigned int)(pool_next_avail_byte-pool_base)>>20);
}

bool in_pool(unsigned long va)
{
	return pool_base < va && va < pool_end;
}
