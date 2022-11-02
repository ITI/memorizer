/*===-- LICENSE
 * -------------------------------------------------------------===
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
 * Filename: memalloc.h
 *
 * Description: Memorizer allocates an isolated boot-time memory region for
 * storing the shadow object and lookup table.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _MEMALLOC_H_
#define _MEMALLOC_H_

/* Start with minimally 3GB region else lookup tables will fail */
#define MEMORIZER_POOL_SIZE     (_AC(1,UL) << 33)
void * memalloc(unsigned long size);
void * zmemalloc(unsigned long size);
void print_pool_info(void);
bool in_pool(unsigned long va);
#endif /* __memalloc.h_H_ */
