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
 *       Filename:  memorizer.h
 *
 *    Description:  General inclues and utilities for memorizer tracing
 *                  framework.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef __MEMORIZER_H_
#define __MEMORIZER_H_

#include <linux/gfp.h>

/* mask to apply to memorizer allocations TODO: verify the list */
#define gfp_memorizer_mask(gfp)	((GFP_ATOMIC | __GFP_NOTRACK | __GFP_NORETRY | GFP_NOWAIT))

long get_ts(void);
struct memorizer_kobj *create_kobj(uintptr_t call_site, uintptr_t ptr, uint64_t size, enum AllocType AT);
#endif /* __MEMORIZER_H_ */
