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
 * Sam King or the University of Illinois, nor the names of its contributors
 * may be used to endorse or promote products derived from this Software
 * without specific prior written permission. 
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * WITH THE SOFTWARE. 
 *
 *===-----------------------------------------------------------------------===
 *
 *       Filename:  memorizer.c
 *
 *    Description:  Memorizer is a memory tracing tool. It hooks into KASAN
 *                  events to record object allocation/frees and all
 *                  loads/stores. 
 *
 *===-----------------------------------------------------------------------===
 */

#include <linux/export.h>
#include <linux/memorizer.h>

//==-- Temporary test code --==//
static unsigned long long ops_x = 0;
uint64_t __memorizer_get_opsx(void)
{
    return ops_x;
}
EXPORT_SYMBOL(__memorizer_get_opsx);

/**
 * memorize_mem_access() - record associated data with the load or store
 * @addr:	The virtual address being accessed
 * @size:	The number of bits for the load/store
 * @write:	True if the memory access is a write (store)
 *
 * This function will memorize, ie. log, the particular data access.
 */
void memorize_mem_access(unsigned long addr, size_t size,
					       bool write)
{
	++ops_x;
}
