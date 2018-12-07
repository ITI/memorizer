/*===-- LICENSE
 * -------------------------------------------------------------===
 * 
 * University of Illinois/NCSA Open Source License 
 *
 * Copyright (C) 2018, The Board of Trustees of the University of Illinois.
 * All rights reserved. 
 *
 * Developed by: 
 *
 *    Research Group of Professor Vikram Adve in the Department of Computer
 *    Science The University of Illinois at Urbana-Champaign
 *    http://web.engr.illinois.edu/~vadve/Home.html
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
#define gfp_memorizer_mask(gfp)	((gfp | GFP_ATOMIC | __GFP_NOTRACK | __GFP_NORETRY) &   \
        ( GFP_ATOMIC            \
          | __GFP_NOTRACK	    \
          | __GFP_NORETRY       \
        )                       \
        )
//| __GFP_MEMALLOC	    \

/* global timestamp counter */
static atomic_t timestamp = ATOMIC_INIT(0);
static long get_ts(void) { return atomic_fetch_add(1,&timestamp); }

#endif /* __MEMORIZER_H_ */

