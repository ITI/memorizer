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
 *       Filename:  stats.h
 *
 *    Description:  
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _STATS_H_
#define _STATS_H_

#include <asm/atomic.h>
#include "kobj_metadata.h"

/* This is a flag that will macro disable stats for more efficient tracing */
#if 1
#define CONFIG_MEMORIZER_STATS 0
#endif

//==-- External Interface --==//
#ifdef CONFIG_MEMORIZER_STATS
void track_alloc(enum AllocType AT);
void track_disabled_alloc(void);
void track_induced_alloc(void);
void track_failed_kobj_alloc(void);
void track_free(void);
void track_kobj_free(void);
void track_access(void);
void track_induced_access(void);
void track_disabled_access(void);
void track_untracked_access(void);
void track_l1_alloc(void);
void track_l2_alloc(void);
void track_l3_alloc(void);
void print_stats(size_t pr_level);
int seq_print_stats(struct seq_file *seq);
#else
static inline void track_alloc(enum AllocType AT){}
static inline void track_disabled_alloc(void){}
static inline void track_induced_alloc(void){}
static inline void track_failed_kobj_alloc(void){}
static inline void track_free(void){}
static inline void track_kobj_free(void){}
static inline void track_access(void){}
static inline void track_induced_access(void){}
static inline void track_disabled_access(void){}
static inline void track_untracked_access(void){}
static inline void track_l1_alloc(void){}
static inline void track_l2_alloc(void){}
static inline void track_l3_alloc(void){}
static inline void print_stats(size_t pr_level){}
static inline int seq_print_stats(struct seq_file *seq){return 0;}
#endif

//TODO: Add kernel config option so can be disabled or add boot flag

#endif /* __STATS_H_ */

