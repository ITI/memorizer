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
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/preempt.h>
#include <linux/bug.h>
#include <linux/jiffies.h>
#include <linux/printk.h>

#include <linux/memorizer.h>

//==-- Debugging and print information ------------------------------------==//

//==-- Temporary test code --==//
static uint64_t ops_x = 0;
uint64_t __memorizer_get_opsx(void)
{
    return ops_x;
}
EXPORT_SYMBOL(__memorizer_get_opsx);

static uint64_t memorizer_num_allocs = 0;
uint64_t __memorizer_get_allocs(void)
{
    return memorizer_num_allocs;
}
EXPORT_SYMBOL(__memorizer_get_allocs);

/**
 * __memorizer_print_events - print the last num events
 * @num_events:		The total number of events to print
 *
 * Simple print assuming an array log. Only tricky thing is to wrap around the
 * circular buffer when hitting the end or printing the last set of events if
 * some of them are at the end of the linear buffer. 
 */
void __memorizer_print_events(unsigned int num_events)
{
	int i;
	int e;

	if((log_index - num_events) > 0)
		i = log_index - num_events;
	else
		i = ARRAY_SIZE(mem_events) - (num_events - log_index + 1);

	for(e = 0; e < num_events; e++)
	{
		char *type_str[10];
		pr_info("Memorizer: access from IP 0x%p at addr 0x%p\n",
			(void *)mem_events->src_ip, mem_events->access_addr);
		switch(mem_events->event_type){
		case READ:
			*type_str = "Read\0";
			break;
		case WRITE:
			*type_str = "Write\0";
			break;
		case ALLOC:
			*type_str = "Alloc\0";
			break;
		case FREE:
			*type_str = "Free\0";
			break;
		default:
			pr_info("Unmatched event type\n");
			*type_str = "Unknown\0";
		}
		pr_info("%s of size %zu by task %s/%d\n", *type_str,
			mem_events->access_size, mem_events->comm,
			task_pid_nr(current));
		i++;
		if(i >= ARRAY_SIZE(mem_events))
			i = 0;
	}
}
EXPORT_SYMBOL(__memorizer_print_events);

//==-- Data types and structs for building maps ---------------------------==//
enum AllocType {KALLAC};
enum EventType {READ,WRITE,ALLOC,FREE};

/**
 * struct memorizer_event - structure to capture all memory related events
 * @alloc_type:	 if allocation then set the type of alloca
 * @event_type:	 type of event
 * @obj_id:	 for allocations track object identifier
 * @src_ip:	 virtual address of the invoking instruction
 * @access_addr: starting address of the operation
 * @access_size: size of the access: for wr/rd size, allocation length
 * @jiffies:	 timestamp
 * @pid:	 PID of invoking task
 * @comm:	 String of executable
 */
struct memorizer_event {
	enum AllocType alloc_type;
	enum EventType event_type;
	uint64_t obj_id;
	uintptr_t src_ip;
	uintptr_t access_addr;		/* The location being accessed */
	uint64_t access_size;		/* events can be allocs or memcpy */
	unsigned long jiffies;		/* creation timestamp */
	pid_t pid;			/* pid of the current task */
	char comm[TASK_COMM_LEN];	/* executable name */
};

/* TODO make this dynamically allocated based upon free memory */
struct memorizer_event mem_events[1000000];
uint64_t log_index = 0;

//==-- Memorizer internal implementation ----------------------------------==//

/**
 * log_event() - log the memory event
 * @addr:	The virtual address for the event start location
 * @size:	The number of bits associated with the event
 * @event_type:	The type of event to record
 * @ip:		IP of the invoking instruction
 *
 * This function records the memory event to the event log. Currently emulates a
 * circular buffer for logging the most recent set of events. TODO extend this
 * to be dynamically determined.
 */
void log_event(uintptr_t addr, size_t size, enum EventType event_type, 
	       uintptr_t ip)
{
	mem_events[log_index].access_addr = addr;
	mem_events[log_index].event_type = event_type;
	mem_events[log_index].access_size = size;
	mem_events[log_index].src_ip = ip;
	mem_events[log_index].jiffies = jiffies;

#if 0 /* NOT IMPLEMENTED YET--- BREAKS EARLY BOOT */
	/* task information */
	if (in_irq()) {
		mem_events[log_index].pid = 0;
		//strncpy(mem_events[log_index].comm, "hardirq",
		//	sizeof(mem_events[log_index].comm));
	} else if (in_softirq()) {
		mem_events[log_index].pid = 0;
		//strncpy(mem_events[log_index].comm, "softirq",
		//	sizeof(mem_events[log_index].comm));
	} else {
		mem_events[log_index].pid = current->pid;
		/*
		 * There is a small chance of a race with set_task_comm(),
		 * however using get_task_comm() here may cause locking
		 * dependency issues with current->alloc_lock. In the worst
		 * case, the command line is not correct.
		 */
		//strncpy(mem_events[log_index].comm, current->comm,
		//	sizeof(mem_events[log_index].comm));
	}
#endif

#if 0 // TODO: Working on creating a lookup function to determine if the given
	page is being used as a PTP. 
	if(is_pagetbl(addr))
	   pr_info("Memorizer: Write to PT from IP 0x%p",ip);
#endif

	if(log_index >= ARRAY_SIZE(mem_events))
		log_index = 0;
	else
		++log_index;
}

//==-- Memorizer external API for event recording -------------------------==//

/**
 * memorize_mem_access() - record associated data with the load or store
 * @addr:	The virtual address being accessed
 * @size:	The number of bits for the load/store
 * @write:	True if the memory access is a write (store)
 * @ip:		IP of the invocing instruction
 *
 * This function will memorize, ie. log, the particular data access.
 */
void memorize_mem_access(uintptr_t addr, size_t size, bool write, uintptr_t ip)
{
	++ops_x;
	enum EventType event_type = write ? WRITE : READ;
	log_event(addr, size, event_type, ip);
}

/**
 * memorize_alloc() - record allocation event
 * @object:	Pointer to the beginning of hte object
 * @size:	Size of the object
 *
 * Track the allocation and add the object to the set of active object tree.
 */
void memorize_kmalloc(const void *object, size_t size)
{
	++memorizer_num_allocs;
}

static void memorize_kfree(const void *address, size_t size){ }
void memorize_alloc_pages(struct page *page, unsigned int order) { }
void memorize_free_pages(struct page *page, unsigned int order) { }
