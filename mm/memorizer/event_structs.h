/* This file describes the structs to be used to describe the events happening inside the kernel:
 * 1. ALLOCATIONS
 * 2. DEALLOCATIONS
 * 3. ACCESSES
 * 4. FORKS
 * These will be used to create stateless logs for Memorizer 2.0
 * */

#include <linux/sched.h>

/* Event and Access type  enumerations */
//enum EventType {Memorizer_Mem_Alloc = 0xaa, Memorizer_Mem_Free = 0xbb, Memorizer_Mem_Read = 0xcc, Memorizer_Mem_Write = 0xdd, Memorizer_Fork = 0xee};
enum AccessType {
    Memorizer_READ=0,
    Memorizer_WRITE,
    Memorizer_Mem_Alloc,
    Memorizer_Mem_Free,
    Memorizer_Fork,
    Memorizer_NULL
};

struct memorizer_kernel_event {
	enum AccessType event_type;
	pid_t		pid;
    union EvntData {
        struct nonfork {
            uintptr_t	src_va_ptr;
            uintptr_t	va_ptr;
            uint64_t	event_size;
        }et;
        char comm[TASK_COMM_LEN];
    }data;
};
