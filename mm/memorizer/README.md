# Memorizer
Memorizer is a tool to track all the allocs, accesses and frees for every object inside the kernel and output them as a CAPMAP, to be used for further analysis.

# Registration
The memorizer, if compiled into the kernel, is initialized by calling memorizer_init() from inside init/main.c
The init function sets up the data structures to be used for keeping track of the events and kernel objects

# Memorizer Hooks
The memorizer uses hooks to track events within the kernel.
Allocs and Frees are hooked by adding function hooks into the individual allocators, present of slub.c (We're only concerned about slub for now since that what most of the current systems use, although extending it to other allocators (SLAB and SLOB) should be trivial.
Loads and Stores(Accesses) are tracked by using KASAN's instrumentation for Loads and Stores. It instruments __asan_load*(addr), and __asan_load*(addr) at the time of kernel compilation.

The following table gives a summary of all the Hooks in Memorizer(Needs Revising):

Hook | Type | Location | Recording Function | Description
--- | --- | --- | --- | ---
kmem_cache_alloc() | Function Call | slub.c | __memorizer_kmalloc() | Records kmem_cache_alloc()
kmalloc() | Function Call | slub.c | __memorizer_kmalloc() | Records kmalloc()
page_alloc() | Funtion Call | page_alloc.c | __memorizer_kmalloc() | Records page_alloc() (NEEDS FIXING)
globals | Function Call | kasan.c (Check) | __memorizer_kmalloc() | Records globals (NEED to record Alloc Addr)
loads | KASAN Instrumentation | kasan.c | memorizer_mem_access() | Records loads
store | KASAN Instrumemtion | kasan.c | memorizer_mem_access() | Records Stores
kmem_cache_free() | Function Call | slub.c | memorizer_free_kobj() | Records kmem_cache_free()
kfree() | Function Call | slub.c | memorizer_free_kobj() | Records the kfree()

# CAPMAP
The memorizer records event data and outputs it in the form of a CAPMAP. A CAPMAP has two types of entries:

## Alloc/Free Information
These are denoted by non indented lines. Each line represents a kernel object and the information recorded is as follows:
lloc IP
* PID
* Size
* Alloc Jiffies
* Free Jiffies
* Free IP
* Common name for the Process

## Access Information
These are denoted by indented lines. Each line represents a memory location that the current memory object has accesses. The information recorded is as follows:
* Access IP
* Access PID
* Number of Writes
* Number of Reads

# DebugFS layout
The memorizer uses the debugfs to communicate between the Kernel and User Space. The DebugFS interface is present in the /sys/kernel/debug/memorizer directory and provides controls for the memorizer. The following section details the use of each file in the DebugFS directory.

## memorizer_enabled
This turns the memorizer On or Off. When the memorizer is disabled, it doesn't track any information. When enabled, it only tracks the allocs and frees. It is enabled by default during bootup.

Enabling the memorizer:
```
echo 1 > memorizer_enabled
```
Disabling the memorizer:
```
echo 0 > memorizer_enabled
```

## memorizer_log_access
This enables/disables the tracking for accesses(loads and stores). It is disabled by default during bootup. To ensure complete tracking, both memorizer_enabled and memorizer_log_access should be enabled.

Enabling access logging:
```
echo 1 > memorizer_log_access
```
Disabling access logging
```
echo 0 > memorizer_log_access
```

## kmap
The CAPMAP generated can be printed out by reading the kmap file present in the directory. This is similar in design to the trace file in ftrace. A callback has been implemented in the kernel that prints out the kmap to the stdio. The CAPMAP can be saved to the file as follows:
```
cat kmap > <path_to_file>
```

The rest of the features can be controlled the same way and their names are self explanatory. The commands are therefore omitted for brevity.
