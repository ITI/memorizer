==============
Special Topics
==============

This section is intended to provide information to people working on
the Memorizer project. For information on how to use Memorizer,
see :ref:`quick-start`.

Implementation Details
======================

Memorizer is a tool to track all the allocs, accesses and frees for
every object inside the kernel and output them as a CAPMAP, to be used
for further analysis.

Here we collect some of the information about
Memorizer's integration into the Linux kernel.
Of course, the source code itself is the final word
on Memorizer's implementation.

Registration
------------

The memorizer, if compiled into the kernel, is initialized by calling
``memorizer_init()`` from inside ``init/main.c``.
The init function sets up the data structures to be used for keeping
track of the events and kernel objects

Memorizer Hooks
---------------

The memorizer uses hooks to track events within the kernel. Allocs and
frees are hooked by adding function hooks into the individual
allocators, present of ``slub.c`` (We’re only concerned about slub for now
since that what most of the current systems use, although extending it
to other allocators (SLAB and SLOB) should be trivial. Loads and
Stores(Accesses) are tracked by using KASAN’s instrumentation for Loads
and Stores. It instruments ``__asan_load*(addr)``, and
``__asan_load*(addr)`` at the time of kernel compilation.

The following table gives a summary of all the Hooks in Memorizer(Needs
Revising):

================================================ ===================== =============== =============================================
Hook / Recording Function                        Type                  Location        Description
================================================ ===================== =============== =============================================
``kmem_cache_alloc()`` ``__memorizer_kmalloc()`` Function Call         slub.c          Records ``kmem_cache_alloc``
``kmalloc()`` ``__memorizer_kmalloc()``          Function Call         slub.c          Records ``kmalloc``
``page_alloc()`` ``__memorizer_kmalloc()``       Function Call         page_alloc.c    Records ``page_alloc`` (NEEDS FIXING)
``globals()`` ``__memorizer_kmalloc()``          Function Call         kasan.c (Check) Records globals (NEED to record Alloc Addr)
loads ``memorizer_mem_access()``                 KASAN Instrumentation kasan.c         Records loads
store ``memorizer_mem_access()``                 KASAN Instrumentation kasan.c         Records stores
``kmem_cache_free()`` ``memorizer_free_kobj()``  Function Call         slub.c          Records ``kmem_cache_free``
``kfree()`` ``memorizer_free_kobj()``            Function Call         slub.c          Records ``the kfree``
================================================ ===================== =============== =============================================

CAPMAP (aka kmap)
-----------------

The memorizer records event data and outputs it in the form of a kmap file.
For a complete description, see :ref:`debugfs-kmap`.

DebugFS layout
--------------

The memorizer uses the debugfs to communicate between the Kernel and
User Space. The DebugFS interface is present in the
``/sys/kernel/debug/memorizer`` directory and provides data, statitistics,
and control files for Memorizer.
More details are avaible in :ref:`debugfs-files`.
