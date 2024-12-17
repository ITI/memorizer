==================
Reference Material
==================

.. _`memorizer-grub-cmdline`:
.. _`kernel-parameters`:
.. _`kernel-cmdline`:

Kernel Command Line Parameters
==============================

The following kernel command line parameters are either unique to Memorizer,
or are required by Memorizer. How to apply these parameters is bootloader-specific.
For ``grub``, edit the ``GRUB_CMDLINE_LINUX`` line in ``/etc/default/grub``, and run
``sudo update-grub``.

Memorizer-specific
~~~~~~~~~~~~~~~~~~

``memorizer_enabled_boot=(yes|no)``
    * ``yes`` - The memorizer data will include traces from early
      in the boot process. This is the default.
    * ``no`` - The memorizer will not trace kernel allocation or
      accesss until specifically enabled by the user.
  
``mem_log_boot=(yes|no)`` 
  * ``yes`` - If ``memorizer_enabled_boot=yes``, then the Memorizer data
    will include information about memory accesses in the initial
    boot process.

  * ``no`` - The Memorizer will not trace memory accesses until
    specifically enabled by the user. This is the default.

``cfg_log_boot=(yes|no)``
  * ``yes`` - Memorizer will create dynamic call graphs from
    the initial boot process.

  * ``no`` - Memorizer will not create dynamic call graphs from
    the initial boot process. This is the default.

``stack_trace_boot=(yes|no)``
  * ``yes`` - include ``RSP`` and ``RBP`` values in the
    dynamic call graph data from the initial boot
    process. Requires ``cfg_log_boot=yes``.

  * ``no`` - Memorizer will not include ``RSP`` and ``RBP`` in
    the dynamic call graph data from the initial boot. This is
    the default.


.. _`memorizer_index_type`:

``memorizer_index_type=(serial|time)``
  * ``serial`` - The ``index`` column in ``kmap`` represents
    a strictly-increasing value, incremented during each
    object allocation. The values generally do not overlap.
    This is the default.

  * ``time`` - The ``index`` column in ``kmap`` represents
    the kernel ``jiffies`` value. On x86_64 Linux, this
    is the number of milliseconds since boot. The values
    will often overlap.

``memalloc_size=#``
  At startup, memorizer reserves a significant
  portion of physical memory for its own uses.
  All kmap data is stored there before being
  retrieved via the `debugfs` file system.
  Make this number the largest you are able to,
  reserving only enough to run your experiment.
  The number is the number of GB to use,
  the suggested minimum value is 4GB. The default
  value is 8G.

Memorizer-required
~~~~~~~~~~~~~~~~~~

.. _`limiting_cpus`:

Limiting Number of CPUs (``maxcpus=1``)
  Restricts the kernel to use only one CPU, currently necessary
  since Memorizer is incompatible with multiple
  processors, ensuring stable system operation.

  Note: Memorizer can be run on SMP systems—and the ``maxcpus``
  field can be excluded from grub boot options—by using ``taskset``
  to bond Memorizer to a specified CPU. This must be done in
  combination with either mode `3`:

  * ``taskset -c <CPU_NUMBER> sh -c "echo 3 > /sys/kernel/debug/memorizer/memorizer_enabled; <PROGRAM_TO_RUN>"``
  
  or mode `pid`:

  * ``PID=<PID_NUMBER>; taskset -c <CPU_NUMBER> -p $PID; echo $PID > /sys/kernel/debug/memorizer/memorizer_enabled;``
  
  Any subsequent or related Memorizer processes must also be pinned to this 
  same CPU via ``taskset``. This includes both kmap streaming (the process 
  with ``/sys/kernel/debug/memorizer/kmap_stream`` open), and kmap reading 
  even after ``memorizer_enabled`` is set to ``0`` 
  (i.e. ``taskset -c <CPU_NUMBER> cp /sys/kernel/debug/memorizer/kmap /tmp/kmap``)


Disabling Split Lock Detection (``split_lock_detect=off``)
  Disables the split lock detection feature, enhancing system
  stability and speed.

Disabling Hash Pointers (``no_hash_pointers``)
  As a security measure, Linux anonymizes all pointer
  values before printing them to the console. We
  turn that feature off so that data analysis tools
  can correlate code pointers with source code.

Disabling Kernel Address Space Layout Randomization (``nokaslr``)
  As a security measure, Linux can be loaded
  into randomly-generated virtual memory addresses.
  We turn that feature off so that the data analysis
  tools can correlate code pointers with source code.

Disabling Audit Feature (``audit=0``)
  Turns off the audit feature, reducing overhead and improving
  system performance by not recording audit logs.

Setting Log Level (``loglevel=8``)
  Sets the kernel log level to the most verbose level, useful for
  debugging as it provides detailed kernel messages.
  As part of memorizer development, we always run
  at a high log level. Your needs may be different.

Configuring Console Output (``console=tty0`` and ``console=ttyS0``)
  These are not strictly required for Memorizer. If you are using
  Qemu to run Memorizer, these provide convenient access to the
  virtualized console.

  - ``console=tty0``: Directs kernel messages to the first virtual
    console.
  - ``console=ttyS0``: Directs kernel messages to the first serial
    port, particularly useful for systems requiring serial console
    access, such as remote debugging.


Using the Grub syntax, here is a working example of a Memorizer kernel command line::

  GRUB_CMDLINE_LINUX="memorizer_enabled_boot=no maxcpus=1 split_lock_detect=off no_hash_pointers nokaslr audit=0 loglevel=8 memalloc_size=4”

Memorizer Kernel Config Variables
=================================
Memorizer kernel config variable definitions can be found in ``/lib/Kconfig.debug`` and ``/lib/Kconfig``. 
These values are set at build-time.

Config Variables
~~~~~~~~~~~~~~~~
``MEMORIZER``
  Boolean, enables/disables the Memorizer tool. Memorizer traces the memory allocations of kernel objects to track patterns across an object's lifetime.

``MEMORIZER_STATS``
  Boolean, enables/disables the Memorizer statistics summary. The statistics summary includes the number of accesses and shadow objects allocated for Memorizer which will slow down the performance of the system.

``MEMORIZER_TRACKPIDS``
  Boolean, enables/disables the segregation of memory access counts by process id (PID) within Memorizer data.

``MEMORIZER_DEBUGFS_RAM``
  Boolean, enables/disables the exposure of Memorizer's buffer via a debugfs file.

``INLINE_LIBS``
  Boolean, forces gcc to use inline calls for some library functions. This must be enabled to run Memorizer.

Dependencies
~~~~~~~~~~~~
``KASAN``
  Boolean, enables/disables Kernel Address Sanitizer (KASAN). This is an error detector designed to find out-of-bounds and use-after-free bugs in dynamic memory. This must be enabled to run Memorizer.

.. _`debugfs-files`:

Memorizer ``debugfs`` files
===========================

Memorizer provides control, data, and status values through the
Linux ``debugfs`` filesystem.  The ``debugfs`` filesystem is
conventionally mounted at ``/sys/kernel/debug/`` and the Memorizer
files are in the ``/sys/kernel/debug/memorizer/`` directory.
Memorizer files are in the ``/sys/kernel/debug/memorizer/`` directory,
with the single exception of ``/proc/<pid>/memorizer_enabled``.

Control Files
~~~~~~~~~~~~~

``clear_dead_objects``
  - `WRITE` - Clear Memorizer's tracking information of any object
    that has completed its lifecycle (i.e. has been freed),
    regardless of whether that data has been reported.
    The value written is not used for anything.
  - `READ` - n/a

``clear_printed_objects``
  - `WRITE` - Clear Memorizer's tracking information of any object
    that has completed its lifecycle (i.e. has been freed), but
    only if that data has been previously reported via ``kmap``.
    The value written is not used for anything.
  - `READ` - n/a

``clear_function_calls``
  - `WRITE` - Clear Memorizer's tracking information for the
    dynamic call graph. The value written is not used for
    anything.
  - `READ` - n/a

``memorizer_enabled``
  - `WRITE` - Set the current Memorizer mode.
    Memorizer gathers data whenever ``memorizer_enabled`` has a
    non-zero value.  The control file ``memorizer_enabled`` accepts
    several different command values:

    * `0` - turn off memorizer
    * `1` - enable memorizer for the entire system
    * `2` - enable memorizer for the current process, its subsequently
      created child processes, plus all interrupt contexts
    * `3` - enable memorizer for the current process and its
      subsequently created child processes, ignoring any
      non-process-context activity.
    * `pid` - enable memorizer for the indicated process and its
      subsequently created child processes

    Note that writing ``0`` to ``memorizer_enabled`` turns off
    Memorizer kernel object tracing immediately. Until some
    other value is written, Memorizer gathers no data whatsoever.

    Processes that were marked as memorizable are still marked even
    after ``memorizer_enabled`` is ``0``. If, later, Memorizer is
    re-enabled, then those processes will be traced.

  - `READ` - The current Memorizer mode and, optionally, the
    process-id of a Memorizer-enabled process.

``/proc/<pid>/memorizer_enabled``
  - `WRITE` - Set or clear the memorizable status of the indicated
    `process`. If a process is memorizable and memorizer is in mode
    ``2`` or ``3``, then the process and all of its subsequently created
    child processes will be tracked.
    This value is unused in modes ``0`` and ``1``.
  - `READ` - The current memorizable status of the indicated process.

``log_accesses_enabled``
  - `WRITE` - Writing any boolean value enables or disables the tracing
    of memory reads and writes.
    Valid values include `yes`, `no`, `true`, `false`, `on`, `off`,
    `1`, and `0`.  Requires `memorizer_enabled` to be set.
  - `READ` - The current status is returned.

``log_calls_enabled``
  - `WRITE` - Writing any boolean value enables or disables
    the tracing of function calls for the dynamic call graph.
  - `READ` - The current status is returned.

``log_frames_enabled``
  - `WRITE` - Writing any boolean value enables or disables the tracing
    of function calls with ``RSP`` and ``RBP`` recorded for the dynamic
    call graph.
  - `READ` - The current status is returned.

  .. note::
    ``log_calls_enabled`` and ``log_frames_enabled``
    share the same ``<caller, callee>`` mapping structure. Please
    choose either one to turn on and clean the cfgmap after finished.

``log_live_enabled``
  - `WRITE` - Writing any boolean value affects the reporting of live
    kernel objects. If `true`, all tracked kernel objects are reported. If
    `false`, only freed objects are reported. This does not affect the
    tracking itself, only the reporting.
  - `READ` - The current status is returned.

``verbose_warnings_enabled``
  - `WRITE` - Writing any boolean value affects the reporting of
    certain internal errors. If `true`, these errors invoke
    ``WARN()``. Otherwise, they invoke ``pr_warn()``.
  - `READ` - The current status is returned.



Data Files
~~~~~~~~~~

These files are all read-only. Any writes to these files will return an error.

.. note::
  The networking program ``scp`` is incompatible with these files. If you
  need to network-copy these files, each of these methods work::

    cat kmap | ssh user@server sh -c "cat > /tmp/kmap"
    cp kmap /tmp/kmap && scp /tmp/kmap user@server:/tmp/kmap
    Client: nc <server> <port> < kmap;  and server: nc -l -k -p <port> > /tmp/kmap

``kmap``
  - `READ` - Returns current Memorizer data. If ``log_live_enabled`` is
    false, returns only information on freed objects. 
    For more information on the data format, see :ref:`debugfs-kmap`

``kmap_stream``
  - `READ` - Returns current Memorizer data in a way convenient for
    network streaming. It only returns data on freed objects, regardless
    of the setting ``log_live_enabled``. When the data is exhausted,
    Memorizer does not return an EOF condition, but waits for more
    data instead. Programs that read from ``kmap_stream`` typically
    never exit and must be signaled via Control-C or the ``kill`` command.
    For more information on the data format, see :ref:`debugfs-kmap-stream`.

``allocations``
  - `READ` - Returns Memorizer information, limited to information
    about object allocations and frees.  If ``log_live_enabled`` is
    ``false``, returns only information on freed objects. 
    For more information on the data format, see :ref:`debugfs-allocations`

``accesses``
  - `READ` - Returns Memorizer information, limited to information
    about object memory accesses.  If ``log_live_enabled`` is
    ``false``, returns only information on freed objects. 
    For more information on the data format, see :ref:`debugfs-accesses`

``function_calls``
  - `READ` - TBD

``global_table``
  - `READ` - TBD

``memalloc_ram``
  - `READ` - Returns a binary image of the initial Memorizer
    memory allocation. This is an experimental feature, provided
    for research into avoiding the text-format overhead.
    This feature is enabled by ``CONFIG_MEMORIZER_DEBUGFS_RAM``.

Status Files
~~~~~~~~~~~~

``stats``
  Reading this file generates human-readable statistical data
  about the current state of Memorizer. For more information,
  see :ref:`debugfs-stat`.


File Formats
============

.. _`debugfs-stat`:

``stat``
~~~~~~~~

blah.

.. _`debugfs-kmap-stream`:
.. _`debugfs-kmap`:

``kmap`` and ``kmap_stream``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::

  The data files ``kmap`` and ``kmap_stream`` are formatted identically.

Memorizer outputs data as text. The format of the ``kmap`` file is as follows::

  alloc_ip,pid,obj_va_ptr,size,alloc_index,free_index,free_ip,alloc_type,command,slabname,new_alloc_type
    access_ip,write_count,read_count,access_pid
    access_ip,write_count,read_count,access_pid
    access_ip,write_count,read_count,access_pid
    ...
  ...

The longer line represents the allocation and destruction of a kernel
object.  The shorter, indented, line represents the memory accesses of
that same object.  Each shorter line refers to the immediately preceding
long line. There may be any number of shorter lines per long line. There
may be any number of long lines in a kmap file.

``alloc_ip``
  The return instruction pointer of the ``call`` instruction which resulted
  in the allocation of the object.

  For some allocations, it is either not useful or not possible
  to describe the actual ``call`` instruction. For example, a
  statically-declared object does not have the same valloc-use-vfree
  life cycle as a dynamically-allocated object. In those case synthetic
  values are used, each with a special meaning.

  ``MEMORIZER_PREALLOCATED(0xfeedbeef)``
    This flag is used when Slub allocates new objects for a cache.
    Memorizer preallocates objects here so any accesses from constructors
    are captured correctly. This value is subsequently overwritten with
    the actual instruction pointer of the ``call`` instruction whch
    resulted in the allocation of the object.

  ``0``
    Memorizer maintains a set of general-purpose object descriptors,
    each with ``alloc_ip`` set to zero and with ``alloc_type`` set to
    a valid :ref:alloc_type value. These are used when a memory access
    occurs and the memory address is not described by an existing
    object descriptor.
    
  Other ``alloc_type`` values.
    Some memory accesses which cannot be associated with existing
    object descriptors result in the creation of new descriptors
    with ``alloc_ip`` set equal to :ref:alloc_type. These
    types include UFO_MEMBLOCK(0x14), STACK_PAGE(0x3), UFO_HEAP(0x5),
    UFO_GLOBAL(0x18), and UFO_NONE(0x19), 

``pid``
  The process ID of the process that allocated the object.

``obj_va_ptr``
  The virtual address of the allocated object.

``size``
  The size (in bytes) of the allocated object.

``alloc_index``
  The moment of the allocation of the object. The moment is
  either recorded as a time or as a sequence number.
  See `memorizer_index_type`_ for an explanation.

``free_index``
  The moment of the destruction of the object. See
  `memorizer_index_type`_ for a description.

``free_ip``
  The instruction pointer of the ``call`` instruction which destroyed the object.

  There are a few special cases:

  - If an object has been allocated but not yet freed, then ``free_ip`` is zero.
    If the object has, in fact, been freed but Memorizer did not observe
    the free, then ``free_ip`` is also zero.

  - If a subsequently allocated object exists in the same virtual addresses
    as a previously allocated, not freed, object, then Memorizer probably
    did not observe the intervening free.

    If this is the result of nested allocations, then ``free_ip`` of
    the previous allocation will have ``0xfedbeef``.

    If this occurs for some other, unknown, reason, then ``free_ip`` of
    the previous allocation will have ``0xdeadbeef``.

    In either case, the ``free_index`` of the previous alloctaion is
    set equal to the ``alloc_index`` of the subsequent allocation.

``alloc_type``
  Memorizer tracks various sorts of object allocation. This field
  gives an indication of which type this is.

  This field has several possible values. Consult the source code
  for more information on each of these:

  STACK (MEM_STACK, 0x0)
    Unused.

  STACK_FRAME (MEM_STACK_FRAME, 0x1)
    Used in the generation of call frame graphs (CFGs).This value should
    not appear in kmap.

  STACK_ARGS (MEM_STACK_ARGS, 0x2)
    Same.

  STACK_PAGE (MEM_STACK_PAGE, 0x3)
    Used to describe a kernel object allocated in a stack frame

  GEN_HEAP (MEM_HEAP, 0x4)
    Unused.

  UFO_HEAP (MEM_UFO_HEAP, 0x5)
    Unused.

  GLOBAL (MEM_GLOBAL, 0x6)
    The object is globally declared.

  KMALLOC (MEM_KMALLOC, 0x7)
    The subject allocation was from either the ``kmalloc`` or
    ``kmalloc_node`` family of allocators.

  KMALLOC_ND (MEM_KMALLOC_ND, 0x8)
    The subject allocation was from either the ``kmalloc`` or
    ``kmalloc_node`` family of allocators.

  KMEM_CACHE (MEM_KMEM_CACHE, 0x9)
    The subject allocation was from the kmem_cache_alloc family of allocators.

  KMEM_CACHE_ND (MEM_KMEM_CACHE_ND, 0xA)
    The subject allocation was from the kmem_cache_alloc family of allocators.

  KMEM_CACHE_BULK (MEM_KMEM_CACHE_BULK, 0xB)
    The subject allocation was from the kmem_cache_alloc family of allocators.

  VMALLOC (MEM_VMALLOC, 0xC)
    The subject allocation was from ``vmalloc``.

  ALLOC_PAGES (MEM_ALLOC_PAGES, 0xD)
    The subject allocation was from ``__alloc_pages``., et al.

  ALLOC_PAGES_EXACT (MEM_ALLOC_PAGES_EXACT, 0xE)
    The subject allocation was from ``alloc_pages_exact``.

  ALLOC_PAGES_GETFREEPAGES (MEM_ALLOC_PAGES_GETFREEPAGES, 0xF)
    The subject alloction was from ``__get_free_page``.

  ALLOC_PAGES_FOLIO (MEM_ALLOC_PAGES_FOLIO, 0x10)
    The subject allocation was from ``__folio_alloc``.

  INDUCED_ALLOC (MEM_INDUCED_ALLOC, 0x11)
    This object was allocated during (and, presumably as a result of)
    Memorizer itself. In order to avoid either deadlock or infinite
    recursion, we mark this object as INDUCED.

  BOOTMEM (MEM_BOOTMEM, 0x12)
    Unused.

  MEMBLOCK (MEM_MEMBLOCK, 0x13)
    This object is inside a region returned by ``memblock_insert_region``.

  UFO_MEMBLOCK (MEM_UFO_MEMBLOCK, 0x14)
    This object is inside a ``memblock_insert_region``,
    but is (incorrectly) not in the Memorizer tracking system.

  MEMORIZER (MEM_MEMORIZER, 0x15)
    This object is inside Memorizer's private memory pool.

  USER (MEM_MZ_USER, 0x16)
   This object exists in user space.

  BUG (MEM_BUG, 0x17)
    This object exists within the first page or is an address
    from which the software can infer no meaning.

  UFO_GLOBAL (MEM_UFO_GLOBAL, 0x18)
    The object is globally declared, 
    but is (incorrectly) not in the Memorizer tracking system.

  UFO_NONE (MEM_UFO_NONE, 0x19)
    Memorizer can infer no information about the object.

  NONE (MEM_NONE, 0x1A)
    Memorizer can infer no information about the object.

``command``
  The executable name, excluding the path, of the program running
  when the object was allocated. If the object was allocated
  outside of process context, the value of ``command`` will
  be either `hardirq` or `softirq`. 

``slabname``
  The name of the slab cache object associated with this object, i.e.
  the ``name`` field of ``struct kmem_cache``.  This field has the
  value `no-slab` if the cache name cannot be determined.

``new_alloc_type``
  Every allocator must, itself, be a client of a more generic
  allocator.  For example, ``kmalloc`` might gets its memory from
  ``__alloc_pages``. When that happens, the allocation kmap
  entry for the more generic allocation will include the
  ``alloc_type`` of the more specific allocation in this
  field.
  

.. _`debugfs-allocations`:
.. _`debugfs-accesses`:

``allocations`` and ``accesses`` files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Memorizer's ``allocations`` and ``accesses`` files contain
identical information to the ``kmap`` file, split into 
two files and formatted in a slightly different fashion.

``allocations`` contains all of the data from the long lines from ``kmap``.

``accesses`` contains all of the data from the short lines from ``kmap``.

In both cases, the order of the fields is subject to change and is different
from the ``kmap`` file. Each file contains a header line which describes
the fields in that file.

This format was chosen to simplify the parsing of Memorizer data::

  allocs = pd.read_csv("./allocations")
  accesses = pd.read_csv("./accesses")
