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

Limiting Number of CPUs (``maxcpus=1``)
  Restricts the kernel to use only one CPU, currently necessary
  since Memorizer is incompatible with multiple
  processors, ensuring stable system operation.

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

.. _`debugfs-files`:

Memorizer ``debugfs`` files
===========================

Memorizer provides control, data, and status values through the
Linux ``debugfs`` filesystem.  The ``debugfs`` filesystem is
conventionally mounted at ``/sys/kernel/debug/`` and the Memorizer
files are in the ``/sys/kernel/debug/memorizer/`` directory.

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
    Client: nc server 9999 < kmap;  and server: nc -l 9999 > /tmp/kmap

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

.. _`debugfs-kmap`:

``kmap``
~~~~~~~~

.. note::

  The data files ``kmap`` and ``kmap_stream`` are formatted identically.

Memorizer outputs data as text. The format of the ``kmap`` file is as follows::

  alloc_ip,pid,obj_va_ptr,size,alloc_index,free_index,free_ip,alloc_type,command,slabname,new_alloc_type
    access_ip,write_count,read_count,access_pid
    access_ip,write_count,read_count,access_pid
    access_ip,write_count,read_count,access_pid
    ...
  ...

The longer line represents the allocation and destruction of a kernel object.
The shorter, indented, line represents the memory accesses of that same object.
Each shorter line refers to the immediately preceding long line. There may be
any number of shorter lines per long line. There may be any number of long lines
in a kmap file.

``alloc_ip``
  The instruction pointer of the ``call`` instruction which resulted
  in the allocation of the object.

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
  The instruction pointer of the `call` instruction which destroyed the object.

  There are a few special cases:

  - If an object has been allocated but not yet freed, then ``free_ip`` is zero.
    If the object has, in fact, been freed but Memorizer did not observe
    the free, then ``free_ip`` is also zero.

  - If a subsequently allocated object exists in the same virtual addresses
    as a previously allocated, not freed, object, then Memorizer probably
    did not observe the intervening free.

    In this case, ``free_ip`` of the previous object is ``0xdeadbeef`` and
    the ``free_index`` of the previous object is set equal to the
    ``alloc_ip`` of the subsequent object.
    ``new_alloc_type`` of the previous
    allocation is set to the ``alloc_type`` of the subsequent allocation.

  - If a subsequently allocated object has exactly the same virtual address
    as the immediately preceding allocation, this represents a
    nested allocation. In this case, ``free_ip`` is set to ``0xfedbeef``.
    ``new_alloc_type`` of the previous
    allocation is set to the ``alloc_type`` of the subsequent allocation.
    ``free_index`` of the previous allocation is set to ``alloc_index``
    of the subsequent allocation.

``alloc_type``
  Memorizer tracks various sorts of object allocation. This field
  gives an indication of which type this is.

  This field has several possible values. Consult the source code
  for information on each of these::

    STACK
    STACK_FRAME
    STACK_ARGS
    STACK_PAGE
    GEN_HEAP
    UFO_HEAP
    GLOBAL
    KMALLOC
    KMALLOC_ND
    KMEM_CACHE
    KMEM_CACHE_ND
    KMEM_CACHE_BULK
    ALLOC_PAGES
    ALLOC_PAGES_EXACT
    ALLOC_PAGES_GETFREEPAGES
    ALLOC_PAGES_FOLIO
    VMALLOC
    INDUCED_ALLOC
    BOOTMEM
    MEMBLOCK
    UFO_MEMBLOCK
    MEMORIZER
    USER
    BUG
    UFO_GLOBAL
    UFO_NONE
    NONE

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
