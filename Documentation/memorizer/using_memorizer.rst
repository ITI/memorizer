===============
Using Memorizer
===============

..note::

This section is a work in progress. The instructions
and information in it might be incomplete or incorrect.

The Memorizer tool traces the allocation and utilization of kernel objects.
The gathering of a
specific set of data can be broken down to:

* `Initial Conditions`_
* `Enabling Memorizer`_
* Running `The Experiment`_
* `Disabling Memorizer`_
* `Gathering`_ and `Transferring`_ the data

Initial Conditions
==================

The initial condition depends upon the details of the specific
experiment being run. To trace all of the kernel object
allocations from the initial boot, you might need to:

* ensure that `memorizer_enabled_boot=yes` appears in
the kernel command line so that boot-time kernel object
allocations may be logged.
* ensure that `mem_log_boot=yes` or `mem_log_boot=no` appears
in the kernel command line, according to whether you
want kernel object accesses to be logged.

Conversely, if you want to start data collection
only when your test program starts, you might need to:

* Disable memorizer tracing by `echo 0 > /sys/kernel/debug/memorizer/memorizer_enabled`.
* Get rid of all previously-collected data by `echo 1 > /sys/kernel/debug/clear_dead_objects`

Non-streaming experiment
========================

Memorizer starts when gather data whenever `memorizer_enabled` has a
non-zero value.  The control file `memorizer_enabled` accepts
several different command values:

* `0` - turn off memorizer
* `1` - enable memorizer for the entire system
* `2` - enable memorizer for the current process, its subsequently
  created child processes, plus all interrupt contexts
* `3` - enable memorizer for the current process and its
  subsequently created child processes
* pid - enable memorizer for the indicated process and its
  subsequently created child processes

Some process-specific non-streaming experiments run this::

echo 3 > /sys/kernel/debug/memorizer/memorizer_enabled
whatever-command-we-are-testing --foo bar
echo 0 > /sys/kernel/debug/memorizer/memorizer_enabled
ssh server sh -c "cat > /tmp/kmap" < /sys/kernel/debug/memorizer/kmap 

That code first enables memorizer's data-gathering function with `echo 3`.
Whatever shell is running the `echo` command will be marked as
memorizable. All of that shell's subsequently created child processes 
will be similarly marked upon their creation.

Next the code performs your test. You can run almost any command
at this step.

We disable memorizer with `echo 0`. Otherwise, memorizer would continue
to gather data unrelated to the experiment. For example, the `cat`
and `ssh` processes will both be marked memorizable.

Finally we capture the data. You may copy the data out of the `kmap`
file any way you see fit. Here we are copying the data to a
file server.


Streaming experiment
====================

In contrast to the previous process memorizer can also
provide its kmap data in real time. Reading `kmap_stream`
provides data about kernel objects that have completed their
life cycle. Additionally, reading `kmap_stream` will destroy
memorizer's record of that kernel object, thus freeing
memorizer memory to use for future kernel object tracing.

To gather data synchronously, one might do this:

  # Either of the following commands will trigger the
  # streaming feature.

  cat /sys/kernel/debug/memorizer/kmap_stream > /tmp/kmap_data.txt
  #nc server 9999 < /sys/kernel/debug/memorizer/kmap_stream

  # Run the experiment:
  sh -c "echo 3 > /sys/kernel/debug/memorizer_enabled && test-program"

This shell script enables the streaming feature by reading
from the file `kmap_stream`. Note that the `cat` or `nc` command
will run "forever". The `kmap_stream` file never indicates an
end-of-file condition. If there is no more data, the `read()` syscall
will block waiting for more data to appear.

..note::

There may be information about previously-allocated (and freed)
kernel objects.  If so, that data will be streamed immediately,
regardless of the state of `memorizer_enabled`.

Next it runs the experiment. Note that the process running `sh` will
be marked as memorizable, along with `test-program` and any processes
that `test-program` might spawn. Since the shell process is ephemeral
(it exits synchronously with `test-program`'s exit), there will be
no memorizable processes when the command finishes.


Interpreting Results
====================

TBD, but this is explained elsewhere.
