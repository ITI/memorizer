============================
Bootstrap Guide to Memorizer
============================

This is intended to be a comprehensive guide to get you started with the
Memorizer project. It is intended to be a reference for anyone working
on the project, and should contain the information needed to boot-up and
run the memorizer kernel, along with collecting and sending kmap data.

Background Information about Memorizer
======================================

Memorizer is a tool to track all the allocs, accesses and frees for
every object inside the kernel and output them as a CAPMAP, to be used
for further analysis.

Registration
------------

The memorizer, if compiled into the kernel, is initialized by calling
memorizer_init() from inside init/main.c The init function sets up the
data structures to be used for keeping track of the events and kernel
objects

Memorizer Hooks
---------------

The memorizer uses hooks to track events within the kernel. Allocs and
Frees are hooked by adding function hooks into the individual
allocators, present of slub.c (We’re only concerned about slub for now
since that what most of the current systems use, although extending it
to other allocators (SLAB and SLOB) should be trivial. Loads and
Stores(Accesses) are tracked by using KASAN’s instrumentation for Loads
and Stores. It instruments \__asan_load*(addr), and \__asan_load*(addr)
at the time of kernel compilation.

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

CAPMAP
------

The memorizer records event data and outputs it in the form of a CAPMAP.
A CAPMAP has two types of entries:

Alloc/Free Information
^^^^^^^^^^^^^^^^^^^^^^

These are denoted by non indented lines. Each line represents a kernel
object and the information recorded is as follows:

-  Alloc IP - instruction pointer that allocated the object
-  Alloc PID - PID of the process that allocated a particular object in
   memory
-  VA (virtual address) - memory location where a specific object is
   stored.
-  Size - Size of allocation in bytes
-  Alloc Time (Jiffies) - time that the object was allocated in memory
-  Free Time (Jiffies) - time that the object was freed from memory
-  Free IP - instruction pointer that freed the object
-  Allocator - Type of allocation (SLAB, kmalloc, malloc, etc.)
-  Common name for the Process
-  Slab Cache - Type of slab cache used for the allocation

Access Information
^^^^^^^^^^^^^^^^^^

These are denoted by indented lines. Each line represents a memory
location that the current memory object has accesses. The information
recorded is as follows:

* Access IP
* Access PID
* Number of Writes
* Number of Reads

DebugFS layout
--------------

The memorizer uses the debugfs to communicate between the Kernel and
User Space. The DebugFS interface is present in the
``/sys/kernel/debug/memorizer directory`` and provides controls for the
memorizer. The following section details the use of each file in the
DebugFS directory.

.. note::

   TODO robadams@illinois.edu Do we need to insert a section here?

Seting up memorizer and kernel testing
======================================

Running the test by hand consists of a couple basic steps:

1. Building the kernel
2. Building and running a VM
3. Running the test
4. Extracting the ``kmap`` file from the VM

Building the kernel
-------------------

TL;DR:

.. code:: sh

   #Download essential packages
   sudo apt update && apt -y upgrade
   sudo apt install build-essential
   sudo apt install libncurses-dev gawk flex bison libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf llvm git ncurses-dev libssl-dev autoconf-archive gnu-standards autoconfdoc libtool gettext binutils-doc bison-doc debtags menu debian-keyring flex-doc g++-multilib g++-12-multilib gcc-12-doc gawk-doc gcc-multilib gcc-doc gcc-12-multilib gcc-12-locales glibcdoc doc-base tagcoll lib32stdc++6-12-dbg libx32stdc++6-12-dbg gettext-doc autopoint libasprintf-dev libgettextpo-dev

   #Clone memorizer source code
   git clone https://code.iti.illinois.edu/ring0/memorizer.git #replace with different memorizer repo if needed
   cd memorizer
   make defconfig
   make memorizer.config
   make -j$(nproc)
   make modules
   make modules_install
   make install

The code below is if you intend to run the kernel on a physical machine.::

   # Modify your grub configuration to make it easy to select which
   # kernel to boot.  Using any text editor, add or change the
   # following lines in /etc/default/grub. e.g. nano /etc/default/grub.
   
   GRUB_TIMEOUT="5"
   GRUB_TIMEOUT_STYLE="countdown"
   GRUB_CMDLINE_LINUX="memorizer_enabled_boot=no maxcpus=1 split_lock_detect=off no_hash_pointers nokaslr audit=0 loglevel=8 memalloc_size=4 console=tty0 console=ttyS0"
   GRUB_CMDLINE_LINUX_DEFAULT=""

   #Finally, update grub
   update_grub

   #Then reboot your system
   reboot

This is a fairly standard kernel build process. The only thing that’s
different is that we need to run ``make memorizer.config`` to enable the
memorizer kernel module. This is because the memorizer module is not
enabled by default in the kernel. The ``memorizer.config`` enables the
memorizer module and disables some other things that are incompatible
with it. You can find the ``memorizer.config`` file in the
``/arch/x86/configs/memorizer.config`` directory.

Summary of GRUB Configuration Updates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- GRUB Timeout Settings:

  - Configured to provide an easy way to select which kernel to boot,
    allowing a grace period to choose a different kernel if needed.

- Kernel Command Line Arguments (``GRUB_CMDLINE_LINUX``):

  - Used to pass specific arguments to the kernel at boot time,
    modifying the kernel’s behavior for compatibility and performance.

- Disabling Memorizer Module (``memorizer_enabled_boot=no``):

  - Disables the memorizer module at boot time, useful for booting the
    kernel without the memorizer module if it causes issues.

- Limiting Number of CPUs (``maxcpus=1``):

  - Restricts the kernel to use only one CPU, currently necessary
    since the memorizer module is incompatible with multiple
    processors, ensuring stable system operation.

- Disabling Split Lock Detection (``split_lock_detect=off``):

  - Disables the split lock detection feature, enhancing system
    stability and speed.

- Disabling Hash Pointers (``no_hash_pointers``):

  - Disables the hash pointers feature, which can interfere with
    specific system operations or performance.

- Disabling Kernel Address Space Layout Randomization
  (``nokaslr``):

  - Disables Kernel Address Space Layout Randomization (KASLR),
    simplifying debugging and improving compatibility with certain
    hardware or software.

- Disabling Audit Feature (``audit=0``):

  - Turns off the audit feature, reducing overhead and improving
    system performance by not recording audit logs.

- Setting Log Level (``loglevel=8``):

  - Sets the kernel log level to the most verbose level, useful for
    debugging as it provides detailed kernel messages.

- Setting Memory Allocation Size (``memalloc_size=4``):

  - Sets the memory allocation size to 4, optimizing memory usage
    based on specific system requirements.

- Configuring Console Output (``console=tty0`` and
  ``console=ttyS0``):

  - ``console=tty0``: Directs kernel messages to the first virtual
    console.
  - ``console=ttyS0``: Directs kernel messages to the first serial
    port, particularly useful for systems requiring serial console
    access, such as remote debugging.

These updates ensure the system boots with specific configurations that
enhance compatibility, performance, and debugging capabilities.

.. note ::

  There has been some difficulties running the memorizer kernel on a
  physical machine. There has been issues with drivers for things like
  wifi or peripherals. The kernel has been tested on a VM and works fine.
  If you want to run the kernel on a physical machine, you may need to do
  some additional configurations; such as making sure all the correct
  modules are installed.

Building and running a VM
-------------------------

TL;DR:

.. code:: sh

   cd scripts/memorizer/VM
   python3 -m venv .venv
   source .venv/bin/activate
   git clone --branch v14 https://github.com/systemd/mkosi.git
   python3 -m pip install ./mkosi
   sudo mkosi build
   mkosi qemu

--------------

Now that we have a kernel, we need to run it in a VM for automated
tests. This is so we don’t have to allocate a machine specifically for
testing Memorizer and worry about the networking of that machine and
what is allowed to connect to it and whether it is physically plugged in.

QEMU needs 3 things to run: A kernel, an initrd, and an OS image. We
already have a kernel from step 1. I bashed my head against a brick wall
for a while trying to figure out how to get the other two things by
hand. Don’t do that. Just use ``mkosi``.

The file ``mkosi.conf`` contains the configuration for the image. You
want to make sure you have ``QemuHeadless=yes`` in there (or pass
``--qemu-headless=yes`` from the command line; all the options can be
passed in this way) so you don’t have to mess around with a graphical
window (which is a problem for automated tests). Other options of note
are ``QemuKvm``, which enables KVM acceleration (makes the vm faster)
and ``Ssh``, which installs ``sshd`` on the machine and generates a key
for us to log into it. Confusingly, the ``Password`` option in
``mkosi.conf`` specifies the password for that key, not for the root
account in the image.

You can build the image with ``mkosi build`` (you will probably need to
use ``sudo``. Also you might want to add the ``--force`` flag if you
want to overwrite an image you’ve already built). Once you’ve generated
the image, you can run it with ``mkosi qemu``, which generates a
horrible qemu command using the parameters in ``mkosi.conf`` so you
don’t have to worry about creating it manually.

There’s a ``mkosi.conf`` with good configuration for automated testing
in ``scripts/memorizer/testVM``. I suggest using that one as a starting
point if you’re trying to replicate this process.

So you should be able to cd ``scripts/memorizer/testVM`` and do
``mkosi build``, right? Well, probably you can, but I can’t guarantee
anything will work correctly. The problem is that different versions of
``mkosi`` have different options, and treat the files differently. So
you need to have the right version of ``mkosi`` installed. For the
configs in this project, that’s version 14. This is especially true for
the ``mkosi.conf`` in ``scripts/memorizer/VM``, which only seems to work
with that version. You can install mkosi 14 by doing:

.. code:: sh

   git clone --branch v14 https://github.com/systemd/mkosi.git
   python3 -m pip install ./mkosi

(You might want to do this in a venv if you want to avoid installing old
things in your normal Python environment. You can do this by running
``python3 -m venv .venv`` and then ``source .venv/bin/activate`` before
running the ``pip install`` command. See
`here <https://docs.python.org/3/library/venv.html>`__ for more info.)

Another note: The mkosi qemu command may not work depending on where
``bzImage`` is located. If this happens, copy the long qemu command
mkosi spits out, and change the directory for the kernel to be the
correct location of ``bzImage``, it should be somewhere around
``../arch/x86/boot/bzImage``.

Running the test
================

An example of a simple test is:

.. code:: sh

   cd /sys/kernel/debug/memorizer
   echo 1 > clear_dead_objs
   cp kmap /dev/null
   echo 1 > clear_printed_list
   echo 0 > print_live_obj
   echo 1 > memorizer_log_access
   echo 1 > memorizer_enabled
   ls -l
   echo 0 > memorizer_enabled
   echo 0 > memorizer_log_access

This should generate a file called ``kmap`` which contains information
about all the memory allocations recorded by Memorizer.

How to get the ``kmap`` file off the VM
---------------------------------------

Once we’ve run the VM and done our tests, we’ll have a ``kmap`` file. We
want to get this file out of the VM so we can look at it with other
tools. There are two ways to do this.

Loopback device
^^^^^^^^^^^^^^^

One way is to use a loopback device. Unfortunately this doesn’t work
super well for automated tests, because it requires root, and uses
kernel functionality that `doesn’t seem to be supported inside
containers. <https://github.com/systemd/mkosi/issues/248>`__. It’s also
super complicated and annoying to automate.

Another reason I don’t like loopback devices is because they require
root, which means you need to give the runner root privileges (or let it
sudo without a password). This is slightly sketchy on any system that’s
going to be running for a long time, and especially bad on a system
that’s being used for other things, since a test that does something bad
to the system could mess it up for anyone/anything else using it.

Luckily, there’s another way.

scp
~~~

TL;DR:

.. code:: sh

   cd scripts/memorizer/VM
   mkosi build
   mkosi qemu
   # Run the tests
   # On the VM running memorizer, do:
   cat /sys/kernel/debug/memorizer/kmap > /tmp/kmap
   scp /tmp/kmap [user]@_gateway:/tmp/.   #replace user with host computers name.

To do this, we need to set up a connection between the guest VM and the
host, and then copy over the kmap files from the guest VM to the host.

In order to get this to work you need to:

1. Make sure openssh-server is installed on the host machine.
2. Read the kernel memory mappings from the ``kmap`` file and write the
   contents to ``/tmp/kmap``.
3. Use ``scp`` to transfer the ``/tmp/kmap`` file from the VM to the
   host machine. Replace ``[user]`` with your actual username. The
   ``gateway`` hostname is used directly as it is recognized by your
   environment. This transfers the kmap file just created to the Hosts
   ``/tmp`` directory.

Note: There were issues occurring when a file named ``kmap`` already
existed in the ``/tmp`` directory of the host. Even when the correct
permission were granted to overwrite that file. In order to fix this
just move all previous ``kmaps`` generated in ``/tmp`` to some other
store directory.

The above process should be enough when the goal is just loading up
memorizer and running the test manually on a VM. However, when we want
to automate this process, we need to do a little more work.

But overall by this point you should have a good idea of how to run the
memorizer kernel and get the ``kmap`` file off of it. This process
should work manually, and you can get started on analyzing and viewing
the data in the ``kmap`` file on your own machine.


Initramfs method for memorizer
==============================

Overview
--------

This process introduces a simplified method for running a virtual
machine (VM) memorizer, minimizing the complexity often associated with
traditional tools like mkosi. The approach leverages a minimal initramfs
environment, utilizing Busybox without a conventional root filesystem
(rootfs). This setup is primarily designed for developing and testing
the memorizer.

Key Features
------------

-  Minimalist Initramfs: The VM runs with a Busybox-based initramfs
   and no rootfs, focusing solely on the essential components required
   for memorizer development and testing.
-  Automated Testing: The provided shell script, ``boottest.sh``,
   automates the process of building a kernel, creating an initramfs,
   and booting the VM. Upon booting, the initramfs automatically
   executes a memorizer test suite and exits the emulator.
-  BATS Integration: The BATS (Bash Automated Testing System) is
   included within the initramfs, specifically in the ``/test``
   directory, allowing for the execution of both new-feature and
   regression tests.

Considerations
--------------

-  Scope Limitations: This solution is highly specialized for
   memorizer development and testing. It lacks support for common
   features such as a window manager, desktop environment, and
   networking capabilities, making it unsuitable for broader application
   testing.
-  Stability: The current implementation may experience issues, such
   as hanging if the VM panics. This is a known problem and requires
   further refinement.

Overview of process
-------------------

This process involves: 1. Cloning the necessary repositories. 2.
Clearing the build environment using ``clear.sh``. 3. Building the
project using ``doit.sh`` or ``gdb_doit.sh`` for debugging. 4. Running
the debug build and connecting GDB to it for remote debugging.

Step-by-Step Guide
------------------

1. Cloning the Repository
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

First, ensure you have cloned the “memorizer” repository along with the
“linux” repository inside the commands folder. This sets up the
necessary environment for the following steps.

.. code:: sh

   git clone <memorizer_repo_url> 

Replace ``<memorizer_repo_url>`` with the actual repository URLs.

2. Clearing the Build Directory
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``clear.sh`` script is used to clean the build environment by
removing the ``o`` directory and the ``initramfs``. If the doit.sh
script was run in the past, this step is essential to ensure a clean
build environment. But if this is your first time building then you can
skip this step.

.. code:: sh

   ./clear.sh

Explanation: - ``clear.sh`` will delete the ``o`` directory where
build artifacts are stored. - It also removes the ``initramfs`` file,
which is used as an initial RAM filesystem during the boot process.

3. Building Memorizer with Initramfs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``doit.sh`` script compiles the “memorizer” project along with an
``initramfs``.

.. code:: sh

   ./doit.sh

Explanation: - ``doit.sh`` automates the build process for “memorizer”.
- It compiles the source code and integrates the
``initramfs``. - The output is typically placed in the ``o`` directory.

4. Building Memorizer for Debugging with GDB
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To build “memorizer” with debugging symbols and support, use the
``gdb_doit.sh`` script.

.. code:: sh

   ./gdb_doit.sh

Explanation: - ``gdb_doit.sh`` builds “memorizer” with the necessary
flags and settings to enable debugging with GDB. - This process
generates a ``vmlinux`` file that can be used for debugging.

5. Debugging with GDB
^^^^^^^^^^^^^^^^^^^^^^^^^

To start debugging, follow these steps:

1. Run Memorizer in Debug Mode

   Open a terminal and execute the debug build of “memorizer”.

   .. code:: sh

      ./gdb_doit.sh

   This will prepare the build for GDB and run it in a mode that allows
   remote debugging.

2. Connect GDB to the Running Instance

   Open another terminal window and navigate to the “memorizer” folder.

   .. code:: sh

      cd memorizer
      gdb -ex 'target remote :1234' o/vmlinux

   Explanation:

   -  ``cd memorizer``: Navigate to the “memorizer” directory.
   -  ``gdb -ex 'target remote :1234' o/vmlinux``: This command starts
      GDB and connects to the target running on port ``1234``. It uses
      the ``vmlinux`` file generated by ``gdb_doit.sh``.

Automating it
=============

Normally the way Gitlab CI works is:

-  you have a ``.gitlab-ci.yml`` that has the tests you want to run in
   it
-  for each test, a runner (a program running on some machine you
   control that talks to GitLab) spins up a new docker container that
   runs the test
-  artifacts you specify are copied from that to the next test

The way it normally seems to be done is that this all runs inside yet
another container, called ``docker.gitlab-runner.service``. This
presents a couple problems for Memorizer specifically. First and
foremost, we can’t run ``mkosi`` inside docker containers, because it
requires the use of loopback devices, which containers don’t really seem
to support, as mentioned above. Instead, we have a pre-built image that
the job grabs.

A second problem is that Docker only supports KVM acceleration when run
with ``--privileged`` (which is important because the memorizer kernel
is very slow). The ``docker.gitlab-runner.service`` container wasn’t run
with ``--privileged`` when I was setting this process up (probably wise,
since it doesn’t need those permissions). For this reason we have a
second image made from the ``gitlab/gitlab-runner`` image, running with
``--privileged``. You can find the dockerfile for this in
``scripts/memorizer/testVM``.

In theory you could make this a shell runner directly on your machine
instead of a container. The reason I didn’t do that was because on the
machine I was working on, ``/etc/gitlab-runner/config.toml`` (the file
that holds the information for all the runners) was synced using a
Docker bindmount to the one on the ``docker.gitlab-runner.service``
container (probably so we didn’t have to re-add the runner in GitLab
every time the container was restarted). This meant if you added a
runner on one, it would be duplicated on the other, leading to tests
running in different environments and potentially a lot of weird bugs.

Tangent
=======

(This part is not strictly necessary but it might be informative if
you’re working with VMs)

For a while I was trying to set up a thing where we had another job
running inside a qemu VM that ran mkosi (since it’s probably a bad idea
to have ``gitlab-runner`` running as root on a machine where we’re doing
other things). Because the image built by mkosi was huge, we’d run the
tests as part of the same job rather than uploading it as an artifact.
This turned out not to work so well because running a memorizer kernel
on qemu inside qemu turned out to be extremely slow, even though KVM
acceleration seemed to be on. Evidently, going too many qemus deep leads
to performance issues.

Setting up the runner
=====================

::

   cd scripts/memorizer/testVM
   mkosi build
   ssh-keygen -p -P root -N "" -f ./id_rsa
   docker build .

The ``ssh-keygen -p`` command removes the password from the ``id_rsa``
key so the test doesn’t have to deal with it.

Find the image you just built in ``docker images``, then do
``docker run -d --privileged <image>``. Go to your repo in Gitlab and go
to settings -> CI/CD -> runners and click New Project Runner. Follow the
instructions on that page. To get a shell inside the container, you can
do ``docker exec -it <running image name> bash``. Once you’ve completed
those steps, the runner should work.

You can look at the Dockerfile to get an idea of what it’s doing, but
the important thing is that it copies all the stuff generated with
``mkosi`` to ``/root/mz-image-hack``. In the test, we then copy those
files to the build working directory so we can do ``mkosi qemu``.

The runner is a shell runner; it runs directly on the container instead
of spinning up new containers. This is because I don’t know how to get
the new containers to run with ``--privileged``. If there’s a way to do
this, feel free to change it to work that way.

How the test works
==================

The test itself is done by ``scripts/memorizer/VM/qemu_test.py``. It
uses ``pexpect`` to send a bunch of commands to the VM, then uses
``scp`` (as explained above) to copy the ``kmap`` file off it. I’m a
little worried about the stability of ``pexpect``, since it just reads
the process output directly and searches it with regex, so if there’s
something less brittle we can use I’d probably prefer to switch to that.
I haven’t found a better method yet though.
