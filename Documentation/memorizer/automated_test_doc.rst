
==============
Kernel Testing
==============

Manual kernel testing using ``mkosi``
=====================================

Running the test by hand consists of a couple basic steps:

1. Building the kernel
2. Building and running a VM
3. Running the test
4. Extracting the ``kmap`` file from the VM

Building the kernel
-------------------

See any of the chapters in :ref:`quick-start`. If you
are testing on hardware, don't forget to set the :ref:`memorizer-grub-cmdline`.

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
----------------

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


Manual testing using Initramfs
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

This process involves:

1. Cloning the necessary repositories.
2. Clearing the build environment using ``clear.sh``.
3. Building the project using ``doit.sh`` or ``gdb_doit.sh`` for debugging.
4. Running the debug build and connecting GDB to it for remote debugging.

.. note::

   The scripts ``clear.sh``, ``doit.sh``, and ``gdb_doit.sh`` are no
   longer provided. This section needs to be rewritten to account
   for that.

   TODO robadams@illinois.edu

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

Automated Testing
=================

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
-------

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
^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^


The test itself is done by ``scripts/memorizer/VM/qemu_test.py``. It
uses ``pexpect`` to send a bunch of commands to the VM, then uses
``scp`` (as explained above) to copy the ``kmap`` file off it. I’m a
little worried about the stability of ``pexpect``, since it just reads
the process output directly and searches it with regex, so if there’s
something less brittle we can use I’d probably prefer to switch to that.
I haven’t found a better method yet though.

Using the BAsh Testing System
=============================

The automated testing for Memorizer currently relies on the Bash Testing System (BATS). You can find the scripts for it in ``<project root>/scripts/memorizer/test``. These should be relatively self-explanatory, but there are a few wrinkles that this guide should help with.

The documentation for BATS can be found here: https://bats-core.readthedocs.io/en/stable/

Running the tests by hand
-------------------------

If you want to run the tests by hand, you can go to ``<project root>/scripts/memorizer/test`` and do ``./boottest.sh``. If there's no built kernel in the repo, the script will build a kernel for you. This may take quite a while, depending on your machine. The automated tests already build a kernel in a previous step, so we don't have to build the kernel twice during that process.

How this works
--------------

The script builds an initramfs with Alpine Linux and BATS on it. It then runs qemu with that initramfs (and without an actual disk).

Test results
--------------

BATS outputs test results in a format like::

	1..5
	ok 1 memorizer exists
	ok 2 memorizer state 0 works
	ok 3 memorizer state 1 works
	ok 4 ls
	not ok 5 is 3+4=7?
	# (in test file /test/simple_test.bat, line 5)
	#   ``[[ $c == 8 ]]' failed

If the test passed, the line will start with "ok" and the test number. If it failed, there will be a "not ok" and more details.

Adding more tests
-----------------

The tests are located in ``<project root>/scripts/memorizer/test/root/test/``. They have the unfortunate extension ``.bat``. You can have as many tests as you want per file, so split them up however you think is most logical.

One thing I would like to be able to do in the future is either cd into a directory in a BATS test (which doesn't seem to work) or specify directories in a less verbose way than we currently have to do::

	@test "memorizer state 1 works" {
		echo -n 1 > /sys/kernel/debug/memorizer/memorizer_enabled
		grep -q "^1" /sys/kernel/debug/memorizer/memorizer_enabled
		echo -n 0 > /sys/kernel/debug/memorizer/memorizer_enabled
	}

Special considerations for CI
=============================

Getting the test results out of the VM
--------------------------------------

Reading the output of the tests is fine for testing on a local machine, but if we run them in a CI job, we want the job to fail if the tests fail, so we need to get the test results out fo the VM somehow. We do this with the following qemu arguments::

	-fsdev local,security_model=mapped,id=fsdev0,path=output -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare

The important parts here are ``path=output`` and ``mount_tag=hostshare``. The former determines the directory to share with the host. In this case it's ``output``. The latter defines a ``mount_tag`` to identify the device in ``/etc/fstab``.

In our ``init`` script (found in ``<project root>/scripts/memorizer/test/root/init``), we then map the device to ``/output``::

	echo "hostshare   /output 9p  trans=virtio,version=9p2000.L   0   0" >> /etc/fstab
	mount -a

We then write the output to ``/output/results`` on the VM when we run the tests::

	/run-test.sh 2>&1 | tee /output/results

Finally, on the host, after the VM exits, we check if ``output/results`` contains any ``not ok`` statuses::

	[ -z "$(grep '^not ok' output/results)" ] || exit 1

(This solution is largely repurposed from here: https://gist.github.com/bingzhangdai/7cf8880c91d3e93f21e89f96ff67b24b . Looking at that gist might be helpful.)

Exiting on kernel panic
-----------------------

Sometimes there will be bugs with Memorizer that cause the kernel to panic. In this case, we'd like the CI job to fail. This is not the default behavior with QEMU, but we can set it to work this way by doing the following things:

1. In the kernel command line, set ``panic=N``, where N is some number. This will cause the kernel to reboot after N seconds if there's a panic. You can also put ``panic=-1`` to make it reboot immediately.
2. In the qemu command line, have ``-no-reboot``. This will make qemu exit instead of rebooting.
