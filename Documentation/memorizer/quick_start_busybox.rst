===============================
Quick Start for Busybox on Qemu
===============================


This guide is a step-by-step set of instructions
for creating a Qemu-based Memorizer installation
using a minimal rootfs. These instructions are designed
to provide the quickest method of running Memorizer.

Environment
===========

We will not be building a kernel, so we do not need any kernel
build tools. However, these techniques do work on a custom-built kernel; see the other *Quick Start* guides for information about building a kernel.

Qemu
----

Install Qemu::

  sudo apt install qemu-system-x86_64
  sudo adduser $USER kvm


Download Memorizer Image
========================

A pre-built Memorizer Linux kernel image is available from ITI's Linux mirror, code.iti.illinois.edu. For Memorizer release v6.6.30-memorizer-25, download the `bzImage` file from https://code.iti.illinois.edu/ring0/memorizer/-/releases/v6.6.30-memorizer-25.

Copy the resulting ``bzImage-v6.6.30-memorizer-25`` file to an empty directory.
All of the remaining tasks will occur in that directory.

Build initramfs Image
=====================

This technique is inspired by https://lyngvaer.no/log/create-linux-initramfs.

Create a root directory::

  mkdir root

Install a copy of busybox::

  mkdir -p root/bin
  curl -L 'https://www.busybox.net/downloads/binaries/1.26.2-defconfig-multiarch/busybox-x86_64' >root/bin/busybox
  chmod +x root/bin/busybox

Copy the following code into ``root/init``::

  #!/bin/busybox sh
  set -ex

  /bin/busybox --install /bin
  PATH=/bin:. ; export PATH

  mkdir -p /dev /proc /sys /tmp /output
  mount -t devtmpfs  devtmpfs  /dev
  mount -t proc      proc      /proc
  mount -t sysfs     sysfs     /sys
  mount -t tmpfs     tmpfs     /tmp
  mount -t debugfs   debugfs   /sys/kernel/debug

  while true
  do
    echo starting a shell. poweroff -f to quit
    setsid cttyhack sh 
  done

Don't forget to make ``/init`` executable::

  chmod +x root/init

At this point, your ``root`` directory should contain two files::

  root/init
  root/bin/busybox

Build the initramfs image::

  cd root/
  find . | cpio -ov --format=newc | gzip >../initramfz
  cd ..

Boot the Kernel
===============

If this were a standard Linux kernel, invocation would be simple::

  qemu-system-x86_64 -kernel vmlinuz -initrd initramfz

However, the Memorizer kernel requires a few more switches::

 qemu-system-x86_64 -machine type=q35,accel=kvm,smm=off -smp 4 -m 8G -cpu max,pmu=off -append 'selinux=0 audit=0 maxcpus=1 split_lock_detect=off memorizer_enabled_boot=no nokaslr no_hash_pointers loglevel=8 memalloc_size=4 console=ttyS0' -kernel bzImage-v6.6.30-memorizer-25 -initrd initramfz

See :ref:`memorizer-grub-cmdline` for more information about individual kernel parameters.

Congratulations! You should now have a running Memorizer kernel. 
See :doc:`using_memorizer` for the next steps.
