===============================================
Quick Start for pre-compiled ``.deb`` packages.
===============================================


This guide is a step-by-step set of instructions
for installing Memorizer onto an existing Debian, Ubuntu,
or derivative system, using pre-built ``.deb`` files.

Environment
===========

Ensure that the system has a package manager compatible with
``.deb`` files, and that the system is up to date.
For example::

  sudo apt update && sudo apt -y upgrade

Locate the ``.deb`` file that you were given or previously
downloaded::

  $ ls ~/Downloads/*.deb
  linux-image-6.6.30-memorizer-25..._amd64.deb

Kernel Instsall
===============

Install the Linux image using the system's packakge manager::

  $ sudo apt install ~/Downloads/linux-image-6.6.30-memorizer*.deb

The Memorizer kernel requires several
specific command-line parameters. For the Grub bootloader, these
parameters are read from `/etc/default/grub` See
<https://www.gnu.org/software/grub/manual/grub/html_node/Simple-configuration.html>

* Edit `/etc/default/grub`. Add these lines to ensure that the grub menu
  is displayed so that the user may control the boot process::

    GRUB_TIMEOUT=5 
    GRUB_TIMEOUT_STYLE=countdown

* Add these boot parameters to the ``GRUB_CMDLINE_LINUX`` line in `/etc/default/grub`.

  memorizer_enabled_boot=no
    The memorizer tool is able to gather information
    during the boot process. Unless your experiment
    requires it, turn it off to save memory space.

  maxcpus=1                
    As of ``linux-6.6.30-memorizer-25<F2>``, 
    memorizer only runs in single-cpu environments.

  split_lock_detect=off
    ..

  no_hash_pointers         
    As a security measure, Linux anonymizes all pointer
    values before printing them to the console. We
    turn that feature off so that data analysis tools
    can corelate code pointers with source code.

  nokaslr                  
    As a security measure, Linux can be loaded
    into randomly-generated virtual memory addresses.
    We turn that feature off so that the data analysis
    tools can corelate code pointers with source code.

  audit=0
    ..

  loglevel=8               
    As part of memorizer development, we always run
    at a high loglevel. Your needs may be different.

  memalloc_size=4          
    At startup, memorizer reserves a significant
    portion of physical memory for its own uses.
    All CAPMAP data is stored there before being
    retrieved via the `debugfs` file system.
    Make this number the largest you are able to,
    reserving only enough to run your experiment.
    The number is the number of GB to use,
    the suggested minimum value is 4GB.

  The ``GRUB_CMDLINER_LINUX`` values must be on a single line.
  Here is an working example::

    GRUB_CMDLINE_LINUX="memorizer_enabled_boot=no maxcpus=1 split_lock_detect=off no_hash_pointers nokaslr audit=0 loglevel=8 memalloc_size=4”

Reboot
======

After updating `/etc/default/grub` as described, run the following commands::

  update-grub
  reboot

Congratulations! You should now have a running Memorizer kernel. 
See :doc:`using_memorizer` for the next steps.
