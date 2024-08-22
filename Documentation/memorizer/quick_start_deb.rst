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

* Edit ``/etc/default/grub``. Add or modify these lines to ensure that the grub menu
  is displayed so that the user may control the boot process::

    GRUB_TIMEOUT=5 
    GRUB_TIMEOUT_STYLE=countdown
    GRUB_CMDLINE_LINUX="memorizer_enabled_boot=no maxcpus=1 split_lock_detect=off no_hash_pointers nokaslr audit=0 loglevel=8 memalloc_size=4”

  See :ref:`memorizer-grub-cmdline` for more information about individual kernel parameters.


Reboot
======

After updating `/etc/default/grub` as described, run the following commands::

  update-grub
  reboot

Congratulations! You should now have a running Memorizer kernel. 
See :doc:`using_memorizer` for the next steps.
