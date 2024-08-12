=====================
Memorizer Quick Start
=====================

Memorizer is a Linux kernel feature for analyzing memory objects inside
the kernel. As a Linux kernel feature, building Memorizer is simply
a matter of rebuilding the Linux kernel. Running Memorizer is simply
booting and interactig with the resulting kernel.

If you are already familiar with building and booting custom
Linux kernels, use your existing workflow. The Memorizer
feature is enabled with the ``CONFIG_MEMORIZER`` configuration
option. See :doc:`using_memorizer` for information on how to use
the Memorizer Linux kernel.

If you are less familiar with building and booting custom
Linux kernels, consult any Linux kernel building guide on the
Internet, or one of our guides. You may use any set of instructions
you wish. As long as you can aquire the Memorizer
source code, compile a kernel, and boot a kernel, you can
use Memorizer.

.. toctree::
    :maxdepth: 1

    quick_start_deb
    quick_start_ubuntu
    quick_start_busybox
    quick_start_mkosi

.. only::  subproject and html

   Indices
   =======

   * :ref:`genindex`

Using the Kernel
================

..note::

Move this to :doc:`using_memorizer`

After you have successfully built a Memorizer Linux kernel, follow
the directions in :doc:`using_memorizer`.

Initial Conditions
------------------

Set it up::

  echo 0 > /sys/foo
  echo 1 > /sys/bar

Run the experiment
------------------

Gather the data::

  echo 1 > start
  ./AmazingApp.AppImage
  echo 0 > start

Store the data
--------------

Submit the results for storage and analysis::

  scp foo bar:

   
