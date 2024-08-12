==================================
Quick Start for Ubuntu on Hardware
==================================


This guide is a step-by-step set of instructions
for installing an Ubuntu LTS release, building a
Memorizer kernel, and booting Memorizer.

These instructions have been tested on a number of PC-compatible
systems including an Intel NUC, a LattePanda single-board computer,
and a Dell laptop.

Environment
===========

We prepare an environment for downloading, building, and booting
a Memorizer Kernel. We presume you have one PC on which to run
the test, and a second PC for network tasks.

- Install Ubuntu from a thumbdrive. Make a note of the
  username and password that you create during the install
  process.
- Boot into Ubuntu. 
- Open terminal
- Type ``sudu bash``
- ``apt install net-tools`` (to be able to find IP address of device)
- ``apt install openssh-server`` (to be able to ssh to device)
- figure out IP of device by typing ``ifconfig`` or ``ip a``

You may find the remainder of these instructions easier to perform
using an ``ssh`` connection from your workstation to the
freshly-installed Ubuntu machine. If so, perform the following
steps.

- go to your workstation
- ``ssh username@ipaddress``

Regardless, finish installing the required software.

- ``sudo bash``
- ``apt update && apt -y upgrade``
- ``sudo apt install build-essential``
  (note: build-essential is supposed to be all you 
  need, but all of the below works on most of the tested hardware
  variations in the lab)
- ``sudo apt install libncurses-dev gawk flex bison libssl-dev dkms
  libelf-dev libudev-dev libpci-dev libiberty-dev autoconf llvm git
  ncurses-dev libssl-dev autoconf-archive gnu-standards autoconf-doc
  libtool gettext binutils-doc bison-doc debtags menu debian-keyring
  flex-doc g++-multilib g++-12-multilib gcc-12-doc gawk-doc
  gcc-multilib gcc-doc gcc-12-multilib gcc-12-locales glibc-doc
  doc-base tagcoll lib32stdc++6-12-dbg libx32stdc++6-12- dbg
  gettext-doc autopoint libasprintf-dev libgettextpo-dev``
- Use these steps if you want to connect to a samba share or skip if
  you don’t samba:

  - ``sudo apt install cifs-utils``
  - ``mkdir /mnt/share``
  - ``mount -t cifs -o username=USERNAME,password=PASSWD //ipaddress/shares /mnt/share``


Kernel Build
============
There are several ways to download and build a Memorizer kernel. This
describes one of them. For alternatives, see the other Quick Start
guides.

Start here, skipping the previous steps, if you have already done a
memorizer install once.

As of this writing, the most recent Memorizer is version 25, 
built upon Linux 6.6.30. In each of the following lines,
replace `X` with ``30`` and replace ``Y`` with ``25``.

Download, install source code
-----------------------------

- ``cd /usr/src``
- ``wget https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-6.6.X.tar.gz``
- ``tar xvf ./linux-6.6.X.tar.gz``
- ``cd linux-6.6.X``
- ``make localmodconfig`` (make localmodconfig will match the currently loaded 
  modules on your system please ensure all modules you need to run the 
  system are there . . . such as USB and CIFS etc) Read through the choices or 
  just accept defaults. Accepting defaults works on most of the tested 
  hardware.
- aquire the appropriate Memorizer patch file. Place it in ``/usr/src``.
- (From ``/usr/src/linux-6.6.X``) ``patch –p1 < /usr/src/v6.6.X-memorizer-Y.patch``


Configure the kernel
--------------------

- ``make memorizer.config``
- confirm that CONFIG_FRAME_WARN is at least 2048. Ubuntu seems to make this
  1024 in some circumstances.

  - ``grep CONFIG_FRAME_WARN .config``
  - If required, ``./scripts/config --set-val CONFIG_FRAME_WARN 2048``

- Disable kernel signing.

  - If you are compiling the kernel on Ubuntu, you may receive the
    following error that interrupts the building process: 
    ``No rule to make target 'debian/canonical-certs.pem``
    If so, disable the conflicting security certificates.

    - ``scripts/config --disable SYSTEM_TRUSTED_KEYS``
    - ``scripts/config --disable SYSTEM_REVOCATION_KEYS``

Building the kernel
-------------------

- ``make -j$(($(nproc) * 2))``
  (This may attempt to complete the
  configuration process. If so,
  accept default answers when prompted)
  (adding ``–j`` makes it compile faster. In this case, ``make`` will use
  twice as many concurrent processes as their are cores in the system.)
- ``make modules``
- ``make modules_install`` (this might require ``sudo``)
- ``make install``

Booting the Kernel
------------------

Its almost time to reboot! The Memorizer kernel requires several
specific command-line parameters. For the Grub bootloader, these
parameters are read from `/etc/default/grub` See
<https://www.gnu.org/software/grub/manual/grub/html_node/Simple-configuration.html>

* Edit `/etc/default/grub`. Add these lines to Ensure that the grub menu
  is displayed so that the user may control the boot process::

    GRUB_TIMEOUT=5 
    GRUB_TIMEOUT_STYLE=countdown

* Add these boot parameters to the ``GRUB_CMDLINE_LINUX`` line in ``/etc/default/grub`` ::

    memorizer_enabled_boot=no
    maxcpus=1
    split_lock_detect=off
    no_hash_pointers
    nokaslr
    audit=0
    loglevel=8
    memalloc_size=4
      
  Make ``memalloc_size`` specify as much memory as you can stand,
  but at least 4 gigabytes.

  The ``GRUB_CMDLINER_LINUX`` values must be on a single line.
  Here is an working example::

    GRUB_CMDLINE_LINUX="memorizer_enabled_boot=no maxcpus=1 split_lock_detect=off no_hash_pointers nokaslr audit=0 loglevel=8 memalloc_size=4”

After updating ``/etc/default/grub`` as described, run the following commands:

* ``update-grub``
* ``reboot``

Congratulations! You should now have a running Memorizer kernel. 
See :doc:`using_memorizer` for the next steps.
