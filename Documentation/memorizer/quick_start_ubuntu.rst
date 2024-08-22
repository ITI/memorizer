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

- Install Ubuntu, most likely from a thumbdrive. Make a note of the
  username and password that you create during the install
  process.
- Boot into Ubuntu. 
- Open terminal.
- Install some networking helpers. ``net-tools`` will allow
  you to find the IP address of your device. ``openssh-server`` will allow
  you to connect to your device from your workstation.

  ::

    sudo bash
    apt install net-tools
    apt install openssh-server

- Figure out IP of device by typing ``ifconfig`` or ``ip a``

.. note::
  You may find the remainder of these instructions easier to perform
  using an ``ssh`` connection from your workstation to the
  freshly-installed Ubuntu machine. Using the username from the Ubuntu install,
  and the IP address you previously discovered,
  run the following command on your workstation.
  ::

    ssh username@ipaddress

- Regardless, finish installing the required software::

    sudo bash
    apt update && apt -y upgrade
    sudo apt install build-essential

  .. note::
    ``build-essential`` is supposed to be all you 
    need, but the following list seems to work
    when ``build-essential`` was not sufficient.
    ::

      sudo apt install \
        autoconf autoconf-archive autoconf-doc autopoint \
        binutils-doc bison bison-doc \
        dbg debian-keyring debtags dkms doc-base \
        flex flex-doc g++-12-multilib gawk gawk-doc \
        gcc-12-doc gcc-12-locales gcc-12-multilib gcc-doc gcc-multilib \
        gettext gettext-doc git glibc-doc g++-multilib gnu-standards \
        lib32stdc++6-12-dbg libasprintf-dev libelf-dev libgettextpo-dev \
        libiberty-dev libncurses-dev libpci-dev libssl-dev libssl-dev \
        libtool libudev-dev libx32stdc++6-12- llvm \
        menu ncurses-dev tagcoll

- Use these steps if you want to connect to a samba share or skip if
  you don’t samba::

    sudo apt install cifs-utils
    mkdir /mnt/share
    mount -t cifs -o username=USERNAME,password=PASSWD //ipaddress/shares /mnt/share


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

- Download and install the linux source::

    cd /usr/src
    wget https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-6.6.X.tar.gz
    tar xvf ./linux-6.6.X.tar.gz
    cd linux-6.6.X
    make localmodconfig

  Read through the choices or just accept defaults. Accepting defaults works on
  most of the tested hardware.

  .. note::

    ``make localmodconfig`` will match the currently loaded 
    modules on your system. Please ensure all modules you need to run the 
    system are there, including USB, CIFS, and other occasionally-used modules.

- aquire the appropriate Memorizer patch file, which can be found
  at <https://code.iti.illinois.edu/ring0/memorizer/-/releases>. Place the
  patch file in ``/usr/src``.

- Apply the patch::

    cd /usr/src/linux-6.6.X
    patch –p1 < /usr/src/v6.6.X-memorizer-Y.patch


Configure the kernel
--------------------

- Apply the memorizer-specific configuration settings::

    make memorizer.config

- Confirm that CONFIG_FRAME_WARN is at least 2048.

  Ubuntu seems to make this
  1024 in some circumstances. If required, set the value to 2048::

    grep CONFIG_FRAME_WARN .config
    ./scripts/config --set-val CONFIG_FRAME_WARN 2048

- Disable kernel signing.

  If you are compiling the kernel on Ubuntu, you may receive the
  following error that interrupts the building process: 
  ``No rule to make target 'debian/canonical-certs.pem``

  If so, disable the conflicting security certificates::

    scripts/config --disable SYSTEM_TRUSTED_KEYS
    scripts/config --disable SYSTEM_REVOCATION_KEYS

Building the kernel
-------------------

Run the following commands to build and install the Memorizer kernel::

  make -j16
  make -j16 modules
  sudo make modules_install
  sudo make install

.. note::
  The first ``make`` might ask some configuration questions. If so, accept the defaults.

.. note::
  Adding ``-j`` can make it compile faster. Choose any number that
  improves your performance. We generally use ``1.5 * #cpus``

Booting the Kernel
------------------

Its almost time to reboot! The Memorizer kernel requires several
specific command-line parameters. For the Grub bootloader, these
parameters are read from `/etc/default/grub` See
<https://www.gnu.org/software/grub/manual/grub/html_node/Simple-configuration.html>

Edit `/etc/default/grub`. Add these lines to ensure that the grub menu
is displayed so that the user may control the boot process::

    GRUB_TIMEOUT=5 
    GRUB_TIMEOUT_STYLE=countdown
    GRUB_CMDLINE_LINUX="memorizer_enabled_boot=no maxcpus=1 split_lock_detect=off no_hash_pointers nokaslr audit=0 loglevel=8 memalloc_size=4”

Make ``memalloc_size`` specify as much memory as you can stand,
but at least 4 gigabytes.

See :ref:`memorizer-grub-cmdline` for more information about individual kernel parameters.

After updating ``/etc/default/grub`` as described, run the following commands::

  update-grub
  reboot

Congratulations! You should now have a running Memorizer kernel. 
See :doc:`using_memorizer` for the next steps.
