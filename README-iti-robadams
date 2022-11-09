# How to build memorizer-v6 & run memorizer test in a VM

This is how Rob Adams builds and executes a linux v6 memorizer kernel, as of 2022-11-08. 

You can do this the easy way or the hard way. Or any other way that works.

## Easy way

* Get a copy of the kernel and rootfs:
```
mkdir VM
cd VM
tar xf /data/robadams/tars/v6-kernel-rootfs.<version>.tgz
```

* Run the kernel:
```
cd v6-kernel-rootfs.<version>
sh doit.sh
```

You will see Linux kernel boot messages for a while, then Linux user-mode boot messages, then a login prompt. Log in as `root`, password `root`.

* Run the tests:

  * `uname -a` should indicate a kernel name like `6.0-memorizer`.  
  * Run your test, capture your data. _more to come_
  * Copy your results to the outside world using `scp`. You can copy it anywhere you want. `10.0.2.2` is a QEMU alias for the machine on which QEMU is running, so my command looks like: `scp foo.bar robadams@10.0.2.2:/data/robadams/.`


When you need to exit qemu's virtual machine, enter `CTRL-A` followed by `x`.

## Hard way

### Setup

* THe only tools you need are [Docker]() and [mkosi](). Find a way to install them.
  * Soon, the only tool you will need is Docker.
* Ensure that this alias is active:
    `alias kb='docker run -it --rm -v "$(pwd):$(pwd)" -w "$(pwd)" -u "$(id -u):$(id -g)" --init pastorrob/kernel-build'`
  This may involve editing `$HOME/.bashrc` or `$HOME/.bash_aliases`

### Build

#### build a kernel

* `cd /data/<yourname>; export TOP=$PWD`
* `git clone gitlab@code.iti.illinois.edu:ring0/memorizer.git`
* `cd memorizer`
* `kb make O=o defconfig`
* `kb make O=o memorizer.config`
* `kb make O=o -j3` # But tune `-j3` to taste.

#### build a rootfs

* `mkdir $TOP/VM`
* `cd $TOP/VM`
* Create `mkosi.default`:
   ```
   [Distribution]
  Distribution=ubuntu
  Release=focal

  [Output]
  Format=gpt_ext4
  Bootable=yes
  Output=rootfs.raw
  QCow2=yes

  [Packages]
  Packages=
         apt,apt-utils,
         isc-dhcp-client,iproute2,wget,curl,
         git,vim,build-essential,gcc-multilib,g++-multilib

  [Validation]
  Password=root

  [Partitions]
  RootSize=20G
  ```
* Create `mkosi.postinst`:
  ```
  echo '#!/bin/bash

  dhclient
  ' >> /etc/rc.local
  chmod +x /etc/rc.local
  ```

### Run

* Launch the QEMU virtual machine
  * `qemu-system-x86_64 --enable-kvm -nographic -cpu host -m 20G -kernel ../memorizer/o/arch/x86/boot/bzImage -append "console=ttyS0 root=/dev/sda2 memalloc=10" -hda rootfs.raw -nographic`
    
    This might be available as `run_qemu.sh` or `doit.sh`. TBD
* Run some commands inside qemu's virtual machine
  * `uname -a` should indicate a kernel name like `6.0-memorizer`.  
  * Run your test, capture your data.
  * Copy your results to the outside world using `scp`. You can copy it anywhere you want. `10.0.2.2` is a QEMU alias for the machine on which QEMU is running, so my command looks like: `scp foo.bar robadams@10.0.2.2:/data/robadams/.`


