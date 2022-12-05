# How to build memorizer-v6 & run memorizer test in a VM

This is how we build and execute a linux v6 memorizer kernel, as of 2022-11-08. 

### Build

#### build a kernel

* `cd /data/<yourname>; export TOP=$PWD`
* `git clone gitlab@code.iti.illinois.edu:ring0/memorizer.git`
* `cd memorizer`
* `make O=o defconfig`
* `make O=o memorizer.config`
* `make O=o -j3` # But tune `-j3` to taste.

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
* Run some commands inside qemu's virtual machine. For more information on this step, see Documentation/memorizer.txt
  * `uname -a` should indicate a kernel name like `6.0-memorizer`.  
  * Run your test, capture your data.
  * Copy your results to the outside world using `scp`. You can copy it anywhere you want. `10.0.2.2` is a QEMU alias for the machine on which QEMU is running, so my command looks like: `scp foo.bar me@10.0.2.2:/data/me/.`
