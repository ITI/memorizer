# How to build memorizer-v6 & run memorizer test in a VM

This is how we build and execute a linux v6 memorizer kernel, as of 2023-03-22. 

### Build

#### build a kernel

* `cd /data/<yourname>; export TOP=$PWD`
* `git clone gitlab@code.iti.illinois.edu:ring0/memorizer.git`
* `cd memorizer`
* `make O=o defconfig`
* `make O=o rob.config`
* `make O=o memorizer.config`
* `make O=o -j3` # But tune `-j3` to taste.

#### build a rootfs

* cd $TOP/VM
* Adjust `mkosi.conf` to taste.
* mkosi build

### Run

* Launch the QEMU virtual machine
* `mkosi qemu`
* Run some commands inside qemu's virtual machine. For more information on this step, see Documentation/memorizer.txt
  * `uname -a` should indicate a kernel name like `6.1.19-memorizer`.  
  * Run your test, capture your data.
  * Copy your results to the outside world using `scp`. You can copy it anywhere you want. `10.0.2.2` is a QEMU alias for the machine on which QEMU is running, so my command looks like: `scp foo.bar me@10.0.2.2:/data/me/.`
