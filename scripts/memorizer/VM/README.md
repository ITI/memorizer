# Running memorizer tests

To run a test using memorizer, you must:

## If using QEMU

* Build a kernel
* Build a VM
* Start the VM
* Run the test
* Copy out the results

## If using hardware (e.g. LattePanda 3 Delta 864)

* Build a kernel
* Build a VM
* Copy disk image to hardware
* Boot the image on hardware
* Run the test
* Copy out the results

## Build a kernel

Build a kernel any way you please. You might use these commands:

    cd ..
    alias kb6='docker run -it --rm     \
        -v "$(pwd):$(pwd)" -w "$(pwd)" \
        -v /etc/passwd:/etc/passwd:ro -u "$(id -u):$(id -g)" \
        pastorrob/kernel-build:6.0'
    kb6 make O=o defconfig
    kb6 make O=o rob.config
    kb6 make O=o memorizer.config
    kb6 make O=o -j3  # but tune '-j3' to taste

## Build a VM

These control files are for `mkosi`. First set up `mkosi`, following its directions.

Then issue this command. In addition to setting up a working Ubuntu 20.04,
this will copy the kernel from `../o` into the image.

    sudo mkosi --force build

The file `focal.img` now contains a memorizer kernel, a rootfs, and an EFI boot environment.
It will work equally well in QEMU and on PC-standard hardware (e.g., LattePanda 3 Delta 864).

## Start the VM

If you are using QEMU, start the VM with this command:

    mkosi qemu

## Copy disk image to hardware

If you are using a hardware device, copy the boot image with this command:

    # below is an example. Select the correct device file for your flash drive
    sudo dd if=focal.img of=/dev/sdq bs=10M

## Boot the image on hardware

If you are using a hardware device, boot the Memorizer kernel.
The following works for at least some PC-compatible targets.

Insert the flash into the target hardware and power the hardware on. You may need to enter
its BIOS setup system to enable EFI booting from a USB device.

During booting, the EFI boot menu should appear. Select "Linux 6.0 memorizer"

## Run the test

In either a VM or a hardware target, the file `/doit.sh` is automatically provided.

Inside the shell, edit the file `/doit.sh` to suit your enviornment and test:

    vi /doit.sh
    /doit.sh

## Copy out the results

When run inside QEMU, the file `/doit.sh` automatically copies out the results to `/data/$USER/data/$UNAME/$DATE`.

Copying out the data in a hardware test is left to the reader. :)
