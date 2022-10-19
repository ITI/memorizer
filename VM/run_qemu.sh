 #!/bin/sh

 # Run a Linux kernel in qemu
 #
 # The command-line options below are defaults -- if you run
 #  $ ./run_qemu.sh
 # then you should see Linux booting.
 #
 # If you need to test a different rootfs, use the first argument:
 #  $ ./run_qemu.sh rootfs_different.raw
 # 
 # If you need to specificy (or override) any other command-
 # line parmeters, they may be provided after the rootfs:
 #  $ ./run_qemu.sh rootfs.raw -kernel ./rootfs.vmlinuz
 # Note: if you specify any other parameters, the name
 # of the rootfs volume must be specified.
 #
 # By default, this script should successfully run
 # the kernel & rootfs from mkosi in a window
 #
 # Here are useful commands to copy-and-paste
 #  $ ./run_qemu.sh rootfs.raw -kernel ../arch/x86/boot/bzImage
 #

 set -ex

 R=${1:-"rootfs.raw"}
 [[ $# > 0 ]] && shift
 
 qemu-system-x86_64 \
  -kernel rootfs.vmlinuz \
  -append "earlyprintk memalloc=1 nokaslr root=/dev/sda2 memorizer_enabled_boot=no memorizer_enabled=no root=/dev/sda2" \
  -initrd rootfs.initrd \
  -m 16G \
  --enable-kvm \
  -cpu host,pmu=off \
  -hda $R \
  "$@"

#  -initrd ramdisk.img \
#  -nographic \
# -append "console=ttyS0"
# -s -S \

# early_param("memorizer_enabled_boot", early_memorizer_enabled);
 # -kernel ../arch/x86_64/boot/bzImage \
