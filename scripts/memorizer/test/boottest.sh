#!/bin/bash
# Commands to boot memorizer with initramfs

set -ex
cd $(dirname $0)
root=../../..
#O=test-o
function mk {
	make -C $root O=$O -j $(( $(nproc) / 3 + 1)) "$@"
}
BUSYBOX='https://www.busybox.net/downloads/binaries/1.26.2-defconfig-multiarch/busybox-x86_64'
BASH='https://github.com/robxu9/bash-static/releases/download/5.2.015-1.2.3-2/bash-linux-x86_64'
BASH='https://github.com/ryanwoodsmall/static-binaries/raw/master/x86_64/bash'
DROPBEAR='https://github.com/ryanwoodsmall/static-binaries/raw/master/x86_64/dropbearmulti'
ALPINE='https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86/alpine-minirootfs-3.20.0-x86.tar.gz'

# Build a Kernel
################
[ -f $root/$O/arch/x86/boot/bzImage ] || { mk defconfig memorizer.config && mk ; }

# Build local copy of initramfs
###############################
mkdir -p root/{bin,dev,etc,lib,mnt,proc,sbin,sys,tmp,var}
[ -x root/bin/cttyhack ] || {
	curl -L "$BUSYBOX" >busybox && cp busybox root/bin/cttyhack && cp busybox root/bin/setsid
	chmod +x root/bin/cttyhack
}
[ -x root/bin/bash ] || curl -L "$BASH" >root/bin/bash
chmod +x root/bin/bash 
# [ -x root/bin/dropbear ] || curl -L "$DROPBEAR" >root/bin/dropbear
# chmod +x root/bin/dropbear
# rm -rf root/test/bats root/test/test_helper
[ -x root/bin/busybox ] || curl -L "$ALPINE" | tar xzC root/.
rm -rf root/test/bats root/test/test_helper
git clone --depth=1 https://github.com/bats-core/bats-core.git root/test/bats
git clone --depth=1 https://github.com/bats-core/bats-support.git root/test/test_helper/bats-support
git clone --depth=1 https://github.com/bats-core/bats-assert.git root/test/test_helper/bats-assert


# Build an InitramFS
####################
cd root/
find . | cpio -ov --format=newc | gzip >../initramfs
cd ..


# Boot a Kernel
###############

# Output directory for the tests
mkdir -p output

# Feel free to add other qemu parameters.
qemu-system-x86_64 -no-reboot -machine type=q35,accel=kvm,smm=off -smp 4 -m 8G -cpu max,pmu=off -nographic -append 'panic=30 selinux=0 audit=0 maxcpus=1 split_lock_detect=off memorizer_enabled_boot=no nokaslr no_hash_pointers loglevel=8 memalloc_size=4 console=ttyS0' -kernel $root/$O/arch/x86/boot/bzImage -initrd initramfs -fsdev local,security_model=mapped,id=fsdev0,path=output -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare

[ -z "$(grep '^not ok' output/results)" ] || exit 1
