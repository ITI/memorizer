# Running memoizer on 4.10


## git it

Set the environment variable `$TOP` to something interesting.
    ```
    export TOP=/data/$USER/linux.code.iti/memorizer
    mkdir -p $TOP
    ```

Clone the repo:
    ```
    cd $TOP
    git clone gitlab@code.iti.illinois.edu:ring0/memorizer.git
    cd $TOP/memorizer
    git checkout/robadams/build
    git checkout/4.10-memorizer
    ```

Choose a branch. Two interesting possibilities are:
    ```
    git checkout robadams/build
    git checkout v4.10-memorizer

    ```

## build it

Your choices are
    1. "Build a kernel" and "Build a runtime", 
    2. "Steal a runtime"

You should do at least one of those.

### Build a kernel
    ```
    cd $TOP/memorizer
    make defconfig
    make memorizerconfig
    make -j16
    ```

### Build a runtime

    ```
    cd cd $TOP/memorizer/VM
    sudo mkosi build
    ```

### Or, steal a runtime

    ```
    tar xCf $TOP/memorizer /data/robadams/mkosi.tar.gz
    ```

## run it

Run a stock image, no memorizer:

    ```
    cd $TOP/memorizer/VM
     # Pick one of the following:
    ./run_qemu.sh
    mkosi qemu
    ```

Run the checked-in memorizer image:

    ```
    cd $TOP/memorizer/VM
    ./run_qemu.sh rootfs.raw -kernel memorizer.bzImage
    ```

Run your recently-built image:

    ```
    cd $TOP/memorizer/VM
    ./run_qemu.sh rootfs.raw -kernel ../arch/x86/boot/bzImage
    ```

Debug your recently-built image:

    | QEMU                                                              | GDB                   |
    |-------------------------------------------------------------------|-----------------------|
    | `cd $TOP/memorizer/VM`                                            | `cd $TOP/memorizer`   | 
    | `./run_qemu.sh rootfs.raw -kernel ../arch/x86/boot/bzImage -s -S` | `gdb vmlinux`         |
    |                                                                   | `target remote :1234` |
    |                                                                   | `c` for continue      |

## capture it

    TBD
