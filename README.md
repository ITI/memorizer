# Running memoizer on 4.10


## git it

Set the environment variable `$TOP` to something interesting.


    export TOP=/data/$USER/linux.code.iti/memorizer
    mkdir -p $TOP


Clone the repo:

    cd $TOP
    git clone gitlab@code.iti.illinois.edu:ring0/memorizer.git
    cd $TOP/memorizer
    git checkout/robadams/build
    git checkout/4.10-memorizer

Choose a branch. Two interesting possibilities are:

    git checkout robadams/build
    git checkout v4.10-memorizer


## build it

Your choices are

1. "Build a kernel" and "Build a runtime", 
2. "Steal a runtime"

You should do at least one of those.

### Build a kernel
    
    cd $TOP/memorizer
    make defconfig
    make kvm_guest.config
    make memorizer.config
    make -j16
    

### Build a runtime

    
    cd cd $TOP/memorizer/VM
    sudo mkosi build
    

### Or, steal a runtime

    
    tar xCf $TOP/memorizer /data/robadams/mkosi.tar.gz
    

## run it

### Run a stock image, no memorizer:

    
    cd $TOP/memorizer/VM
     # Pick one of the following:
    ./run_qemu.sh
    mkosi qemu
    

### Run the checked-in memorizer image:

    
    cd $TOP/memorizer/VM
    ./run_qemu.sh rootfs.raw -kernel memorizer.bzImage
    

### Run your recently-built image:

    
    cd $TOP/memorizer/VM
    ./run_qemu.sh rootfs.raw -kernel ../arch/x86/boot/bzImage
    

### Debug your recently-built image:

#### QEMU

Run a linux image under qemu, like so:

    cd $TOP/memorizer/VM                                             
    ./run_qemu.sh rootfs.raw -kernel ../arch/x86/boot/bzImage -s -S 

 ### GDB

Launch GDB and connect to the running QEMU instacnce, like so:

    cd $TOP/memorizer 
    gdb vmlinux
    target remote :1234

## capture it

Instructions are TBD, but this script might help in the meanwhile:

    U=robadams
    K=/sys/kernel
    M=$K/debug/memorizer
    T=$K/tracing

    # Setup the test
    echo 1 > $M/clear_dead_objs
    echo 1 > $M/clear_printed_list
    echo 0 > $M/print_live_obj

    # start the test
    echo function > $T/current_tracer
    echo 1 > $M/memorizer_enabled
    echo 1 > $M/memorizer_log_access
    echo 1 > $M/cfg_log_on

    # run some test here.
    sleep 2

    # Shut down the test
    echo 0 > $M/memorizer_log_access
    echo 0 > $M/memorizer_enabled
    echo 0 > $M/cfg_log_on

    # Gather the data
    # You might have had to run "dhclient" before running this test
    D=$(date --iso=seconds)
    cat $M/kmap | ssh $U@10.0.2.2 "cat >/data/output/kmap.$D"
    cat $M/cfgmap | ssh $U@10.0.2.2 "cat >/data/output/cfgmap.$D"

    # Clear the data
    echo 1 > $M/clear_dead_objs
    echo 1 > $M/clear_printed_list
