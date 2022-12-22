# Running memorizer tests

To run a test using memorizer, you must

* Build a kernel
* Build a VM
* Start the VM
* Run the test
* Copy out the results

## Build a kernel

Build a kernel any way you please. You might use these commands:

    cd ..
    alias kb6='docker run -it --rm -v "$(pwd):$(pwd)" -v /etc/passwd:/etc/passwd:ro -w "$(pwd)" -u "$(id -u):$(id -g)" pastorrob/kernel-build:6.0'
    kb6 make O=o defconfig
    kb6 make O=o memorizer.config
    kb6 make O=o -j3
    make O=o -j3 # But tune `-j3` to taste.

## Build a VM

These control files are for `mkosi`. First set up `mkosi`, following its directions.

Then issue these commands:

    sudo mkosi --force build

## Start the VM

Again, use `mkosi`:

    mkosi qemu

## Run the test

Inside the VM shell, edit the file `/doit.sh` to suit your enviornment and test:

    /doit.sh

## Copy out the results

The file `/doit.sh` automatically copies out the results to `/data/$USER/data/$UNAME/$DATE`.
