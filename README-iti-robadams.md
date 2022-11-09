# How to build memorizer-v6 & run memorizer test in a VM

## Easy way

`cp`
`sh doit1.sh`

## Hard way

### Setup

* THe only tool you need is [Docker](). Find a way to install it.
* Ensure that this alias is active:
    `alias kb=...`
  This may involve editing `$HOME/.bashrc` or `$HOME/.bash_aliases`

### build

#### Build a kernel

* `cd $TOP`
* `kb make O=o defconfig`
* `kb make O=o memorizer.config`
* `kb make O=o -j3` # But tune `-j3` to taste.

#### Build a rootfs

* `mkosi`

### Run

* `sh doit.sh`
* Run your test, capture your data.
* `scp datafile.txt 10.something`
