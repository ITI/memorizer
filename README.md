
# Memorizer

Memorizer is a tool to record information about access to kernel objects:
specifically, it counts memory accesses from distinct IP addresses in the
kernel source and also the PID that accessed, thereby providing spatial and
temporal dimensions.

This branch contains memorizer rebased on Linux v5.15.15. See the commit history for port status. See another branch for legacy version based on v4.10.

### Boot Test

1. Install [system/mkosi](https://github.com/systemd/mkosi) v12 for root file system construction. Use the zipapp approach. Tweak PATH. DO NOT use apt-get since that version is outdated.

2. Build root file system.
```
mkdir VM
cp ./scripts/memorizer/mkosi.default ./VM
cp ./scripts/memorizer/mkosi.postinst ./VM
(cd ./VM && sudo mkosi)
```

3. Build the kernel.
```
cp ./scripts/memorizer/memorizer_config.config .config
make -j$(nproc)
```

4. Run QEMU. Both username and password are `root`.
```
./scripts/memorizer/run_qemu.sh ./VM/rootfs.raw
```

