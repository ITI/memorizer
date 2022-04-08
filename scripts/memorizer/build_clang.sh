# Path to the customized LLVM-13
LLVM_BIN=$HOME/fierce-lab/llvm13-memorizer/build/bin

make $@ -j$(nproc) \
    CC=$LLVM_BIN/clang LD=$LLVM_BIN/ld.lld AR=$LLVM_BIN/llvm-ar NM=$LLVM_BIN/llvm-nm STRIP=$LLVM_BIN/llvm-strip OBJCOPY=$LLVM_BIN/llvm-objcopy OBJDUMP=$LLVM_BIN/llvm-objdump READELF=$LLVM_BIN/llvm-readelf HOSTCC=$LLVM_BIN/clang HOSTCXX=$LLVM_BIN/clang++ HOSTAR=$LLVM_BIN/llvm-ar HOSTLD=$LLVM_BIN/ld.lld