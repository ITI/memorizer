KASAN_SANITIZE := n
KCOV_INSTRUMENT := n

CFLAGS_REMOVE_memorizer.o = -pg
# Function splitter causes unnecessary splits in __asan_load1/__asan_store1
# see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
#
# FIXME NDD: These flags were copied from kasan, I'm not sure if they are needed.
CFLAGS_memorizer.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)

obj-y := memorizer.o kobj_metadata.o FunctionHashTable.o stats.o memalloc.o
