DISK=$1
shift;

# Allocate to memorizer with minimally 3GB region else lookup tables will fail. 
# Here we allocate the machine 20GB and memorizer 10GB.
MEM_VM=20
MEM_MEMORIZER=10

qemu-system-x86_64 --enable-kvm -nographic -cpu host -m ${MEM_VM}G \
     -kernel arch/x86/boot/bzImage -append "console=ttyS0 root=/dev/sda2 memalloc=$MEM_MEMORIZER" \
     -hda $DISK \
     $@