#ifndef __MEMRZ_ALLOC_TYPE
#define __MEMRZ_ALLOC_TYPE

enum AllocType {
    MEM_STACK=0,
    MEM_STACK_FRAME,
    MEM_STACK_ARGS,
    MEM_STACK_PAGE,
    MEM_HEAP,
    MEM_UFO_HEAP,
    MEM_GLOBAL,
    MEM_KMALLOC,
    MEM_KMALLOC_ND,
    MEM_KMEM_CACHE,
    MEM_KMEM_CACHE_ND,
    MEM_VMALLOC,
    MEM_ALLOC_PAGES,
    MEM_INDUCED,
    MEM_BOOTMEM,
    MEM_MEMBLOCK,
    MEM_UFO_MEMBLOCK,
    MEM_MEMORIZER,
    MEM_USER,
    MEM_BUG,
    MEM_UFO_GLOBAL,
    MEM_UFO_NONE,
    /* TODO: Legacy type, fix in tracking code to not use */
    MEM_NONE,
    NumAllocTypes
};

#endif