// SPDX-License-Identifier: GPL-2.0
/*
 * Interface borrowed from mm/kasan/generic.c (Kernel v5.15.15)
 */

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/memorizer.h>

/* The layout of struct dictated by compiler */
static struct nssan_global {
	const void *beg;		/* Address of the beginning of the global variable. */
	size_t size;			/* Size of the global variable. */
	size_t size_with_redzone;	/* Size of the variable + size of the red zone. 32 bytes aligned */
	const void *name;
	const void *module_name;	/* Name of the module where the global variable is declared. */
	unsigned long has_dynamic_init;	/* This needed for C++ */
	struct kasan_source_location *location;
	char *odr_indicator;
};

static void register_global(struct nssan_global *global)
{
	memorizer_register_global(global->beg, global->size);
	int written = sprintf(global_table_ptr, "%p %d %s %s\n", global -> beg,
		(int)(global -> size), (char *)(global -> name), (char *)(global -> module_name));
	global_table_ptr += written;
}

void __nssan_register_globals(struct nssan_global *globals, size_t size)
{
	int i;

	for (i = 0; i < size; i++)
		register_global(&globals[i]);
}
EXPORT_SYMBOL(__nssan_register_globals);

void __nssan_unregister_globals(struct nssan_global *globals, size_t size)
{
}
EXPORT_SYMBOL(__nssan_unregister_globals);

// TODO: move the following into void __nssan_load##size(unsigned long addr)
// memorizer_mem_access(addr, size, false, _RET_IP_);

#define DEFINE_ASAN_LOAD_STORE(size)					\
	void __nssan_load##size(unsigned long addr)			\
	{								\
	}								\
	EXPORT_SYMBOL(__nssan_load##size);				\
	__alias(__nssan_load##size)					\
	void __nssan_load##size##_noabort(unsigned long);		\
	EXPORT_SYMBOL(__nssan_load##size##_noabort);			\
	void __nssan_store##size(unsigned long addr)			\
	{								\
		memorizer_mem_access(addr, size, true, _RET_IP_);	\
	}								\
	EXPORT_SYMBOL(__nssan_store##size);				\
	__alias(__nssan_store##size)					\
	void __nssan_store##size##_noabort(unsigned long);		\
	EXPORT_SYMBOL(__nssan_store##size##_noabort)

DEFINE_ASAN_LOAD_STORE(1);
DEFINE_ASAN_LOAD_STORE(2);
DEFINE_ASAN_LOAD_STORE(4);
DEFINE_ASAN_LOAD_STORE(8);
DEFINE_ASAN_LOAD_STORE(16);

void __nssan_loadN(unsigned long addr, size_t size)
{
	memorizer_mem_access(addr, size, false, _RET_IP_);
}
EXPORT_SYMBOL(__nssan_loadN);

__alias(__nssan_loadN)
void __nssan_loadN_noabort(unsigned long, size_t);
EXPORT_SYMBOL(__nssan_loadN_noabort);

void __nssan_storeN(unsigned long addr, size_t size)
{
	memorizer_mem_access(addr, size, true, _RET_IP_);
}
EXPORT_SYMBOL(__nssan_storeN);

__alias(__nssan_storeN)
void __nssan_storeN_noabort(unsigned long, size_t);
EXPORT_SYMBOL(__nssan_storeN_noabort);

/* to shut up compiler complaints */
void __nssan_handle_no_return(void) {}
EXPORT_SYMBOL(__nssan_handle_no_return);