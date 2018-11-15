#ifndef _LINUX_KASAN_CHECKS_H
#define _LINUX_KASAN_CHECKS_H
#include <linux/types.h>

#ifdef CONFIG_KASAN
bool kasan_obj_alive(const void *p, unsigned int size);
bool kasan_obj_stack(const void *p, unsigned int size);
void kasan_check_read(const void *p, unsigned int size);
void kasan_check_write(const void *p, unsigned int size);
#else
bool kasan_obj_alive(const void *p, unsigned int size) { }
static inline void kasan_check_read(const void *p, unsigned int size) { }
static inline void kasan_check_write(const void *p, unsigned int size) { }
#endif

#endif
