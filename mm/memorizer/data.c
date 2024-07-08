/*===-- LICENSE ------------------------------------------------------------===
 * Developed by:
 *
 *    Research Group of Professor Vikram Adve in the Department of Computer
 *    Science The University of Illinois at Urbana-Champaign
 *    http://web.engr.illinois.edu/~vadve/Home.html
 *
 * Copyright (c) 2015, Nathan Dautenhahn
 * Copyright (c) 2024, The Board of Trustees of University of Illinois
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *===-----------------------------------------------------------------------===
 *
 *       Filename:  data.c
 *
 *    Description:  Implements the data-related files in debugfs/memorizer.
 *
 *===-----------------------------------------------------------------------===
 */

#include <linux/bug.h>
#include <linux/gfp.h>
#include <linux/cpumask.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/memorizer.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <asm/page_64.h>
#include <linux/rbtree.h>
#include <linux/rwlock.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/smp.h>
#include <linux/workqueue.h>
#include <asm/atomic.h>
#include <asm/bitops.h>
#include <asm/percpu.h>
#include <linux/relay.h>
#include <asm-generic/bug.h>
#include <linux/cdev.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
// #include <linux/bootmem.h>
#include <linux/kasan-checks.h>
#include <linux/mempool.h>

#include<asm/fixmap.h>

#include "kobj_metadata.h"
#include "event_structs.h"
#include "FunctionHashTable.h"
#include "memorizer.h"
#include "stats.h"
#include "memalloc.h"
#include "../slab.h"
#include "../kasan/kasan.h"

/* Either a kobj represents an allocated
 * memory range, or it represents a free'd
 * memory range, or it is, itself, free'd
 * and ready for re-use.
 */
extern struct list_head memorizer_object_allocated_list;
extern struct list_head memorizer_object_freed_list;
extern struct list_head memorizer_object_reuse_list;


/*
 * kmap_seq_start() --- set up the next 'session' of the seq_file. N.b.
 *                      this function is called rougly once per `read()` syscall.
 *
 * We must not call seq_list_start(). On every call to seq_list_start, other
 * than the first, seq_list_next() is called pos times. Since
 * seq_list_start() is called roughly once per read(), this means that
 * seq_list_next is called O(n^2) times. 
 *
 * We are inside the memorizer_enter exclusion, so no locks are required. In fact,
 * the memorizer_enter exclusion goes from the open() to the release(), including
 * several read system calls in between. [I know that isn't what memorizer_enter
 * was written for. Maybe we should use some other exclusion device. Maybe
 * {kmap,clear_dead_obj,clear_printed_list} each set memorizer_enabled to 0?]
 * TODO robadams@illinois.edu - fix this locking silliness.
 */
static void *kmap_seq_start(struct seq_file *seq, loff_t *pos)
{
	/*
	 * The first time through, private and pos are both zero.
	 * The subsequent times before EOF, private and pos are both non-zero.
	 * At EOF, private is zero, pos is non-zero.
	 */
	if (!seq->private && !*pos) {
		seq->private = memorizer_object_allocated_list.next;
		return SEQ_START_TOKEN;
	}
	return seq->private;
}

/*
 * kmap_seq_next() --- move the head pointer in the list or return null
 */
static void *kmap_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct list_head *lh = v;
	struct list_head *next;

	++*pos;

	/* we are at the beginning */
	if (v == SEQ_START_TOKEN) {
		return seq->private;
	}

	next = lh->next;
	if (list_is_head(next, &memorizer_object_allocated_list)) {
		next = memorizer_object_freed_list.next;
	}
	if (list_is_head(next, &memorizer_object_freed_list)) {
		return NULL;
	}

	return next;
}

/*
 * kmap_seq_show() - print out the object including access info
 */
static int kmap_seq_show(struct seq_file *seq, void *v)
{
    struct access_from_counts *afc;
    struct memorizer_kobj *kobj = list_entry(v, struct memorizer_kobj, object_list);
    char *new_alloc_type = 0;
    uintptr_t free_ip = 0;
    int bkt;

    if (v == SEQ_START_TOKEN) {
        /* kmap file doesn't have a header */
        return 0;
    }

    read_lock(&kobj->rwlock);

    if ((kobj->free_index != 0) != (kobj->state == KOBJ_STATE_FREED)) {
        pr_err("kobj(%p)->free_index==%lu, ->state==%d\n",
               kobj, kobj->free_index, kobj->state);
        read_unlock(&kobj->rwlock);
        BUG();
    }

    /* Iff free_index is 0 then this object is live */
    if (!log_live_enabled.value && kobj->free_index == 0) {
        read_unlock(&kobj->rwlock);
        return 0;
    }
    kobj->printed = true;

    /* Print object allocation info */
    if ((kobj->free_ip >> 32) == 0xdeadbeef) {
        /* This allocation was replaced by another
         * allocation with no intervening `free()`
         * for reasons unknown. The subsequent
         * allocator is in `free_ip`.
         */
        new_alloc_type = alloc_type_str(kobj->free_ip & 0xffff);
        /* Some post-processing scripts expect to
         * see "DEADBEEF" in this case.
         */
        free_ip = 0xdeadbeef;
    } else if ((kobj->free_ip >> 32) == 0xfeed) {
        /* This allocation was replaced by another
         * allocation with no intervening `free()` due
         * to a nested allocation. The subsequent allocator
         * is in `free_ip`.
         * */
        new_alloc_type = alloc_type_str(kobj->free_ip & 0xffff);
        free_ip = 0xfedbeef;
    } else {
        /* Normal allocation */
        new_alloc_type = "";
        free_ip = kobj->free_ip;
    }
    seq_printf(seq, "%-p,%d,%p,%lu,%lu,%lu,%p,%s,%s,%s,%s\n",
               (void *)kobj->alloc_ip, kobj->pid, (void *)kobj->va_ptr,
               kobj->size, kobj->alloc_index, kobj->free_index, (void *)
               free_ip, alloc_type_str(kobj->alloc_type), kobj->comm,
               kobj->slabname, new_alloc_type);

    /* Iterate over the hashtable and print each access IP with counts */
    hash_for_each(kobj->access_counts, bkt, afc, hnode) {
        if (kobj->alloc_type == MEM_NONE) {
            seq_printf(seq, "  from:%p,%llu,%llu\n",
                       (void *)afc->ip,
                       (unsigned long long)afc->writes,
                       (unsigned long long)afc->reads);
        } else {
            seq_printf(seq, "  %p,%llu,%llu,%lld\n",
                       (void *)afc->ip,
                       (unsigned long long)afc->writes,
                       (unsigned long long)afc->reads,
                       (unsigned long long)afc->pid);
        }
    }

    read_unlock(&kobj->rwlock);
    return 0;
}


/*
 * allocs_seq_show() - print out the object
 */
static int allocs_seq_show(struct seq_file *seq, void *v)
{
	struct memorizer_kobj *kobj = list_entry(v, struct memorizer_kobj,
			object_list);
	char *new_alloc_type = 0;
	uintptr_t free_ip = 0;

	if (v == SEQ_START_TOKEN) {
		/* first time through, print the header */
		char *index_column = "serial";
		if(index_column_type == COLUMN_TIME)
			index_column = "time";

		seq_printf(seq, "alloc_ip,pid,ptr,size,alloc_%s,free_%s,free_ip,type,slab,new_type\n", index_column, index_column);
		return 0;
	}
	read_lock(&kobj->rwlock);
	/* If free_index is 0 then this object is live */
	if (!log_live_enabled.value && kobj->free_index == 0) {
		read_unlock(&kobj->rwlock);
		return 0;
	}
	kobj->printed = true;

	/* Print object allocation info */
	if((kobj->free_ip >> 32) == 0xdeadbeef) {
		/* This allocation was replaced by another
		 * allocation with no interveing `free()`
		 * for reasons unknown. The subsequent
		 * allocator is in `free_ip`.
		 */
		new_alloc_type = alloc_type_str(kobj->free_ip & 0xffff);
		/* Some post-processing scripts expect to
		 * see "DEADBEEF" in this case.
		 */
		free_ip = 0xdeadbeef;
	} else if ((kobj->free_ip >> 32) == 0xfeed) {
		/* This allocation was replaced by another
		 * allocation with no intervening `free()` due
		 * to a nested allocation. The subsequent allocator
		 * is in `free_ip`.
		 * */
		new_alloc_type = alloc_type_str(kobj->free_ip & 0xffff);
		free_ip = 0xfedbeef;
	} else {
		/* Normal allocation */
		new_alloc_type = "";
		free_ip = kobj->free_ip;
	}
	seq_printf(seq,"%-p,%d,%p,%lu,%lu,%lu,%p,%s,%s,%s,%s\n",
			(void*) kobj->alloc_ip, kobj->pid, (void*) kobj->va_ptr,
			kobj->size, kobj->alloc_index, kobj->free_index, (void*)
			free_ip, alloc_type_str(kobj->alloc_type), kobj->comm,
			kobj->slabname,new_alloc_type);

	read_unlock(&kobj->rwlock);
	return 0;
}

/*
 * accesses_seq_show() - print out the access info
 */
static int accesses_seq_show(struct seq_file *seq, void *v)
{
    struct access_from_counts *afc;
    struct memorizer_kobj *kobj;
    int bkt;

    if (v == SEQ_START_TOKEN) {
        /* first time through, print the header */
        seq_printf(seq,
                   "alloc_index,access_ip,"
#ifdef CONFIG_MEMORIZER_TRACKPIDS
                   "pid,"
#endif
                   "writes,reads\n");
        return 0;
    }

    kobj = list_entry(v, struct memorizer_kobj, object_list);

    read_lock(&kobj->rwlock);
    /* If free_index is 0 then this object is live */
    if (!log_live_enabled.value && kobj->free_index == 0) {
        read_unlock(&kobj->rwlock);
        return 0;
    }
    kobj->printed = true;

    /* print each access IP with counts and remove from hashtable */
    hash_for_each(kobj->access_counts, bkt, afc, hnode) {
        if (kobj->alloc_type == MEM_NONE) {
            seq_printf(seq, "  from:%p,%llu,%llu\n",
                       (void *)afc->ip,
                       (unsigned long long)afc->writes,
                       (unsigned long long)afc->reads);
        } else {
            seq_printf(seq,
#ifdef CONFIG_MEMORIZER_TRACKPIDS
                       "%llu,%p,%llu,%llu,%llu\n",
#else
                       "%llu,%p,%llu,%llu\n",
#endif
                       (unsigned long long)kobj->alloc_index,
                       (void *)afc->ip,
#ifdef CONFIG_MEMORIZER_TRACKPIDS
                       (unsigned long long)afc->pid,
#endif
                       (unsigned long long)afc->writes,
                       (unsigned long long)afc->reads);
        }
    }

    read_unlock(&kobj->rwlock);
    return 0;
}


/*
 * kmap_seq_stop() --- clean up on end of single read session.
 */
static void kmap_seq_stop(struct seq_file *seq, void *v)
{
	/*
	 * We are exiting the read syscall. We need a place
	 * to store our list pointer until the next read syscall.
	 */
	seq->private = v;
}

static const struct seq_operations kmap_stream_seq_ops = {
	.show = kmap_seq_show,
};
static const struct seq_operations kmap_seq_ops = {
	.start = kmap_seq_start,
	.next  = kmap_seq_next,
	.stop  = kmap_seq_stop,
	.show  = kmap_seq_show,
};
static const struct seq_operations allocs_seq_ops = {
	.start = kmap_seq_start,
	.next  = kmap_seq_next,
	.stop  = kmap_seq_stop,
	.show  = allocs_seq_show,
};
static const struct seq_operations accesses_seq_ops = {
	.start = kmap_seq_start,
	.next  = kmap_seq_next,
	.stop  = kmap_seq_stop,
	.show  = accesses_seq_show,
};

static int kmap_open(struct inode *inode, struct file *file)
{
	/* TODO robadams@illinois.edu
	 * We need to temporarily stop memorizer so that
	 * the seq_file iterator remains valid between
	 * syscalls. [Yes, I know. This is ugly and needs to
	 * be replaced.]
	 */
	if(__memorizer_enter()) {
		/*
		 * Probably should wait_event() here, but mem_access
		 * can't reliably call wake_up().
		 */
		return -EBUSY;
	}

	return seq_open(file, &kmap_seq_ops);

	/* __memorizer_exit to be called in kmap_release()  */
}

static int stream_open_(struct inode *inode,
	struct file *file,
	struct list_head* lh,
	struct seq_operations const *op)
{
	struct seq_file *seq;
	int rc = seq_open(file, op);
	if(rc < 0)
		return rc;

	seq = file->private_data;
	seq->private = lh;

	return rc;
}

static int kmap_stream_open(struct inode *inode, struct file *file)
{
	pr_info("Starting kmap streaming\n");
	return stream_open_(inode, file, &memorizer_object_freed_list, &kmap_stream_seq_ops);
}

static int kmap_stream_release(struct inode *inode, struct file *file)
{
	pr_info("Ending kmap streaming\n");
	return seq_release(inode, file);
}

static int kmap_release(struct inode *inode, struct file *file)
{
	int ret = seq_release(inode, file);

	/* __memorizer_enter called in kmap_open() */
	__memorizer_exit();
	return ret;
}



/*
 * Specialized seq_read for kmap. Ignore the file offset, always
 * return the next item.
 */
static ssize_t 
stream_seq_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	struct seq_file *m = file->private_data;
	struct list_head *lh = m->private;
	struct list_head *p;
	size_t count;
	int err;

	if(!size)
		return 0;

	if(!m->buf) {
		m->size = size;
		if(m->size < PAGE_SIZE)
			m->size = PAGE_SIZE;
		if(m->size > 1024 * PAGE_SIZE)
			m->size = 1024 * PAGE_SIZE;
		m->buf = kvmalloc(m->size, GFP_KERNEL_ACCOUNT);
		if(!m->buf)
			return -ENOMEM;
	}

	/* There may be leftover bytes from the previous read */
	if(m->count) {
		goto Drain;
	}

	m->from = 0;
		
	/* wait for data to be available */
	do {
		long err = wait_event_interruptible_timeout(object_list_wq, !list_empty(lh), HZ);
		if(err < 0)
			return err;
		p = pop_or_null_mementer(lh);
	} while(!p);
	INIT_LIST_HEAD(p);

	/* Format the data, resizing the buffer as required */
	while(1) {
		err = m->op->show(m, p);
		if(err < 0) {
			if(!__memorizer_enter_wait(1)) {
				list_add(p, lh);
				__memorizer_exit();
			}
			return err;
		}
		if(seq_has_overflowed(m)) {
			/* You're gonna need a bigger boat */
			kvfree(m->buf);
			m->size <<= 1;
			m->buf = kvmalloc(m->size, GFP_KERNEL_ACCOUNT);
			if(!m->buf) {
				if(!__memorizer_enter_wait(1)) {
					list_add(p, lh);
					__memorizer_exit();
				}
				return -ENOMEM;
			}
			continue;
		}
		break;
	}
	memorizer_discard_kobj(list_entry(p, struct memorizer_kobj, object_list));

#if 0
	/* TODO robadams@illinois.edu
	 * Returning one object per loop seems wasteful. If we steal the rest
	 * of the code from seq_read_iter, we need to be mindful of getting
	 * too far ahead of the reader. What would happen if we consume
	 * many more entries than the process can read?
	 */

	/* Next, grab as many results as will fit in the remaining buffer */
	while(1) {
		p = pop_or_null(lh);
		if(!p) {
			/* all of the source material is consumed */
			break;
		}
		size_t count = m->count;
		err = m->op->show(m, p);
		if(err < 0) {
			m->count = count;
			list_add(p, lh);
			return err;
		}
		if(seq_has_overflowed(m)) {
			/* If it doesn't fit, put it back */
			m->count = count;
			list_add(p, lh);
			break;
		}
		memorizer_discard_kobj(list_entry(p, struct memorizer_kobj, object_list));
	}
#endif

Drain:
	count = m->count;
	if(count > size) {
		count = size;
	}
	if(copy_to_user(buf, m->buf + m->from, count)) {
		return -EFAULT;
	}
	m->count -= count;
	m->from += count;
	return count;
}
static const struct file_operations kmap_stream_fops = {
	.owner		= THIS_MODULE,
	.open		= kmap_stream_open,
	.read		= stream_seq_read,
	.release	= kmap_stream_release,
};

static const struct file_operations kmap_fops = {
	.owner		= THIS_MODULE,
	.open		= kmap_open,
	.read		= seq_read,
	.release	= kmap_release,
};
static int allocs_open(struct inode *inode, struct file *file)
{
	/* We need to temporarily stop memorizer so that
	 * the seq_file iterator remains valid between
	 * syscalls. [Yes, I know. This is ugly and need to
	 * be replaced.]
	 */
	if(__memorizer_enter()) {
		/*
		 * Probably should wait_event() here, but mem_access
		 * can't reliably call wake_up().
		 */
		return -EBUSY;
	}
	return seq_open(file, &allocs_seq_ops);

	/* __memorizer_exit to be called in kmap_release()  */
}
static const struct file_operations allocs_fops = {
	.owner		= THIS_MODULE,
	.open		= allocs_open,
	.read		= seq_read,
	.release	= kmap_release,
};

static int accesses_open(struct inode *inode, struct file *file)
{
	/* We need to temporarily stop memorizer so that
	 * the seq_file iterator remains valid between
	 * syscalls. [Yes, I know. This is ugly and need to
	 * be replaced.]
	 */
	if(__memorizer_enter()) {
		/*
		 * Probably should wait_event() here, but mem_access
		 * can't reliably call wake_up().
		 */
		return -EBUSY;
	}
	return seq_open(file, &accesses_seq_ops);

	/* __memorizer_exit to be called in kmap_release()  */
}

static const struct file_operations accesses_fops = {
	.owner		= THIS_MODULE,
	.open		= accesses_open,
	.read		= seq_read,
	.release	= kmap_release,
};

static int function_calls_seq_show(struct seq_file *seq, void *v)
{
	struct EdgeBucket * b;
	int index;
	for (index = 0; index < cfgtbl -> number_buckets; index++) {
		b = cfgtbl -> buckets[index];
		while (b != NULL) {
			seq_printf(seq,"%lx %lx %ld\n", b -> from, b -> to, atomic_long_read(&b -> count));
			b = b -> next;
		}
	}
	return 0;
}

static int function_calls_open(struct inode *inode, struct file *file)
{
	return single_open(file, &function_calls_seq_show, NULL);
}

static const struct file_operations function_calls_fops = {
	.owner		= THIS_MODULE,
	.open		= function_calls_open,
	.read		= seq_read,
};

/* The debugging info generated by gcc doesn't quite include *everything*,
 * even when using -g3 for most debugging info. As far as I can tell, the
 * only things missing are some string constants, etc that are not very
 * interesting. However, on the uSCOPE analysis side, we really want to map
 * these back to files / folders for analysis. This interface lets you print
 * the entire global table exactly as KASAN sees it, so that everything matches
 * up and we get complete debug info for all globals. */
static int globaltable_seq_show(struct seq_file *seq, void *v)
{
  seq_printf(seq, "%s\n", global_table_text);
  return 0;
}

static int globaltable_open(struct inode *inode, struct file *file)
{
	return single_open(file, &globaltable_seq_show, NULL);
}

static const struct file_operations globaltable_fops = {
	.owner		= THIS_MODULE,
	.open		= globaltable_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/*
 * Late initialization function.
 */
int memorizer_data_late_init(struct dentry *dentryMemDir)
{
	debugfs_create_file("kmap", S_IRUGO, dentryMemDir,
			NULL, &kmap_fops);
	debugfs_create_file("kmap_stream", S_IRUGO, dentryMemDir,
			NULL, &kmap_stream_fops);
	debugfs_create_file("allocations", S_IRUGO, dentryMemDir,
			NULL, &allocs_fops);
	debugfs_create_file("accesses", S_IRUGO, dentryMemDir,
			NULL, &accesses_fops);
	debugfs_create_file("function_calls", S_IRUGO, dentryMemDir,
			NULL, &function_calls_fops);
	debugfs_create_file("global_table", S_IRUGO, dentryMemDir,
				     NULL, &globaltable_fops);

#ifdef CONFIG_MEMORIZER_DEBUGFS_RAM
	{
		extern uintptr_t pool_base;
		extern uintptr_t pool_end;
		static struct debugfs_blob_wrapper memalloc_blob;

		memalloc_blob.data = (void*)pool_base;
		memalloc_blob.size = pool_end - pool_base;
		debugfs_create_blob("memalloc_ram", S_IRUGO, dentryMemDir,
					&memalloc_blob);
	}
#endif
	return 0;
}


