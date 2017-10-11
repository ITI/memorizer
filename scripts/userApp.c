#define _GNU_SOURCE 
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include "event_structs.h"
#include <pthread.h>


#define ML 500000  // The size of profiler buffer (Unit: memory page)

#define BUFF_MUTEX_LOCK { \
		while(*buff_mutex)\
		*buff_mutex = *buff_mutex + 1;\
	}

#define BUFF_MUTEX_UNLOCK {*buff_mutex = *buff_mutex - 1;}

#define BUFF_FILL_RESET {*buff_fill = 0;}



static int buf_fd1;
static int buf_fd2;
static int buf_len;
struct stat s ;
char *buff1;
char *buff2;
char *buf;
char *buff_end;
char *buff_start;
char *buff_fill;
char *buff_mutex;
struct memorizer_kernel_event *mke_ptr;
unsigned int *buff_free_size; 
char *stringBase;
unsigned int idx;
char outputFileName[30];
FILE *fp;
char curBuf = 0;

/*
 * switchBuffer - switches the the buffer being written to, when the buffer is full
 */
void switchBuffer()
{
	if(!curBuf)
	{
		buf = (char *)buff1;
	
		buff_fill = buf;
		buf = buf + 1;
	
		buff_mutex = buf;
		buf = buf + 1;
	
	
		buff_free_size = (unsigned int *)buf;
		buf = buf + sizeof(unsigned int);
	

		buff_start = buf;
	

		//Switch to the first buffer
	}
	else
	{
		buf = (char *)buff2;
	
		buff_fill = buf;
		buf = buf + 1;
	
		buff_mutex = buf;
		buf = buf + 1;
	
	
		buff_free_size = (unsigned int *)buf;
		buf = buf + sizeof(unsigned int);
	

		buff_start = buf;


		//Switch to the second buffer
	}
}








// This function opens a character device (which is pointed by a file named as fname) and performs the mmap() operation. If the operations are successful, the base address of memory mapped buffer is returned. Otherwise, a NULL pointer is returned.
void *buf_init(char *fname,int *buf_fd)
{
	unsigned int *kadr;

	buf_len = ML * getpagesize();
	if ((*buf_fd=open(fname, O_RDWR|O_SYNC))<0){
	          printf("File open error. %s\n", fname);
	          return NULL;
	}
	kadr = mmap(0, buf_len, PROT_READ|PROT_WRITE, MAP_SHARED, *buf_fd, 0);
	if (kadr == MAP_FAILED){
		printf("Buf file open error.\n");
		return NULL;
		}
	return kadr;
}

// This function closes the opened character device file
void buf_exit(int buf_fd)
{
	if(buf_fd!=-1){
		close(buf_fd);
		buf_fd = -1;
	}
}

void printAllocHex()
{
	struct memorizer_kernel_alloc *mke_ptr;
	mke_ptr = (struct memorizer_kernel_alloc *)buf;
	fprintf(fp,"aa, ");
	fprintf(fp,"%llx, ",(unsigned long long)mke_ptr->event_ip);
	fprintf(fp,"%llx, ",(unsigned long long)mke_ptr->src_va_ptr);
	fprintf(fp,"%llx, ",(unsigned long long)mke_ptr->src_pa_ptr);
	fprintf(fp,"%x, ",mke_ptr->event_size);
	fprintf(fp,"%lx, ",mke_ptr->event_jiffies);	
	fprintf(fp,"%x, ",mke_ptr->pid);
	fprintf(fp,"%s, ",mke_ptr->comm);
	fprintf(fp,"%s\n",mke_ptr->funcstr);
	buf = buf + sizeof(struct memorizer_kernel_alloc);
//	fprintf(stderr, "before 1 incrementing = %u\n", *buff_free_size);
//	*buff_free_size = *buff_free_size + sizeof(struct memorizer_kernel_alloc);
//	fprintf(stderr, "after 1 incrementing = %u\n", *buff_free_size);
}

void printAlloc()
{
	struct memorizer_kernel_alloc *mke_ptr;
	mke_ptr = (struct memorizer_kernel_alloc *)buf;
	fprintf(fp,"Alloc: ");
	fprintf(fp,"%llx, ",(unsigned long long)mke_ptr->event_ip);
	fprintf(fp,"%llx, ",(unsigned long long)mke_ptr->src_va_ptr);
	fprintf(fp,"%llx, ",(unsigned long long)mke_ptr->src_pa_ptr);
	fprintf(fp,"%u, ",mke_ptr->event_size);
	fprintf(fp,"%lu, ",mke_ptr->event_jiffies);	
	fprintf(fp,"%u, ",mke_ptr->pid);
	fprintf(fp,"%s, ",mke_ptr->comm);
	fprintf(fp,"%s\n",mke_ptr->funcstr);
	buf = buf + sizeof(struct memorizer_kernel_alloc);
//	fprintf(stderr, "before 2 incrementing = %u\n", *buff_free_size);
//	*buff_free_size = *buff_free_size + sizeof(struct memorizer_kernel_alloc);
//	fprintf(stderr, "after 2 incrementing = %u\n", *buff_free_size);
}


void printFreeHex()
{
	struct memorizer_kernel_free *mke_ptr;
	mke_ptr = (struct memorizer_kernel_free *)buf;
	fprintf(fp,"0xbb, ");
	fprintf(fp,"%llx, ",(unsigned long long)mke_ptr->event_ip);
	fprintf(fp,"%llx, ",(unsigned long long)mke_ptr->src_va_ptr);
	fprintf(fp,"%lx, ",mke_ptr->event_jiffies);	
	fprintf(fp,"%x\n",mke_ptr->pid);
	buf = buf + sizeof(struct memorizer_kernel_free);
//	fprintf(stderr, "before 3 incrementing = %u\n", *buff_free_size);
//	*buff_free_size = *buff_free_size + sizeof(struct memorizer_kernel_free);
//	fprintf(stderr, "after 3 incrementing = %u\n", *buff_free_size);
}

void printFree()
{
	struct memorizer_kernel_free *mke_ptr;
	mke_ptr = (struct memorizer_kernel_free *)buf;
	fprintf(fp,"Free: ");
	fprintf(fp,"%llx, ",(unsigned long long)mke_ptr->event_ip);
	fprintf(fp,"%llx, ",(unsigned long long)mke_ptr->src_va_ptr);
	fprintf(fp,"%lu, ",mke_ptr->event_jiffies);	
	fprintf(fp,"%u\n",mke_ptr->pid);
	buf = buf + sizeof(struct memorizer_kernel_free);
//	fprintf(stderr, "before 4 incrementing = %u\n", *buff_free_size);
//	*buff_free_size = *buff_free_size + sizeof(struct memorizer_kernel_free);
//	fprintf(stderr, "after 4 incrementing = %u\n", *buff_free_size);
}

void printAccessHex(char type)
{
	struct memorizer_kernel_access *mke_ptr;
	mke_ptr = (struct memorizer_kernel_access *)buf;
	if(type=='r')
		fprintf(fp,"0xcc, ");
	else
		fprintf(fp,"0xdd, ");
	fprintf(fp,"%llx, ",(unsigned long long)mke_ptr->event_ip);
	fprintf(fp,"%llx, ",(unsigned long long)mke_ptr->src_va_ptr);
	fprintf(fp,"%x, ",mke_ptr->event_size);
	fprintf(fp,"%lx, ",mke_ptr->event_jiffies);	
	fprintf(fp,"%x\n",mke_ptr->pid);
	buf = buf + sizeof(struct memorizer_kernel_access);
//	fprintf(stderr, "before 5 incrementing = %u\n", *buff_free_size);
//	*buff_free_size = *buff_free_size + sizeof(struct memorizer_kernel_access);
//	fprintf(stderr, "after 5 incrementing = %u\n", *buff_free_size);
}


void printAccess(char type)
{
	struct memorizer_kernel_access *mke_ptr;
	mke_ptr = (struct memorizer_kernel_access *)buf;
	if(type=='r')
		fprintf(fp,"Read: ");
	else
		fprintf(fp,"Write: ");
	fprintf(fp,"%llx, ",(unsigned long long)mke_ptr->event_ip);
	fprintf(fp,"%llx, ",(unsigned long long)mke_ptr->src_va_ptr);
	fprintf(fp,"%u, ",mke_ptr->event_size);
	fprintf(fp,"%lu, ",mke_ptr->event_jiffies);	
	fprintf(fp,"%u\n",mke_ptr->pid);
	buf = buf + sizeof(struct memorizer_kernel_access);
//	fprintf(stderr, "before 6 incrementing = %u\n", *buff_free_size);
//	*buff_free_size = *buff_free_size + sizeof(struct memorizer_kernel_access);
//	fprintf(stderr, "after 6 incrementing = %u\n", *buff_free_size);
}

void printFork()
{
	struct memorizer_kernel_fork *mke_ptr;
	mke_ptr = (struct memorizer_kernel_fork *)buf;
	fprintf(fp,"Fork: ");
	fprintf(fp,"%ld, ",mke_ptr->pid);
	fprintf(fp,"%s\n",mke_ptr->comm);
	buf = buf + sizeof(struct memorizer_kernel_fork);
	fprintf(stderr, "before 7 incrementing = %u\n", *buff_free_size);
//	*buff_free_size = *buff_free_size + sizeof(struct memorizer_kernel_fork);
//	fprintf(stderr, "after 7 incrementing = %u\n", *buff_free_size);
}

int main (int argc, char *argv[])
{

	 
	if(argc != 2)
	{
		printf("Incorrect number of Command Line Arguments!\n");
		return 0;
	}

	// Open the Character Device and MMap 
	buff1 = buf_init("node1",&buf_fd1);
	if(!buff1)
		return -1;
	buff2 = buf_init("node2",&buf_fd2);
	if(!buff2)
		return -1;

	switchBuffer();
	
	printf("Choosing inital buffer\n");


	if(*argv[1]=='c')
	{
		printf("Remaining Bytes: ");
		printf("%u\n",*buff_free_size);
	}
	else if(*argv[1]=='p')
	{

		while(1)
		{
			
			
			// We Don't want the memorizer tracking us clearing out the buffer from userspace
			if(!*buff_fill)
			{
				curBuf = !curBuf;
				switchBuffer();
				BUFF_MUTEX_UNLOCK;
				continue;
			}
			
			printf("Userspace: Buffer Full! Now Clearing Buffer %d\n",curBuf);

			
			sprintf(outputFileName,"ouput%d",idx);
			fp = fopen(outputFileName,"w+");

			printf("Acquired the Lock\n");
			BUFF_MUTEX_LOCK;
			while(*buf!=0)
			{
				if(*buf == 0xffffffaa)
					printAlloc();
				else if (*buf == 0xffffffbb)
					printFree();
				else if(*buf == 0xffffffcc)
					printAccess('r');
				else if(*buf == 0xffffffdd)
					printAccess('w');
				else if(*buf == 0xffffffee)
					printFork();
				idx++;
			}
			*buff_fill = 0;
			BUFF_MUTEX_UNLOCK;
			printf("Done Printing\n");

			fclose(fp);
	
			idx++;

		}
			
	}
	else if(*argv[1]=='n')
	{
		*buff_free_size = 409599994;
		*buff_fill = 0;
	}
	
	buf_exit(buf_fd1);
	//printf("Closed the First Buffer\n");
	buf_exit(buf_fd2);
	//printf("Closed the Second Buffer\n");

	
	return 0;
}


