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

#define ML (100000)   // The size of profiler buffer (Unit: memory page)
#define BUFD_MAX 48000 // The max number of profiled samples stored in the profiler buffer




static int buf_fd = -1;
static int buf_len;


// This function opens a character device (which is pointed by a file named as fname) and performs the mmap() operation. If the operations are successful, the base address of memory mapped buffer is returned. Otherwise, a NULL pointer is returned.
void *buf_init(char *fname)
{
	unsigned int *kadr;

	if(buf_fd == -1){
	buf_len = ML * getpagesize();
	if ((buf_fd=open(fname, O_RDWR|O_SYNC))<0){
	          printf("File open error. %s\n", fname);
	          return NULL;
		}
	}
	kadr = mmap(0, buf_len, PROT_READ|PROT_WRITE, MAP_SHARED, buf_fd, 0);
	if (kadr == MAP_FAILED){
		printf("Buf file open error.\n");
		return NULL;
		}
	return kadr;
}

// This function closes the opened character device file
void buf_exit()
{
	if(buf_fd!=-1){
		close(buf_fd);
		buf_fd = -1;
	}
}




int main ()
{
	unsigned long long *buf;
	int index = 0;
	unsigned lonng long i;

	// Open the Character Device and MMap 
	buf = buf_init("node");
	if(!buf)
		return -1;
	//Read and count the MMaped data entries
	while(buf[index]!=0)
	{	
		if(buf[index]==0xaa || buf[index]==0xbb)
		i++;
	}

	
	buf_exit();
	printf("%ull",i);	
	
	return 0;
}

