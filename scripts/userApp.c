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

#define ML 100000  // The size of profiler buffer (Unit: memory page)
#define BUFD_MAX 48000 // The max number of profiled samples stored in the profiler buffer

#define BUFF_MUTEX_LOCK { \
		while(*buff_mutex); \
		*buff_mutex = *buff_mutex + 1;\
	}

#define BUFF_MUTEX_UNLOCK {*buff_mutex = *buff_mutex - 1;}

#define BUFF_FILL_RESET {*buff_fill = 0;}



static int buf_fd = -1;
static int buf_len;
struct stat s ;

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




int main (int argc, char *argv[])
{
	char *buf;
	char *buff_end;
	char *buff_fill;
	unsigned int *buff_free_size; 
	unsigned long long index = 0;
	unsigned long long i;
	if(argc != 2)
	{
		printf("Incorrect number of Command Line Arguments!\n");
		return 0;
	}

	// Open the Character Device and MMap 
	buf = buf_init("node");
	if(!buf)
		return -1;

	//Read and count the MMaped data entries
	buff_end = (buf + ML*getpagesize()) - 1;
	buff_fill = buf;
	buf++;
	buff_free_size = (unsigned int *)buf;
	buf = buf + sizeof(unsigned int);

	if(*argv[1]=='c')
	{
		printf("Remaining Bytes: ");
		printf("%u",*buff_free_size);
	}
	else if(*argv[1]=='p')
	{
	//while(1)
	//{
		//BUFF_MUTEX_LOCK;
		//while(!*buff_fill);
		while(buf+index != buff_end)
		{
			printf("%u",buf[index]);
			index++;
			*buff_free_size = *buff_free_size + 1;
			//BUFF_FILL_RESET;

		}
		/**buff_free_size = *buff_free_size +1;
		if(buf + index == buff_end)
			index = 0;
		else
			index++;*/
		//BUFF_MUTEX_UNLOCK;
	//}
	


	}	
	buf_exit();
	
	return 0;
}

