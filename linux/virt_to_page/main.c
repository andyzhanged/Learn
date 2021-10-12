#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

int main()
{
    int fd = open("/dev/mmap_test", O_RDONLY);
    if(fd < 0){
	printf("open file error\n");
    	return -1;
    }
    char *str = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0x5000);
    close(fd);
    return 0;
}
