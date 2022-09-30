#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/mman.h>
int main( int argc, char *argv[] ) {
        char *mem;
        int fd;
        fd = open ("/dev/mem", O_RDWR);
        assert(fd >= 0);
       mem = mmap(NULL, getpagesize(), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_LOCKED, fd, (off_t) 0x800000000);
        assert(mem != MAP_FAILED);
        printf("Memory pointer: %p\n", mem);
       printf("The PCI memory is : %c\n",*mem);
       *mem = 'c';
       printf("The PCI memory is : %c\n", *mem);
       munmap(mem, getpagesize());
       close(fd);
       return 0;
}

