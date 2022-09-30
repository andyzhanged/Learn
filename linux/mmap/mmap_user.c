#include <unistd.h>
 #include <stdio.h>
 #include <fcntl.h>
 #include <assert.h>
 #include <sys/mman.h>
 int main( int argc, char *argv[] ) {
        char *mem;
        int fd;
        fd = open("/dev/zhanged_mem0", O_RDWR);
        assert(fd >= 0);
        printf("fd is %d\n", fd);
        printf("pid is %d\n", getpid());
        sleep(10);
        mem = mmap(NULL, getpagesize(), PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, fd, (off_t) (0x800000000 + 0x40000000));
        assert(mem != MAP_FAILED);
//        memset(mem, 0, getpagesize());
        printf("Memory pointer: %p\n", mem);
        int *zhanged = mem;
        printf("%x %x %x %x\n",*zhanged, *(zhanged + 1), *(zhanged + 2), *(zhanged + 3));
        *mem = 'a';
        printf("The PCI memory is : %c\n",*mem);
        *mem = 'c';
        printf("The PCI memory is : %c\n", *mem);

        char cpu_mem[128];
        memset(cpu_mem, 0, 128);
        printf("11111  %llx\n", *(unsigned long long*)(cpu_mem));
        printf("11111  %llx\n", *(unsigned long long*)(cpu_mem + 1));
        printf("11111  %llx\n", *(unsigned long long*)(cpu_mem + 2));
        printf("11111  %llx\n", *(unsigned long long*)(cpu_mem + 3));
        printf("11111  %llx\n", *(unsigned long long*)(cpu_mem + 4));
        printf("11111  %llx\n", *(unsigned long long*)(cpu_mem + 5));
        printf("11111  %llx\n", *(unsigned long long*)(cpu_mem + 6));
        printf("11111  %llx\n", *(unsigned long long*)(cpu_mem + 7));

        char *temp = mem;
        printf("temp addr is %p\n", temp);
        printf("22222  %llx\n", *(unsigned long long*)temp);
        printf("22222  %llx\n", *(unsigned long long*)(temp + 1));
        printf("22222  %llx\n", *(unsigned long long*)(temp + 2));
        printf("22222  %llx\n", *(unsigned long long*)(temp + 3));
        printf("22222  %llx\n", *(unsigned long long*)(temp + 4));
        printf("22222  %llx\n", *(unsigned long long*)(temp + 5));
        printf("22222  %llx\n", *(unsigned long long*)(temp + 6));
        printf("22222  %llx\n", *(unsigned long long*)(temp + 7));


        munmap(mem, getpagesize());
        sleep(2);
        close(fd);
        return 0;
 }

