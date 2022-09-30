#include <stdlib.h>

int main()
{
#if defined(__GNUC__)
#if defined(__i386__)
    asm("pushf \n\torl $0x40000, (%esp)\n\tpopf");
#elif defined(__x86_64__)
    asm("pushf \n\torl $0x40000, (%rsp)\n\tpopf");
#endif
#endif

    char buff[9];
    int *pi = (int *)(buff + 3);
    *pi = 42;
    return 0;
}
