#include <stdlib.h>
#include <time.h>

//#define DO_PREFETCH
int binary_search(int *array, int number_of_elements, int key)
{
    int low = 0, hight = number_of_elements - 1, mid;
    while (low <= hight){
        mid = (hight + low) / 2;
#ifdef DO_PREFETCH
        __builtin_prefetch(&array[(mid + 1 + hight) / 2], 0, 1);
        __builtin_prefetch(&array[(low - 1 + mid) / 2], 0, 1);
#endif
        if(array[mid] < key)
            low = mid + 1;
        else if(array[mid] == key)
            return mid;
        else if(array[mid] > key)
            hight = mid - 1;
    }

    return -1;
}

int main()
{
    int size = 1024 * 1024 * 512;
    int *array = malloc(size * sizeof(int));
    for (size_t i = 0; i < size; i++)
        array[i] = i;

    int num_lookups = 1024 * 1024 * 8;
    srand(time(NULL));
    int *lookups = malloc(num_lookups * sizeof(int));
    for (size_t i = 0; i < size; i++)
        lookups[i] = rand() % size;

    for (size_t i = 0; i < num_lookups; i++)
    {
        int result = binary_search(array, size, lookups[i]);
    }

    //free(array);
    free(lookups);
}