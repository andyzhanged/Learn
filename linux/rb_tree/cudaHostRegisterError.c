#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <cuda_runtime.h>
#include <cstdio>

long freqNum = 375;
long computeChannelNum = 256;
long MAX_ARITHAVE_FRAMES = 400;

long *goodChannelData_real[8];
long *goodChannelData_real_host;

void *schedulerThread(void *arg)
{
    int devNo = (int)(long)arg;
    cudaSetDevice(devNo);

    long freqComputeChannelCount = freqNum * computeChannelNum;
    cudaMalloc((void **)&goodChannelData_real[devNo], MAX_ARITHAVE_FRAMES * freqComputeChannelCount * sizeof(long));
    cudaMemsetAsync(goodChannelData_real[devNo], 0xCAFE, MAX_ARITHAVE_FRAMES * freqComputeChannelCount * sizeof(long));
    cudaDeviceSynchronize();

    long copyByteSize = 230 * freqNum * 230 * sizeof(long);
    long gpuStartIndex = (freqNum * devNo) * 230 * 230;
    cudaMemcpy(goodChannelData_real[devNo], goodChannelData_real_host + gpuStartIndex, copyByteSize, cudaMemcpyHostToDevice);

    printf("in device GPU%d, ori pointer is %ld \n",devNo, goodChannelData_real[devNo]);
    printf("in device GPU%d, offset is %ld \n", devNo, goodChannelData_real_host + gpuStartIndex);

    long *temp = (long *)malloc(copyByteSize);
    cudaMemcpy(temp, goodChannelData_real[devNo], copyByteSize, cudaMemcpyDeviceToHost);

    char filed[200];
    char fileh[200];

    sprintf(filed, "./input_data_%d_dev", devNo);
    sprintf(fileh, "./input_data_%d_hst", devNo);
    printf("filed=%s, fileh=%s\n", filed, fileh);

    FILE *fd = fopen(filed, "wb");
    FILE *fh = fopen(fileh, "wb");

    fwrite(temp, 1, copyByteSize, fd);
    fwrite(goodChannelData_real_host + gpuStartIndex, 1, copyByteSize, fh);

    fclose(fd);
    fclose(fh);

    cudaFree(goodChannelData_real[devNo]);
    free(temp);
    return NULL;
}


int main(int argc, char *argv[])
{
    goodChannelData_real_host = (long *)malloc(3000L * 230 * 230 * 8);
    FILE *fd = fopen("./freqChannelDataAllR.bin", "rb");
    fread(goodChannelData_real_host, 1, 3000L * 230 * 230 * 8, fd);
    fclose(fd);

    pthread_t threadId[8];

    printf("test starting......\n");
    for (int i = 0; i < 1; i++)
    {
        pthread_create(&threadId[i], NULL, schedulerThread, (void *)(long)i);
    }
    for (int i = 0; i < 1; i++)
    {
        pthread_join(threadId[i], NULL);
    }

    schedulerThread(0);
    printf("test end......\n");
    free(goodChannelData_real_host);
    return 0;
}