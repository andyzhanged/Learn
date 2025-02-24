#!/bin/bash

# C 风格的 for 循环
for ((i=1; i<=5; i++))
do
    echo "Iteration $i"
	insmod ./dma_test.ko
	rmmod ./dma_test.ko
done
