obj-m += importer-dummy.o
KBUILD_EXTRA_SYMBOLS += /home/zhanged/code/my_github/Learn/linux/dma_buf/exporter/Module.symvers
all:
	make -C /lib/modules/$(shell uname -r)/build KBUILD_EXTMOD=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

