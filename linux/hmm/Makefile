obj-m := test_hmm.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

#obj-m := gup_test.o
gup_test:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
test:
	gcc -g hmm-tests.c -I../tools/testing/selftests/ -I../mm -o hmm-tests
