obj-m += xor-generic.o
obj-m += test_xor.o
obj-m += test_cbc_xor.o
obj-m += create_xor_cbc.o

PWD := $(CURDIR)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
