ifneq ($(KERNELRELEASE),)
obj-m	:= authdev.o dummy_client.o kadmctrl_req.o kclient.o

else
KDIR	:= /lib/modules/$(MAKEFOR)/build
PWD		:= $(shell pwd)
CC := gcc
CFLAGS := -Wall -I../src
TESTS := dummy_authd

.PHONY = default clean tests

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

tests: $(TESTS)

dummy_authd: dummy_authd.o
	$(CC) -o $@ $^

clean:
	rm -f $(TESTS) *.o *.ko *.mod.c .*.cmd
endif
