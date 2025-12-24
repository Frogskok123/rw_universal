obj-m += rw_universal.o

KDIR ?= /lib/modules/$(shell uname -r)/build
ARCH ?= arm64

ifndef LLVM
    CROSS_COMPILE ?= aarch64-linux-gnu-
    CC ?= gcc
endif

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
