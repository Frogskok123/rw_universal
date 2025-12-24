obj-m += rw_universal.o

KDIR  ?= $(shell pwd)/kernel/android12-5.10
ARCH  ?= arm64
CROSS_COMPILE ?= aarch64-linux-android21-
CC    := clang

all:
	$(MAKE) -C $(KDIR) \
		ARCH=$(ARCH) \
		CC=$(CC) \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		M=$(PWD) \
		modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

