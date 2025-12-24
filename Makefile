obj-m += rw_universal.o

KDIR  ?= $(shell pwd)/kernel/android12-5.10
ARCH  ?= arm64
CROSS_COMPILE ?= aarch64-linux-android-

all:
	$(MAKE) -C $(KDIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) M=$(PWD) modules

sign:
	$(KDIR)/scripts/sign-file sha256 signing_key.pem signing_key.x509 rw_universal.ko

release:
	zip rw_universal-$(shell date +%Y%m%d).zip rw_universal.ko signing_key.x509

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
