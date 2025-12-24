# Имя модуля
obj-m += rw_universal.o

# Определяем путь к ядру, если он не передан извне
# В GitHub Actions мы будем передавать KDIR явно, но для локальной сборки оставим дефолт
KDIR ?= /lib/modules/$(shell uname -r)/build

# Настройки по умолчанию, если не переданы из командной строки
ARCH ?= arm64

# Если LLVM=1 не передан, пытаемся использовать стандартный кросс-компилятор
# Но лучше всегда передавать LLVM=1 при вызове make
ifndef LLVM
    CROSS_COMPILE ?= aarch64-linux-gnu-
    CC ?= gcc
endif

all:
\t$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
\t$(MAKE) -C $(KDIR) M=$(PWD) clean
