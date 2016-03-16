#General Purpose Makefile for Linux Kernel module by guoqingbo

#KERN_DIR = /usr/src/kernels/2.6.32-220.el6.x86_64/
#KERN_DIR = /usr/src/$(shell uname -r)
KERN_DIR = /lib/modules/$(shell uname -r)/build
#KERN_DIR += ./include

iptable-objs := netfilter.o hook.o rule.o chardev.o
all:
	make -C $(KERN_DIR) M=$(shell pwd) modules

gcc:
	@gcc iptable-save.c -o iptable-save
	@gcc iptable -o iptable

clean:
	make -C $(KERN_DIR) M=$(shell pwd) modules clean
	@rm -rf modules.order
	@if (("0" < "$(shell lsmod | grep iptable | wc -l)"));				\
	then																\
		sudo rmmod iptable;												\
	else																\
		echo "iptable not running";										\
	fi

install:
	make -C $(KERN_DIR) M=$(shell pwd) modules
	@if (("0" >= "$(shell lsmod | grep iptable | wc -l)"));				\
	then																\
		sudo insmod iptable.ko;											\
	else																\
		echo "iptable is running";										\
	fi


obj-m += iptable.o
