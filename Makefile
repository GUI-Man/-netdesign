#KERN_DIR = /usr/src/$(shell uname -r)
KERN_DIR = /lib/modules/$(shell uname -r)/build
myfw-objs := my_dev.o #my_dev.o
obj-m += my_dev.o

all:
	make -C $(KERN_DIR) M=$(shell pwd) modules   
clean:                                  
	make -C $(KERN_DIR) M=$(shell pwd) modules clean
	rm -rf modules.order
	rm -f *.symvers
