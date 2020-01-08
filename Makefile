obj-m+=firewall.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	$(CC) set_config.c -o test
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm test
#-include /lib/modules/$(shell uname -r)/build/Rules.make
