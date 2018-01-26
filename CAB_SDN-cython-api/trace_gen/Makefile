KDIR            :=  /lib/modules/$(shell uname -r)/build
MODULE_NAME     :=  cecho
SRCDIR          :=  ./ 
INCDIR          :=  ./

SOURCES         :=  client_echo.c 
OBJECTS         :=  $(SOURCES:.c=.o)
EXTRA_CFLAGS    :=  -I$(PWD)/$(SRCDIR)  -I$(PWD)/$(INCDIR)

$(MODULE_NAME)-objs =   client_echo.o
obj-m       :=  $(MODULE_NAME).o
ccflags-y       :=  -std=gnu99 -DDEBUG -DLOC_DEBUG
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	# gcc -O2 vmf_user.c -o vmf_user
clean:
		rm -rf .*.o .tmp_versions .*.cmd *.mod.c *.ko *.ko.unsigned *.o Module.* modules.*
