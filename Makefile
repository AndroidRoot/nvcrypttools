#!/usr/bin/make
CROSS_COMPILE ?= arm-none-linux-gnueabi-

CC := $(CROSS_COMPILE)gcc
MAKE ?= make

CFLAGS := -O2 -Wall -Wno-unused-variable -static -march=armv7-a -mthumb -I.
LDFLAGS := 
STRIP := $(CROSS_COMPILE)strip

SHARED_OBJS := nvaes.o nvrcm.o

#NVBLOB2GO_OBJS = gpiokeys.o scrollback.o

DEVICE_DIRS = $(shell find devices/ -mindepth 1 -maxdepth 1 -type d)
DEVICE_TARGETS = $(patsubst devices/%,%, $(DEVICE_DIRS))
DEVICE_RAMDISKS = $(patsubst %, %.cpio.gz, $(DEVICE_TARGETS))
DEVICE_BOOTIMGS = $(patsubst %, %.img, $(DEVICE_TARGETS))

all: nvsign nvencrypt nvdecrypt $(DEVICE_TARGETS)

$(DEVICE_TARGETS): nvblob2go.c $(SHARED_OBJS) bins
	$(CC) $(CFLAGS) -Idevices/$@ -o $@ nvblob2go.c $(SHARED_OBJS) $(LDFLAGS) && \
		$(STRIP) $@

%.cpio.gz: %
	@echo "Creating ramdisk $@"
	@rm -rf $<_ramdisk
	@rm -f $@
	@mkdir $<_ramdisk
	@cp $< $<_ramdisk/init
	@cp vfat.img $<_ramdisk/
	@cd $<_ramdisk && find|cpio -o -H newc|gzip -c > ../$@
	@rm -rf $<_ramdisk
	@echo Done

%.img: % %.cpio.gz
	@echo "Creating $@"
	mkbootimg --kernel devices/$</kernel.gz --ramdisk $<.cpio.gz -o $@

mknvfblob: mknvfblob.c $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $@.c $(SHARED_OBJS) && \
		$(STRIP) $@

nvsign: nvsign.c $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $@.c $(SHARED_OBJS)

nvencrypt: nvencrypt.c $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $@.c $(SHARED_OBJS)

nvdecrypt: nvdecrypt.c $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $@.c $(SHARED_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

bins:
	$(MAKE) -C devices


ramdisks: $(DEVICE_RAMDISKS)

bootimgs: $(DEVICE_BOOTIMGS)

clean: 
	@rm -f mknvfblob nvencrypt nvdecrypt nvsign $(SHARED_OBJS) \
		$(DEVICE_TARGETS) $(DEVICE_RAMDISKS)
	@make -C devices clean

.PHONY: all clean bins ramdisks
