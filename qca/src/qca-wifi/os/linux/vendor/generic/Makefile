#
# Copyright (c) 2013 Qualcomm Atheros, Inc.
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#

#
# Makefile for generic IOCTL
#

ifeq ($(obj),)
obj := .
endif

DEPTH := ../../../..

ifeq ($(BINDIR),)
BINDIR=/usr/local/bin
endif

include $(obj)/${DEPTH}/os/linux/Makefile.inc

INCS+= -I$(obj)/${DEPTH}/os/linux/vendor/generic/ioctl -I${obj}/${DEPTH} -I${WLAN}
CFLAGS=	${INCS} ${COPTS}

ifeq (${BUILD_DEBUG}, y)
CFLAGS += -g
endif

ifeq ($(BUILD_OPTIMIZED),y)
CFLAGS += -Os -pipe -mips32r2 -mtune=mips32r2 -funit-at-a-time
endif
