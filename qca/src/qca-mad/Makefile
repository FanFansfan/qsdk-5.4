# Makefile for qca-mad
#
# Copyright (c) 2020 Qualcomm Technologies, Inc.
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.
#

-include Makefile.defs

MESHDIR := $(shell pwd)

ifneq ($(strip $(TOOLPREFIX)),)
export  CROSS:=$(TOOLPREFIX)
endif

export CC = $(CROSS)gcc
export CFLAGS += -O2 -Wall -Werror -fPIC
export CFLAGS += $(QCACFLAGS)
export LDFLAGS += ${QCALDFLAGS}
export DEFS =
export OBJEXT = o
export EXEEXT =
export RANLIB = $(CROSS)ranlib
export STRIP = $(CROSS)strip
export ARFLAGS = cru
export AR = $(CROSS)ar
export COMPILE = $(CC) $(DEFS) $(INCLUDES) $(CFLAGS)
export LINK = $(CC) $(CFLAGS) $(LDFLAGS)

CFLAGS += -I$(STAGING_DIR)/usr/include/hyficommon -I$(STAGING_DIR)/usr/include/wpa2

SRCDIRS = ieee1905 \
	  meshevent \
	  dataelements \
	  src

INSTALL_DIRS = lib \
	       include

# Making default targets:
all: installdirs subdirs mesh_telnet
	@echo All done in `pwd`

MESH_APPLICATION_DAEMON_TERMINAL := $(INSTALL_ROOT)/sbin/mat

mesh_telnet:
	@if [ ! -f $(MESH_APPLICATION_DAEMON_TERMINAL) ]; then \
		echo "telnet 127.0.0.1 7788" > $(MESH_APPLICATION_DAEMON_TERMINAL); \
		chmod 755 $(MESH_APPLICATION_DAEMON_TERMINAL); \
	fi

installdirs :
	@if [ -d $(firstword $(SRCDIRS)) ]; then \
		for dir in $(INSTALL_DIRS); do (mkdir -p $(MA_INSTALL_ROOT)/$$dir); done ;\
	fi

subdirs : installdirs
	@if [ -d $(firstword $(SRCDIRS)) ]; then \
		for dir in $(SRCDIRS) ; do (cd $$dir && $(MAKE) all) || exit 1; done ;\
	fi

# Remove all generated files
clean:
	@if [ -d $(firstword $(SRCDIRS)) ]; then \
		rm -rf install ;\
		for dir in $(SRCDIRS)  ; do (cd $$dir && $(MAKE) clean) || exit 1; done ;\
		find . -name *.o -o -name *.d | xargs rm -rf ;\
	fi
	@$(MAKE) -C plugins clean

.PHONY: all clean install

