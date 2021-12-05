# Makefile for QCA SON Memory Management Library

STORAGEDIR := $(shell pwd)

ifneq ($(strip $(TOOLPREFIX)),)
export  CROSS:=$(TOOLPREFIX)
endif

export CC = $(CROSS)gcc
export CFLAGS += -O2 -Wall -Werror -fPIC $(EXTRA_CFLAGS)
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
export LINK = $(CC) $(CFLAGS) $(EXTRA_LDFLAGS)

CFLAGS += -I.

STORAGE_INSTALL_ROOT := $(STORAGEDIR)/install

ifndef INSTALL_ROOT
INSTALL_ROOT=$(STORAGE_INSTALL_ROOT)
endif

STORAGE_INSTALL_INCLUDE = $(INSTALL_ROOT)/include
STORAGE_INSTALL_LIB = $(INSTALL_ROOT)/lib

# What we build by default:
ALL=libqcasonmemdebug.so

# For every C file to be compiled, place it's object file in the OBJS list
# (as required by Makefile.rules).
# Please keep in alphabetical order
OBJS = filter-mgmt.o memory-mgmt.o qca-son-mem-debug.o

# Making default targets:
all: local install
	@echo All done in `pwd`

local : $(ALL)
	@echo Made outputs in `pwd`

# Doing installation (see comments at top of this file)
# Note: header files should be installed with "ln -s -f" in order to
# prevent compiler from using old copies of local header files!
install: local
	cp -a -f $(ALL) $(STORAGE_INSTALL_LIB)
	cp -a -f common-lib.h filter-mgmt.h memory-mgmt.h qca-son-mem-debug.h son-mem-debug.h $(STORAGE_INSTALL_INCLUDE)
	@echo Installed outputs from `pwd`

# Making our specific library outputs
$(ALL) : $(OBJS)
	rm -f $@
	$(COMPILE) -shared -o $@ $(OBJS) $(LIBS)

# Remove all generated files
clean:
	@rm -f *.o *.so

.PHONY: all clean install


