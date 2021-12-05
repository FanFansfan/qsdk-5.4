# Copyright (c) 2020 Qualcomm Technologies, Inc.
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.
#

TOP_SRCDIR = ../
include $(TOP_SRCDIR)/Makefile.defs

INSTALLHEADERS = meshIeee1905.h
TARGET_LIB = libmeshIeee1905.a
TARGET_OBJECTS = meshIeee1905.$(OBJEXT)

all: $(TARGET_LIB) install

$(TARGET_LIB): $(TARGET_OBJECTS)
	@rm -f $(TARGET_LIB)
	$(AR) $(ARFLAGS) $(TARGET_LIB) $(TARGET_OBJECTS)
	$(RANLIB) $(TARGET_LIB)

.c.o:
	$(COMPILE) -c $<

install: $(TARGET_LIB)
	@cp -a -f $(TARGET_LIB) $(MALIB_STATIC)/.
	@for file in $(INSTALLHEADERS) ; do ln -s -f `pwd`/$$file $(MAINCLUDE)/. ; done

clean:
	@rm -f *.o $(TARGET_LIB) *~

.PHONY: all clean

