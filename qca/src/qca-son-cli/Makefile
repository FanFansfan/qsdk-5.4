# son_cli -- SON CLI command interface
#
#

-include Makefile.defs

ifneq ($(strip $(TOOLPREFIX)),)
export  CROSS:=$(TOOLPREFIX)
endif

export CC = $(CROSS)gcc
export CFLAGS += -O2 -Wall -Werror $(EXTRA_CFLAGS)
export OBJEXT = o
export RANLIB = $(CROSS)ranlib
export STRIP = $(CROSS)strip
export ARFLAGS = cru
export AR = $(CROSS)ar
export CFLAGS += -I. -I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/usr/include/libnl \
          -I$(STAGING_DIR)/usr/include/libnl3 -L$(STAGING_DIR)/usr/lib -I$(STAGING_DIR)/usr/include/hyficommon
export CFLAGS += -DUMAC_SUPPORT_CFG80211=1
export CFLAGS += -DSON_CLI_DBG_MODE=1
export CFLAGS += -DATH_SUPPORT_HYFI_ENHANCEMENTS=1
export CFLAGS += -UUMAC_SUPPORT_WEXT
export CFLAGS += -DQCA_SUPPORT_SON=1
export COMPILE = $(CC) $(DEFS) $(INCLUDES) $(CFLAGS) -fpie
export LINK = $(CC) $(CFLAGS) $(EXTRA_LDFLAGS)

SONCLI_INSTALL_ROOT := $(SONCLIDIR)/install

ifndef INSTALL_ROOT
INSTALL_ROOT=$(SONCLI_INSTALL_ROOT)
endif

LIBS = -lpthread  -lqca_nl80211_wrapper -lnl-3 -lhyficommon -lnl-genl-3


ifeq ($(ENABLE_SON_MEMORY_DEBUG),y)
CFLAGS += -DSON_MEMORY_DEBUG
endif

all: install

install: son_cli
	cp -a son_cli $(INSTALL_ROOT)/sbin
	cp -a -f meminfo.h $(INSTALL_ROOT)/include

# OBJS: object files for wsplcd program
OBJS += son_cli.o test_cases.o linux_netif.o

ifeq ($(ENABLE_SON_MEMORY_DEBUG),y)
OBJS += meminfo.o
endif

son_cli: $(OBJS)
	@echo "compiling SON binary"
	$(COMPILE) -Xlinker --start-group $(OBJS) $(LIBS) -Xlinker --end-group -pie -o $@

clean:
	@rm -f core junk* *~ *.o *.d son_cli

