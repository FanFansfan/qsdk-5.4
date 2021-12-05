# wsplcd -- wifi setup over plc daemon
#
#

ifneq ($(strip $(TOOLPREFIX)),)
export  CROSS:=$(TOOLPREFIX)
endif

export CC = $(CROSS)gcc
export CFLAGS += -O2 -Wall -Werror $(EXTRA_CFLAGS)
ifeq ($(CALLTRACE_SUPPORT),y)
export CFLAGS += -O0 -g -lunwind-$(ARCH) -rdynamic -DCALLTRACE_SUPPORT=1
endif
export DEFS = 
export OBJEXT = o
export EXEEXT = 
export RANLIB = $(CROSS)ranlib
export STRIP = $(CROSS)strip
export ARFLAGS = cru
export AR = $(CROSS)ar
export COMPILE = $(CC) $(DEFS) $(INCLUDES) $(CFLAGS) -fpie
export LINK = $(CC) $(CFLAGS) $(EXTRA_LDFLAGS)

WSPLCD_INSTALL_ROOT := $(WSPLCDDIR)/install

ifndef INSTALL_ROOT
INSTALL_ROOT=$(WSPLCD_INSTALL_ROOT)
endif

CFLAGS += -I. -I$(ATHDIR) -I$(WPA2INCLUDE) -I$(GWINCLUDE) -I$(HYDINCLUDE) \
          -I$(STORAGEINCLUE) -L$(GWLIB) -I$(IEEE1905INCLUDE) \
          -I$(PLCSRV)
LIBS += -lhyficommon -lstorage -lwpa2 -lieee1905 -ldl -lwifisoncfg

ifeq ($(ENABLE_SON_MEMORY_DEBUG),y)
LIBS += -lqcasonmemdebug -lpthread
endif

ifeq ($(WSPLCD_SUPPORT_CFG80211),y)
LIBS += -lqca_nl80211_wrapper -lnl-3 -lnl-genl-3
endif

ifeq ($(LIBSTORAGE_UCI),y)
LIBS += -luci
endif

ifeq ($(GATEWAY_TR069),y)
LIBS += -L$(GWTOP)libath/polarssl  -lpolarssl  
endif

CFLAGS += -DATH_SUPPORT_LINKDIAG_EXT=1 -DCONFIG_CRYPTO_INTERNAL=1 -DATH_SUPPORT_HYFI_ENHANCEMENTS=1 -DQCA_AIRTIME_FAIRNESS=1

ifeq ($(ENABLE_SON_MEMORY_DEBUG),y)
CFLAGS += -I$(SONMEMDEBUGINCLUDE)
CFLAGS += -DSON_MEMORY_DEBUG
endif

ifeq ($(ENABLE_MAP),y)
CFLAGS += -DMAP_ENABLED
BINNAME = wsplcd-map
endif

ifeq ($(ENABLE_SON),y)
CFLAGS += -DSON_ENABLED
BINNAME = wsplcd-son
endif

ifeq ($(ENABLE_MAP),y)
ifeq ($(ENABLE_SON),y)
BINNAME = wsplcd
endif
endif

ifeq ($(HYFI10_COMPATIBLE),y)
CFLAGS += -DHYFI10_COMPATIBLE
endif

ALL=$(BINNAME)

all: $(ALL)
	$(MAKE) -C tools all install
	@echo wsplcd compiled ok

install: all
	@cp -a $(ALL) $(INSTALL_ROOT)/sbin
	@cp -f athx100.conf $(INSTALL_ROOT)/etc

# OBJS: object files for wsplcd program
OBJS += wsplcd.o apac_hyfi20.o apac_hyfi20_init.o  apac_hyfi20_wps.o apac_hyfi20_mib.o\
        pbc_hyfi20.o apac_hyfi20_ctrl.o ucpk_hyfi20.o apac_hyfi20_atf.o

ifeq ($(HYFI10_COMPATIBLE),y)
OBJS += wsplcd_hyfi10.o mib_wps.o apclone.o eap_wps.o legacy_ap.o
endif

ifeq ($(ENABLE_MAP),y)
OBJS += apac_map.o
endif

$(BINNAME): $(OBJS) $(COMMON_LIBS)
	$(COMPILE) -Xlinker --start-group $(OBJS) $(LIBS) -Xlinker --end-group -pie -o $@

clean:
	@rm -f core junk* *~ *.o *.d $(ALL)
	@$(MAKE) -C tools clean

