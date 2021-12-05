CC=$(TOOLPREFIX)gcc

ACFG_PROFILE_BINARY ?= acfg_set_profile

SRCS=$(shell ls *.c)
SRCS+=$(shell ls ../acfg_app_cmn/*.c)
OBJS=$(patsubst %.c,%.o,$(SRCS))
PWD=$(shell pwd)

CFLAGS := -I$(PWD)
CFLAGS += -I$(PWD)/../include
CFLAGS += -I$(PWD)/../acfg_app_cmn

CFLAGS += -I$(WLAN_TOP)/include
CFLAGS += -I$(WLAN_TOP)/include/libnl3/
LDFLAGS += -pie -lnl-3 -lnl-genl-3 -lqca_nl80211_wrapper -l$(PROFILE_LIB_OUT)

CFLAGS += -L$(PWD)/../src
CFLAGS += -I$(PWD) -I$(PWD)/../src -Wall
CFLAGS += -D_GNU_SOURCE
CFLAGS += -fpie

all:
	@echo -e "\nBuilding ACFG PROFILE APP..."
	$(CC) $(SRCS) $(CFLAGS) $(LDFLAGS) $(COPTS) -o $(ACFG_PROFILE_BINARY)

clean:
	@echo -e "\nCleaning ACFG PROFILE TESTAPP..."
	rm -f $(ACFG_PROFILE_BINARY)
	rm -f $(OBJS)
