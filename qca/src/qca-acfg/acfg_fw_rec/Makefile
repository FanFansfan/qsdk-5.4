CC=$(TOOLPREFIX)gcc

ACFG_FW_REC ?= acfg_fw_recovery

SRCS=$(shell ls *.c)
SRCS+=$(shell ls ../acfg_app_cmn/*.c|grep -v acfg_config)
SRCS+=$(shell ls ../src/appbr_if.c)
SRCS+=$(shell ls ../src/acfg_log.c)
OBJS=$(patsubst %.c,%.o,$(SRCS))
PWD=$(shell pwd)

CFLAGS := -I$(PWD)
CFLAGS += -I$(PWD)/../include
CFLAGS += -I$(PWD)/../acfg_app_cmn

CFLAGS += -I$(WLAN_TOP)/include
CFLAGS += -I$(WLAN_TOP)/include/libnl3/

CFLAGS += -I$(PWD) -I$(PWD)/../src -Wall
CFLAGS += -D_GNU_SOURCE
CFLAGS += -fpie

all:
	@echo -e "\nBuilding ACFG_FW_RECOVERY TESTAPP..."
	$(CC) $(SRCS) $(CFLAGS) $(COPTS) -o $(ACFG_FW_REC)

clean:
	@echo -e "\nCleaning ACFG_FW_RECOVERY  TESTAPP..."
	rm -f $(ACFG_FW_REC)
	rm -f $(OBJS)

