#
# Makefile for Atheros tools.
#

ifeq ($(obj),)
obj := .
endif

DEPTH := ../../..
COMPONENT_DEV_TOOLS_PATH=${DEPTH}/component_dev/tools/linux
ifeq ($(BINDIR),)
BINDIR=/usr/local/bin
endif

ifeq ($(BUILD_X86),y)
UMAC_SUPPORT_CFG80211=0
endif

include $(obj)/${DEPTH}/os/linux/Makefile.inc

# Remove all the kernel include from the INCS variable as we're building
# a user space application
KMAJ := $(strip $(shell head -n 1 ${KERNELPATH}/Makefile | cut -f 2 -d'='))
KMIN := $(strip $(shell head -n 2 ${KERNELPATH}/Makefile | tail -1 | cut -f 2 -d'='))
KREV := $(strip $(shell head -n 3 ${KERNELPATH}/Makefile | tail -1 | cut -f 2 -d'='))

kver_ge = $(shell [ $(KMAJ)$(KMIN)$(KREV) -ge $(1)$(2)$(3) ] && \
		echo 1 || echo 0)

ifeq ($(call kver_ge,3,10,0), 1)
ifeq ($(QCA_THIRDPARTY), 1)
INCS:=$(filter-out -I${KERNELPATH}%, ${INCS})
COPTS:=$(filter-out -isystem${KERNELPATH}%, ${COPTS})
else
INCS:=$(filter-out -I${KERNELPATH}%, ${INCS})
COPTS:=$(filter-out -isystem ${KERNELPATH}%, ${COPTS})
INCS += -I$(KERNELPATH)/arch/$(KERNELARCH)/include/uapi
INCS += -I$(KERNELPATH)/arch/$(KERNELARCH)/include/generated/uapi
INCS += -I$(KERNELPATH)/include/uapi
INCS += -I$(KERNELPATH)/include/generated/uapi
INCS += -I$(KERNELPATH)/include
endif
else
ifeq ($(QCA_THIRDPARTY), 1)
INCS:=$(filter-out -I${KERNELPATH}%, ${INCS})
COPTS:=$(filter-out -isystem${KERNELPATH}%, ${COPTS})
else
INCS:=$(filter-out -I${KERNELPATH}%, ${INCS})
COPTS:=$(filter-out -isystem${KERNELPATH}%, ${COPTS})
endif
endif

ifneq ($(ARCH),mips)
COPTS:=$(filter-out -mcmodel=large, $(COPTS))
CFLAGS += -fpie
TARGET_CFLAGS += -fpie
LDFLAGS += -pie
TARGET_LDFLAGS += -pie
endif

ifeq ($(ARCH),x86_64)
TARGET_CFLAGS += -fPIC -mcmodel=medium
endif

ifeq ($(BUILD_X86),y)
TARGET_CFLAGS += -fPIC
endif

TARGET_CFLAGS += \
		-I$(STAGING_DIR)/usr/include/ \
		-I../../../cmn_dev/umac/cfr/dispatcher/inc \
		-I../../../umac/son/dispatcher/inc/ \
		-I../../../umac/son/os/linux

ifeq ($(ARCH),x86_64)
TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/libnl3
else
TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/libnl
TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/libnl3
endif

TARGET_LDFLAGS += \
		-lnl-3 -lnl-genl-3 -lpthread
ifeq ($(ATH_SUPPORT_CFG_8K), 1)
ALL=  libqca_tools.so cgiMain 80211stats athstats athstatsclr apstats athkey athchans athctrl athdebug wlanconfig \
      athcwm athampdutrc atrc pktlogconf pktlogdump thermaltool exttool qca_gensock
ATH_TOOLS= libqca_tools.so cgiMain 80211stats athstats athstatsclr apstats pktlogconf pktlogdump wifitool qldtool wlanconfig thermaltool exttool athkey qca_gensock
else
ALL=  libqca_tools.so 80211stats athstats athstatsclr apstats athkey athchans athctrl athdebug wlanconfig \
      athcwm athampdutrc atrc pktlogconf pktlogdump thermaltool wps_enhc exttool qca_gensock cfr_test_app peerratestats
ATH_TOOLS= libqca_tools.so 80211stats athstats athstatsclr apstats pktlogconf pktlogdump wifitool qldtool wlanconfig thermaltool wps_enhc exttool athkey qca_gensock cfr_test_app peerratestats

ifeq ($(UMAC_SUPPORT_WNM), 1)
ATH_TOOLS += wnm-app
endif
ifeq ($(UMAC_SUPPORT_CFG80211), 1)
ifeq ($(WIFISTATS_TOOL_SUPPORT),1)
ALL += wifistats
ALL += libwifistats.so
ATH_TOOLS += wifistats
ATH_TOOLS += libwifistats.so
endif
ifeq ($(STATS_TOOL_LIBRARIES),1)
ALL += libapstats.so
ATH_TOOLS += libapstats.so
endif
ALL += peerratestats
ATH_TOOLS += peerratestats
endif

ifeq ($(ATH_ACS_DEBUG_SUPPORT), 1)
ALL += acsdbgtool
ATH_TOOLS += acsdbgtool
endif
endif

ifeq ($(DEBUG_TOOLS), 1)
ATH_TOOLS += dumpregs reg
endif

ALL += athadhoc
ATH_TOOLS += athadhoc

ifneq ($(strip ${QCA_SUPPORT_SSID_STEERING}),0)
ALL += ssidsteering
ATH_TOOLS += ssidsteering
endif

ifneq ($(strip ${UMAC_SUPPORT_ACL}),0)
ALL += assocdenialnotify
ATH_TOOLS += assocdenialnotify
endif

ifneq ($(BOARD_TYPE),ap91-2MB)
ifneq ($(strip ${ATH_SUPPORT_DFS}),0)
ALL+= radartool
ATH_TOOLS+= radartool
endif

ifneq ($(strip ${QCA_ALLOW_DEV_TEST}),0)
ALL+=  dfs_inject_radar.o
ATH_TOOLS+= dfs_inject_radar.o
endif

ifneq ($(strip ${WLAN_SPECTRAL_ENABLE}),0)
ALL+= spectraltool
ATH_TOOLS+= spectraltool
# The following are added to compile spectraltool for x86
# platform
ifeq ($(TARGET),x86)
OS_VERSION:=$(shell uname -r)
AUTOCONF_PATH:=/usr/src/linux-headers-$(OS_VERSION)/include/
INCS += -I$(AUTOCONF_PATH)
endif
endif

ifeq ($(ATH_SUPPORT_TX99),1)
ALL+= tx99tool
ATH_TOOLS+= tx99tool
INCS += -I$(TX99)
endif
endif

ifeq ($(BUILD_X86),y)
Bx86_LIB= -lbsd
endif

all:	${ALL}

INCS += -I$(PERF_PWR_OFFLOAD_DIR_PATH)/include/fwcommon
INCS += -I$(PERF_PWR_OFFLOAD_DIR_PATH)/include/htt_stats
ifeq ($(WIFISTATS_TOOL_SUPPORT),1)

STAT_INCS= -I${DEPTH}/cmn_dev/fw_hdr/fw/
endif
INCS+= -I${obj}/${DEPTH} -I${COMMON} -I${WLAN}
CFLAGS += ${INCS} ${COPTS} ${QCACFLAGS}

ifeq (${BUILD_STATIC}, y)
LDFLAGS= -static
endif
LDFLAGS += ${QCALDFLAGS}
LDFLAGS += -L$(obj)/${DEPTH}/os/linux/tools
CFLAGS += -I$(obj)/${DEPTH}/os/linux/tools
CFLAGS += -I$(obj)/${DEPTH}/component_dev/dp/inc/
CFLAGS += -I$(obj)/${DEPTH}/offload/wlan/lmac_offload_if/

ifeq (${BUILD_DEBUG}, y)
CFLAGS += -g
endif

ifeq ($(ATH_CONFIG_NVRAM), 1)
CFLAGS += -DCONFIG_NVRAM=1
endif

ifndef __EXPORTED_HEADERS__
CFLAGS += -D__EXPORTED_HEADERS__
endif

CFLAGS += -DCONFIG_LOCALPC=1 -DCONFIG_DATA_AT_ROOT=1

ifeq ($(BUILD_OPTIMIZED),y)
ifeq ($(KERNELARCH),mips)
CFLAGS += -Os -pipe -mips32r2 -mtune=mips32r2 -funit-at-a-time
else
CFLAGS += -Os -pipe -funit-at-a-time
endif
endif

ifndef BUILD_HOSTAPD_071
export BUILD_HOSTAPD_071=0
endif

ifneq ($(strip ${BUILD_HOSTAPD_071}),0)
COPTS+= -DCFG_HOSTAPD_071=1
endif

ifndef BUILD_HOSTAPD_072
export BUILD_HOSTAPD_072=0
endif

ifneq ($(strip ${BUILD_HOSTAPD_072}),0)
COPTS+= -DCFG_HOSTAPD_072=1
endif

ifndef BUILD_ATHR_HOSTAP
export BUILD_ATHR_HOSTAP=0
endif

ifneq ($(strip ${BUILD_ATHR_HOSTAP}),0)
COPTS+= -DCFG_ATHR_HOSTAP=1
endif

DFLAGS+= -Wall -Werror

all:	${ALL}

ath_tools: ${ATH_TOOLS}
ifneq ($(BOARD_TYPE),ap91-2MB)
	cp athstats $(INSTALL_ROOT)/sbin;\
	cp 80211stats $(INSTALL_ROOT)/sbin;\
	cp athstatsclr $(INSTALL_ROOT)/sbin;\
	cp apstats $(INSTALL_ROOT)/sbin;\
	cp pktlogconf $(INSTALL_ROOT)/sbin;\
	cp pktlogdump $(INSTALL_ROOT)/sbin;\
	cp wifitool $(INSTALL_ROOT)/sbin;
	cp qldtool $(INSTALL_ROOT)/sbin;
	cp wlanconfig $(INSTALL_ROOT)/sbin;
	cp thermaltool $(INSTALL_ROOT)/sbin;
	cp exttool $(INSTALL_ROOT)/sbin;
	cp athkey $(INSTALL_ROOT)/sbin;
ifeq ($(ATH_SUPPORT_CFG_8K), 1)
	cp cgiMain $(INSTALL_ROOT)/sbin;
	cp scripts/wlan/rc.* $(INSTALL_ROOT)/sbin;
	cp scripts/network $(INSTALL_ROOT)/sbin;
	cp scripts/ip8k/ap* $(INSTALL_ROOT)/sbin;
	cp scripts/ip8k/*VAP $(INSTALL_ROOT)/sbin;
	cp scripts/ip8k/rcS $(INSTALL_ROOT)/sbin;
	cp scripts/ip8k/rc.network $(INSTALL_ROOT)/sbin;
	cp scripts/ip8k/rc.bridge $(INSTALL_ROOT)/sbin;
else
	cp wps_enhc $(INSTALL_ROOT)/sbin;
endif
ifneq ($(strip ${ATH_ACS_DEBUG_SUPPORT}),0)
	cp acsdbgtool $(INSTALL_ROOT)/sbin;
endif
ifneq ($(strip ${ATH_SUPPORT_DFS}),0)
	cp radartool $(INSTALL_ROOT)/sbin;
endif
ifneq ($(strip ${WLAN_SPECTRAL_ENABLE}),0)
	cp spectraltool $(INSTALL_ROOT)/sbin;
endif
	cp athadhoc $(INSTALL_ROOT)/sbin;
ifneq ($(strip ${QCA_SUPPORT_SSID_STEERING}),0)
	cp ssidsteering $(INSTALL_ROOT)/sbin;
endif
ifneq ($(strip ${UMAC_SUPPORT_ACL}),0)
	cp assocdenialnotify $(INSTALL_ROOT)/sbin;
endif
ifeq ($(ATH_SUPPORT_TX99),1)
	cp tx99tool $(INSTALL_ROOT)/sbin/tx99tool_bin;
endif
else
	@echo Athtools done....
endif
ifeq ($(DEBUG_TOOLS), 1)
	cp dumpregs $(INSTALL_ROOT)/sbin;
	cp reg $(INSTALL_ROOT)/sbin;
endif
ifeq ($(UMAC_SUPPORT_WNM), 1)
	cp wnm-app $(INSTALL_ROOT)/sbin;
endif
ifeq ($(UMAC_SUPPORT_CFG80211), 1)
ifeq ($(WIFISTATS_TOOL_SUPPORT),1)
	cp wifistats $(INSTALL_ROOT)/sbin/wifistats;
endif
endif


#- athampdutrc athcwm atrc pktlogconf pktlogdump radartool
QCA_TOOLS_LIB:=libqca_tools.so

libqca_tools.so: qcatools_lib.o
	$(CC) -shared -o libqca_tools.so ${CFLAGS} ${TARGET_CFLAGS} qcatools_lib.o

qcatools_lib.o: qcatools_lib.c
	${CC} -O -o qcatools_lib.o ${CFLAGS} ${TARGET_CFLAGS} -c qcatools_lib.c

dumpregs: hal_diag/dumpregs.o hal_diag/dumpregs_5212.o hal_diag/dumpregs_5416.o hal_diag/dumpregs_9300.o
	${CC} -o dumpregs ${CFLAGS} ${LDFLAGS} hal_diag/dumpregs.o \
		hal_diag/dumpregs_5212.o hal_diag/dumpregs_5416.o hal_diag/dumpregs_9300.o

reg: hal_diag/reg.c
	${CC} -o reg ${CFLAGS} ${LDFLAGS} hal_diag/reg.c

wps_enhc: wps_enhc.c $(QCA_TOOLS_LIB)
ifeq ($(UMAC_SUPPORT_CFG80211), 1)
	${CC} -o $@ ${CFLAGS} -I../ath ${LDFLAGS} ${TARGET_CFLAGS} ${TARGET_LDFLAGS} wps_enhc.c -lqca_tools -lqca_nl80211_wrapper
else
	${CC} -o $@ ${CFLAGS} -I../ath ${TARGET_CFLAGS} ${TARGET_LDFLAGS} -pthread -ldl $<
endif

athstats: athstats.c $(QCA_TOOLS_LIB)
ifeq ($(UMAC_SUPPORT_CFG80211), 1)
	${CC} -o athstats ${CFLAGS} -I../ath ${LDFLAGS} ${TARGET_CFLAGS}  athstats.c -lqca_tools -lqca_nl80211_wrapper ${TARGET_LDFLAGS}
else
	${CC} -o athstats ${CFLAGS} -I../ath ${LDFLAGS}  athstats.c qcatools_lib.c ${Bx86_LIB}
endif

athstatsclr: athstatsclr.c
	${CC} -o athstatsclr ${CFLAGS} -I../ath ${LDFLAGS} ${TARGET_CFLAGS} athstatsclr.c

apstats: apstats.c $(QCA_TOOLS_LIB)
ifeq ($(UMAC_SUPPORT_CFG80211), 1)
	${CC} -o apstats ${CFLAGS} -I../ath -I$(PERF_PWR_OFFLOAD_DIR_PATH)/include/legacy ${LDFLAGS} ${TARGET_CFLAGS} apstats.c -lqca_tools -lqca_nl80211_wrapper ${TARGET_LDFLAGS}
else
	${CC} -o apstats ${CFLAGS} -I../ath -I$(PERF_PWR_OFFLOAD_DIR_PATH)/include/legacy ${LDFLAGS}  apstats.c qcatools_lib.c ${Bx86_LIB}
endif


athctrl: athctrl.c
	${CC} -o athctrl ${CFLAGS} ${LDFLAGS} athctrl.c

athampdutrc: athampdutrc.c
	${CC} -o athampdutrc ${CFLAGS} -I../ath ${LDFLAGS} athampdutrc.c

80211stats: 80211stats.c
	${CC} -o 80211stats ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} 80211stats.c

thermaltool: thermaltool.c $(QCA_TOOLS_LIB)
ifeq ($(UMAC_SUPPORT_CFG80211), 1)
	${CC} -o thermaltool ${CFLAGS} -I$(PERF_PWR_OFFLOAD_DIR_PATH)/wlan/include ${LDFLAGS} ${TARGET_CFLAGS} thermaltool.c -lqca_nl80211_wrapper ${TARGET_LDFLAGS}
else
	${CC} -o thermaltool ${CFLAGS} -I$(PERF_PWR_OFFLOAD_DIR_PATH)/wlan/include ${LDFLAGS}  thermaltool.c
endif

exttool: exttool.c $(QCA_TOOLS_LIB)
ifeq ($(UMAC_SUPPORT_CFG80211), 1)
	${CC} -o exttool ${CFLAGS} -I./include ${LDFLAGS} ${TARGET_CFLAGS} exttool.c -lqca_tools -lqca_nl80211_wrapper ${TARGET_LDFLAGS}
else
	${CC} -o exttool ${CFLAGS} -I./include ${LDFLAGS}  exttool.c -lqca_tools
endif

athkey: athkey.c $(QCA_TOOLS_LIB)
ifeq ($(UMAC_SUPPORT_CFG80211), 1)
	${CC} -o athkey ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} athkey.c -lqca_tools -lqca_nl80211_wrapper ${TARGET_LDFLAGS}
else
	${CC} -o athkey ${CFLAGS} ${LDFLAGS}  athkey.c ${Bx86_LIB}
endif

ifeq ($(ATH_SINGLE_CFG),1)

CFLAGS += -DATH_SINGLE_CFG=1 -DKERNELVER='"$(KERNELVER)"'

ifeq ($(ATH_SINGLE_CFG_DISABLE_SET_DEFAULT),1)
CFLAGS += -DATH_SINGLE_CFG_DISABLE_SET_DEFAULT=1
endif

ifeq ($(KERNELVER),2.6.31)
IWDIR=$(TOPDIR)/apps/wireless_tools.29
else
IWDIR=$(TOPDIR)/apps/wireless_tools.28
endif
cgiMain: cgiMain.c
	${CC} -o cgiMain ${CFLAGS} ${LDFLAGS} cgiMain.c $(IWDIR)/iwlib.c -I $(IWDIR) -lm
ifneq ($(ATH_SUPPORT_CFG_8K), 1)
	cp cgiMain $(INSTALL_ROOT)/usr/www/cgi-bin
	ln -s /usr/www/cgi-bin/cgiMain $(INSTALL_ROOT)/bin/cfg
	ln -s /tmp $(INSTALL_ROOT)/var/run
endif
else
ifeq ($(BUILD_X86), y)
CFLAGS += -DCONFIG_DATA_AT_ROOT=1
endif
cgiMain: cgiMain.c
	$(CC) $(COPTS) -o cgiMain ${CFLAGS} ${LDFLAGS} cgiMain.c
ifneq ($(ATH_SUPPORT_CFG_8K), 1)
ifneq ($(BUILD_X86), y)
	cp cgiMain $(INSTALL_ROOT)/usr/www/cgi-bin
	ln -s /usr/www/cgi-bin/cgiMain $(INSTALL_ROOT)/bin/cfg
	ln -s /tmp $(INSTALL_ROOT)/var/run
endif
endif
endif

athdebug: athdebug.c
	${CC} -o athdebug ${CFLAGS} ${LDFLAGS} athdebug.c
wifitool: wifitool.c $(QCA_TOOLS_LIB)
ifeq ($(UMAC_SUPPORT_CFG80211), 1)
	${CC} -o wifitool ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} -pthread -ldl wifitool.c libqca_tools.so -lqca_nl80211_wrapper ${TARGET_LDFLAGS}
else
	${CC} -o wifitool ${CFLAGS} ${LDFLAGS} -pthread wifitool.c qcatools_lib.c ${Bx86_LIB}
endif
qldtool: qldtool.c $(QCA_TOOLS_LIB)
ifeq ($(UMAC_SUPPORT_CFG80211), 1)
	${CC} -o  qldtool ${CFLAGS} -g -I../../../cmn_dev/utils/qld/inc/ ${LDFLAGS} ${TARGET_CFLAGS} -pthread -ldl qldtool.c libqca_tools.so -lqca_nl80211_wrapper ${TARGET_LDFLAGS}
endif

wlanconfig: wlanconfig.c $(QCA_TOOLS_LIB)
ifeq ($(UMAC_SUPPORT_CFG80211), 1)
	${CC} -o wlanconfig ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} wlanconfig.c wlanconfig_atf.c wlanconfig_hmwds.c wlanconfig_misc.c wlanconfig_nac.c wlanconfig_nawds.c wlanconfig_vap.c wlanconfig_vendorie.c wlanconfig_wnm.c -lqca_nl80211_wrapper -lqca_tools ${TARGET_LDFLAGS}
else
	${CC} -o wlanconfig ${CFLAGS} ${LDFLAGS}  wlanconfig.c wlanconfig_atf.c wlanconfig_hmwds.c wlanconfig_misc.c wlanconfig_nac.c wlanconfig_nawds.c wlanconfig_vap.c wlanconfig_vendorie.c wlanconfig_wnm.c qcatools_lib.c ${Bx86_LIB}
endif
wnm-app: tfs-app.c
	${CC} -o wnm-app ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} tfs-app.c
80211debug: 80211debug.c
	${CC} -o 80211debug ${CFLAGS} ${LDFLAGS} 80211debug.c
athcwm: athcwm.c
	${CC} -o athcwm ${CFLAGS} -I../ath ${LDFLAGS} athcwm.c
atrc: atrc.c
	${CC} -o atrc ${CFLAGS} -I../atrc ${LDFLAGS} atrc.c
pktlogdump: pktlogdump.c
	${CC} -o pktlogdump ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} pktlogdump.c -lm ${Bx86_LIB}
athadhoc: athadhoc.c
	${CC} -o athadhoc ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} athadhoc.c -lm
ssidsteering: ssidsteering.c $(QCA_TOOLS_LIB)
	${CC} -o ssidsteering ${CFLAGS} ${TARGET_CFLAGS} ${LDFLAGS} ssidsteering.c -lm -lqca_tools -lqca_nl80211_wrapper ${TARGET_LDFLAGS}
assocdenialnotify: assocdenialnotify.c
	${CC} -o assocdenialnotify ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} assocdenialnotify.c -lm
pktlogconf: pktlogconf.c
	${CC} -o pktlogconf ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} pktlogconf.c ${Bx86_LIB}
radartool: radartool.c $(QCA_TOOLS_LIB)
ifeq ($(UMAC_SUPPORT_CFG80211), 1)
	${CC} -o radartool ${CFLAGS} -I../../../cmn_dev/umac/dfs/dispatcher/inc/ -I../ath ${LDFLAGS} ${TARGET_CFLAGS} radartool.c -lqca_tools -lqca_nl80211_wrapper ${TARGET_LDFLAGS}
else
	${CC} -o radartool ${CFLAGS} -I../../../cmn_dev/umac/dfs/dispatcher/inc/ -I../ath ${LDFLAGS} radartool.c -lqca_tools
endif

ifeq ($(QCA_ALLOW_DEV_TEST), 1)
dfs_inject_radar.o: dfs_inject_radar.c
	${CC} -o $@ -c $< ${CFLAGS} -I../../../cmn_dev/umac/dfs/dispatcher/inc/  -I../../../cmn_dev/umac/dfs/core/src/ -I../ath ${TARGET_CFLAGS} -g  -O0
endif


spectraltool: spectraltool.c $(QCA_TOOLS_LIB)
	${CC} -o spectraltool ${CFLAGS} -I../ath -I../../../cmn_dev/umac/dfs/dispatcher/inc/ -I../../../cmn_dev/spectral/dispatcher/inc/ -I../../../cmn_dev/os_if/linux/ ${LDFLAGS} ${TARGET_CFLAGS} spectraltool.c -lqca_tools -lqca_nl80211_wrapper -lm ${TARGET_LDFLAGS}
ifeq ($(ATH_SUPPORT_TX99),1)
tx99tool: tx99tool.c
	${CC} -o tx99tool ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} tx99tool.c
endif

ifeq ($(ATH_ACS_DEBUG_SUPPORT),1)
acsdbgtool: acsdbgtool.c $(QCA_TOOLS_LIB)
	${CC} -o acsdbgtool ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} acsdbgtool.c -lqca_tools -lqca_nl80211_wrapper ${TARGET_LDFLAGS}
endif

ifeq ($(UMAC_SUPPORT_CFG80211), 1)
libapstats.so: apstats.c
	${CC} -O -o apstats_api.o ${CFLAGS} -DAPSTATS_API  ${TARGET_CFLAGS} -c apstats.c
	${CC} -shared -o libapstats.so ${CFLAGS} ${TARGET_CFLAGS} apstats_api.o
ifeq ($(WIFISTATS_TOOL_SUPPORT),1)
wifistats: wifistats_main.o libwlanfw_htt.so libwlanfw_wmi.so $(QCA_TOOLS_LIB)
	${CC} -o wifistats ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} wifistats_main.o -lqca_tools -lwlanfw_htt -lwlanfw_wmi -lpthread -lqca_nl80211_wrapper ${TARGET_LDFLAGS}

wifistats_main.o: wifistats_main.c
	${CC} -O -o wifistats_main.o ${CFLAGS} ${TARGET_CFLAGS} -c wifistats_main.c

libwlanfw_htt.so: wlanfw_htt.o
	${CC} -shared -o libwlanfw_htt.so ${CFLAGS} ${TARGET_CFLAGS}  wlanfw_htt.o

libwlanfw_wmi.so: wlanfw_wmi.o
	${CC} -shared -o libwlanfw_wmi.so ${CFLAGS} ${TARGET_CFLAGS}  wlanfw_wmi.o
libwifistats.so: wifistats_main.c
	${CC} -O -o wifistats_main_api.o ${CFLAGS} -DWIFISTATS_API_INTERFACE  ${TARGET_CFLAGS} -c wifistats_main.c
	${CC} -shared -o libwifistats.so ${CFLAGS} ${TARGET_CFLAGS} wifistats_main_api.o

wlanfw_htt.o: ${DEPTH}/cmn_dev/fw-qca-stats/wifistats_wlanfw_htt.c
	${CC} -O -o wlanfw_htt.o ${STAT_INCS} ${CFLAGS} ${DFLAGS} ${TARGET_CFLAGS} -c ${DEPTH}/cmn_dev/fw-qca-stats/wifistats_wlanfw_htt.c

wlanfw_wmi.o: ${DEPTH}/cmn_dev/fw-qca-stats/wifistats_wlanfw_wmi.c
	${CC} -O -o wlanfw_wmi.o ${STAT_INCS} ${CFLAGS} ${DFLAGS} ${TARGET_CFLAGS} -c ${DEPTH}/cmn_dev/fw-qca-stats/wifistats_wlanfw_wmi.c

endif

endif

qca_gensock: qca_gensock.c
	${CC} -o qca_gensock ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} ${TARGET_LDFLAGS} qca_gensock.c -pthread

cfr_test_app: ${COMPONENT_DEV_TOOLS_PATH}/cfr_test_app.c
	${CC} -o ${COMPONENT_DEV_TOOLS_PATH}/cfr_test_app ${CFLAGS} ${LDFLAGS} ${TARGET_CFLAGS} ${TARGET_LDFLAGS} ${COMPONENT_DEV_TOOLS_PATH}/cfr_test_app.c

peerratestats: ${COMPONENT_DEV_TOOLS_PATH}/peerstats.c $(QCA_TOOLS_LIB)
	${CC} -o ${COMPONENT_DEV_TOOLS_PATH}/peerratestats ${CFLAGS} ${LDFLAGS} ${DFLAGS} ${TARGET_CFLAGS} -lpthread -lqca_tools ${COMPONENT_DEV_TOOLS_PATH}/peerstats.c -lqca_nl80211_wrapper ${TARGET_LDFLAGS}
install: ${ALL}
	cp athstats ${DESTDIR}${BINDIR}
	cp 80211stats ${DESTDIR}${BINDIR}
	cp athstatsclr ${DESTDIR}${BINDIR}
	cp apstats ${DESTDIR}${BINDIR}
	cp athampdutrc ${DESTDIR}${BINDIR}
	cp athcwm ${DESTDIR}${BINDIR}
	cp athdebug ${DESTDIR}${BINDIR}
	cp wifitool ${DESTDIR}${BINDIR}
	cp qldtool ${DESTDIR}${BINDIR}
	cp atrc ${DESTDIR}${BINDIR}
	cp pktlogconf ${DESTDIR}${BINDIR}
	cp pktlogdump ${DESTDIR}${BINDIR}
	-rm ${DESTDIR}/${BINDIR}/wlanstats
	ln ${DESTDIR}/${BINDIR}/80211stats ${DESTDIR}/${BINDIR}/wlanstats
	cp 80211debug ${DESTDIR}${BINDIR}
	-rm ${DESTDIR}/${BINDIR}/wlandebug
	ln ${DESTDIR}/${BINDIR}/80211debug ${DESTDIR}/${BINDIR}/wlandebug
	cp wlanconfig ${DESTDIR}${BINDIR}
	cp tfs-app ${DESTDIR}${BINDIR}
	cp radartool ${DESTDIR}${BINDIR}/radartool
	cp spectraltool ${DESTDIR}${BINDIR}/spectraltool
	cp thermaltool ${DESTDIR}${BINDIR}/thermaltool
	cp qca_gensock  ${DESTDIR}${BINDIR}
	cp ${COMPONENT_DEV_TOOLS_PATH}/cfr_test_app  ${DESTDIR}${BINDIR}
	cp ${COMPONENT_DEV_TOOLS_PATH}/peerratestats ${DESTDIR}${BINDIR}
ifeq ($(ATH_SUPPORT_CFG_8K), 1)
	cp cgiMain ${DESTDIR}${BINDIR}/cgiMain
	cp scripts/network ${DESTDIR}${BINDIR}
	cp scripts/wlan/rc.* ${DESTDIR}${BINDIR}
	cp scripts/ip8k/ap* ${DESTDIR}${BINDIR}
	cp scripts/ip8k/*VAP ${DESTDIR}${BINDIR}
	cp scripts/ip8k/rcS ${DESTDIR}${BINDIR}
	cp scripts/ip8k/rc.network ${DESTDIR}${BINDIR}
	cp scripts/ip8k/rc.bridge ${DESTDIR}${BINDIR}
else
	cp wps_enhc ${DESTDIR}${BINDIR}
endif
ifeq ($(ATH_SUPPORT_TX99),1)
	cp tx99tool ${DESTDIR}${BINDIR}
endif
ifeq ($(UMAC_SUPPORT_CFG80211), 1)
ifeq ($(WIFISTATS_TOOL_SUPPORT),1)
	cp wifistats $(INSTALL_ROOT)/sbin/wifistats;
endif
endif
ifeq ($(ATH_ACS_DEBUG_SUPPORT),1)
	cp acsdbgtool $(INSTALL_ROOT)/sbin;
endif

ath_tools_clean:
	@rm -f wps_enhc athstats 80211stats athstatsclr apstats pktlogdump pktlogconf radartool spectraltool tx99tool wifitool qldtool cgiMain wlanconfig thermaltool acsdbgtool qca_gensock ${COMPONENT_DEV_TOOLS_PATH}/cfr_test_app ${COMPONENT_DEV_TOOLS_PATH}/peerratestats
ifeq ($(DEBUG_TOOLS), 1)
	@rm -f dumpregs reg && rm -f hal_diag/*.o
endif

clean: ath_tools_clean
	rm -f ${ALL} core a.out *.o

spectraltool_clean:
	@rm -f spectraltool
