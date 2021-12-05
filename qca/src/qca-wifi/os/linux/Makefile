#
# Makefile for the HAL-based Atheros driver.
#
ifeq ($(obj),)
obj := $(shell pwd)
endif

DEPTH := ../..
TMP_FILE := $(DEPTH)/include/ieee80211_external_config.h.tmp
ORIGINAL_FILE := $(DEPTH)/include/ieee80211_external_config.h

ATH_BUILD= $(shell pwd)/ath

include $(obj)/$(DEPTH)/os/linux/Makefile.inc

obj-m += \
    $(DEPTH)/cmn_dev/qdf/ $(DEPTH)/asf/ \
    $(DEPTH)/cmn_dev/qdf/ $(DEPTH)/rawsim/

obj-m += $(DEPTH)/lmac/ath_pktlog/

ifeq ($(UNIFIED_SMARTANTENNA),1)
obj-m += $(DEPTH)/smartantenna/
endif

ifeq ($(MESH_MODE_SUPPORT),1)
obj-m += $(DEPTH)/testmodule/
endif

ifeq ($(ATH_PERF_PWR_OFFLOAD),1)

ifeq ($(strip $(ATH_HIF_TYPE)),sim)
obj-m += $(PERF_PWR_OFFLOAD_DIR_PATH)/host/hif/sim/linux/
endif

ifeq ($(strip $(ATH_HIF_TYPE)),sdio)
ifeq ($(strip $(NATIVE_SDIO)),0)
	obj-m += $(PERF_PWR_OFFLOAD_DIR_PATH)/host/sdiostack/src/
endif
endif

endif

ifneq ($(strip ${ATH_WLAN_COMBINE}),1)
obj-m += $(DEPTH)/qca_ol/
obj-m += $(DEPTH)/umac/
endif
ifeq ($(strip ${BUS}),USB)
obj-m += $(DEPTH)/os/linux/src/
endif
ifeq ($(ATH_SW_WOW_SUPPORT),1)
obj-m += $(DEPTH)/wow/
endif
ifeq ($(WIFI_MEM_MANAGER_SUPPORT),1)
obj-m += $(DEPTH)/os/linux/mem/
endif

WHUNT_MAKEOPTS:=CONFIG_PLD_PCIE_CNSS=0 CONFIG_AHB_FW_SIM=1 CONFIG_SHADOW_V2=1
WHUNT_FIRST_MAKEOPTS:=$(WHUNT_MAKEOPTS) MULTI_IF_NAME=sim0
WHUNT_SECOND_MAKEOPTS:=$(WHUNT_MAKEOPTS) MULTI_IF_NAME=sim1 WLAN_DISABLE_EXPORT_SYMBOL=1
WHUNT_THIRD_MAKEOPTS:=$(WHUNT_MAKEOPTS) MULTI_IF_NAME=sim2 WLAN_DISABLE_EXPORT_SYMBOL=1

all: compare
	echo $(INCS)
ifneq ($(BUILD_X86),y)
	rm -f $(TMP_FILE)
ifeq ($(strip ${QCA_PARTNER_MAKE_F_SUPPORT}),1)
	cd $(DEPTH)/cmn_dev/qdf/ && make -f Kbuild
	cd $(DEPTH)/asf/ && make -f Kbuild
	cd $(DEPTH)/lmac/ath_pktlog && make -f Kbuild
	cd $(DEPTH)/cmn_dev/spectral && make -f Kbuild
        cd $(DEPTH)/cmn_dev/qdf/ && make -f Kbuild
	cd $(DEPTH)/umac && make -f Kbuild
	cd $(DEPTH)/qca_ol && make -f Kbuild
#ifeq ($(QCA_SUPPORT_RAWMODE_PKT_SIMULATION),1)
#	cd $(DEPTH)/rawsim && make -f Kbuild
#endif
else
ifeq ($(CONFIG_WHUNT),1)
	($(foreach var,$(strip $(WHUNT_FIRST_MAKEOPTS)),export $(var);) \
		$(MAKE) -C $(KERNELPATH) KBUILD_EXTRA_SYMBOLS="$(WLAN_TOP)/Module.symvers" M=$(shell pwd) modules && \
		$(MAKE) -C $(KERNELPATH) KBUILD_EXTRA_SYMBOLS="$(WLAN_TOP)/Module.symvers" M=$(shell pwd)/$(DEPTH) modules)

	($(foreach var,$(strip $(WHUNT_SECOND_MAKEOPTS)),export $(var);) \
		$(MAKE) -C $(KERNELPATH) KBUILD_EXTRA_SYMBOLS="$(WLAN_TOP)/Module.symvers" M=$(shell pwd) modules && \
		$(MAKE) -C $(KERNELPATH) KBUILD_EXTRA_SYMBOLS="$(WLAN_TOP)/Module.symvers" M=$(shell pwd)/$(DEPTH) modules)

	($(foreach var,$(strip $(WHUNT_THIRD_MAKEOPTS)),export $(var);) \
                $(MAKE) -C $(KERNELPATH) KBUILD_EXTRA_SYMBOLS="$(WLAN_TOP)/Module.symvers" M=$(shell pwd) modules && \
                $(MAKE) -C $(KERNELPATH) KBUILD_EXTRA_SYMBOLS="$(WLAN_TOP)/Module.symvers" M=$(shell pwd)/$(DEPTH) modules)
else
	$(MAKE) -C $(KERNELPATH) KBUILD_EXTRA_SYMBOLS="$(WLAN_TOP)/Module.symvers" M=$(shell pwd) modules
ifeq ($(QCA_SINGLE_WIFI_3_0),1)
	$(MAKE) -C $(KERNELPATH) KBUILD_EXTRA_SYMBOLS="$(WLAN_TOP)/Module.symvers" M=$(shell pwd)/$(DEPTH) modules
endif
endif

endif
else
	$(MAKE) -C $(KERNELPATH) KBUILD_EXTRA_SYMBOLS="$(WLAN_TOP)/Module.symvers $(ATH_HAL)/Module.symvers" M=$(shell pwd) modules
endif

src_config:
ifneq ($(BUILD_X86),y)
	echo "===========================PREPARING EXTERNAL CONFIG======================================"
	-rm -f $(TMP_FILE)

	echo "#ifndef __IEEE80211_EXTERNAL_CONFIG__H" >> $(DEPTH)/include/ieee80211_external_config.h.tmp
	echo "#define __IEEE80211_EXTERNAL_CONFIG__H" >> $(DEPTH)/include/ieee80211_external_config.h.tmp

	$(foreach var,$(strip $(COPTS)), \
		echo $(if $(findstring -D,$(var)), "#ifndef" $(firstword $(subst =, ,$(subst -D, ,$(var))))) >> $(DEPTH)/include/ieee80211_external_config.h.tmp;\
		echo $(if $(findstring -D,$(var)), "#define" $(subst =, ,$(subst -D, ,$(var)))) >> $(DEPTH)/include/ieee80211_external_config.h.tmp;\
		echo $(if $(findstring -D,$(var)),"#endif") >> $(DEPTH)/include/ieee80211_external_config.h.tmp \
	;)
	echo "#endif" >> $(DEPTH)/include/ieee80211_external_config.h.tmp
endif

compare: src_config
ifneq ($(BUILD_X86),y)
	cmp -s $(TMP_FILE) $(ORIGINAL_FILE); \
	RETVAL=$$?; \
	if [ $$RETVAL -eq 0 ]; then \
		echo "Not copying external configs to header"; \
	else \
		echo "Copying external configs to header"; \
		rm -f $(ORIGINAL_FILE); \
		cp -af $(TMP_FILE) $(ORIGINAL_FILE); \
	fi
endif

install:
	echo "Making Linux Install"
	cd $(ATH_HAL) && make install
	echo IN DIRECTORY `pwd`
	cp ../../cmn_dev/qdf/*.ko $(MODULEPATH)
	cp ../../asf/*.ko $(MODULEPATH)
	cp ../../direct_attach/lmac/ath_dev/*.ko $(MODULEPATH)
	cp ../../lmac/ath_pktlog/*.ko $(MODULEPATH)
	cp ../../cmn_dev/qdf/*.ko $(MODULEPATH)
ifneq ($(strip ${ATH_WLAN_COMBINE}),1)
	cp ../../umac/*.ko $(MODULEPATH)
	cp ../../direct_attach/lmac/ratectrl/*.ko $(MODULEPATH)
endif
ifeq ($(ATH_PERF_PWR_OFFLOAD),1)
ifeq ($(strip $(ATH_HIF_TYPE)),sim)
	cp $(PERF_PWR_OFFLOAD_DIR_PATH)/host/hif/sim/linux/ath_sim.ko $(MODULEPATH)
endif
endif

ifneq ($(strip ${WLAN_SPECTRAL_ENABLE}),0)
	cp ../../cmn_dev/spectral/*.ko $(MODULEPATH)
endif

ifeq ($(strip ${BUS}),USB)
	cp src/*.ko $(MODULEPATH)
endif

ifeq ($(ATH_SUPPORT_TX99),1)
	cp ../../direct_attach/lmac/tx99/*.ko $(MODULEPATH)
endif

ifeq ($(ATH_SW_WOW_SUPPORT),1)
	cp ../../wow/*.ko $(MODULEPATH)
endif
ifeq ($(MESH_MODE_SUPPORT),1)
	cp ../../testmodule/*.ko $(MODULEPATH)
endif
ifeq ($(WIFI_MEM_MANAGER_SUPPORT),1)
	cp ../../os/linux/mem/*.ko $(MODULEPATH)
endif
	$(STRIP) -S $(MODULEPATH)/*.ko
#       $(MAKE) INSTALL_MOD_PATH=$(INSTALLROOT) -C $(KERNELPATH) SUBDIRS=$(shell pwd) modules_install
#ifeq ($(DESTDIR),)
#       (export MODULEPATH=${MODULEPATH}; /sbin/depmod -b ${MODULEPATH} -ae)
#endif

clean:
	cd $(ATH_HAL) && make clean
#	$(MAKE) -C $(KERNELPATH) SUBDIRS=$(ATH_BUILD) clean
#	$(MAKE) -C $(KERNELPATH) SUBDIRS=$(ATH) clean
	$(MAKE) -C $(KERNELPATH) M=$(ATH_RATE) clean
ifneq ($(strip ${WLAN_SPECTRAL_ENABLE}),0)
	$(MAKE) -C $(KERNELPATH) M=$(obj)/$(DEPTH)/cmn_dev/spectral clean
endif
	$(MAKE) -C $(KERNELPATH) M=$(ATH_PKTLOG) clean
	$(MAKE) -C $(KERNELPATH) M=$(obj)/$(DEPTH)/umac clean
	$(MAKE) -C $(KERNELPATH) M=$(obj)/$(DEPTH)/cmn_dev/qdf clean
	$(MAKE) -C $(KERNELPATH) M=$(obj)/$(DEPTH)/cmn_dev/qdf clean
	$(MAKE) -C $(KERNELPATH) M=$(obj)/$(DEPTH)/asf clean
ifeq ($(ATH_SUPPORT_TX99),1)
	$(MAKE) -C $(KERNELPATH) M=$(TX99) clean
endif
ifeq ($(ATH_SW_WOW_SUPPORT),1)
	$(MAKE) -C $(KERNELPATH) M=$(obj)/$(DEPTH)/wow clean
endif
ifeq ($(MESH_MODE_SUPPORT),1)
	$(MAKE) -C $(KERNELPATH) M=$(obj)/$(DEPTH)/testmodule clean
endif
	rm -rf .tmp_versions Module.symvers modules.order src/*.o src/.*.o.cmd
ifeq ($(strip ${QCA_PARTNER_MAKE_F_SUPPORT}),1)
	cd $(PERF_PWR_OFFLOAD_DIR_PATH) && find ./ -name *.o | xargs rm -f
endif
ifeq ($(ATH_HIF_TYPE),sdio)
ifeq ($(strip $(NATIVE_SDIO)),0)
	$(MAKE) -C $(KERNELPATH) M=$(shell readlink -f $(PERF_PWR_OFFLOAD_DIR_PATH)/host/sdiostack/src) clean
endif
endif
