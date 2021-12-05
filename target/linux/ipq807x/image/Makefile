# Copyright (c) 2014 The Linux Foundation. All rights reserved.
#
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

define Device/Default
	PROFILES := Default
	KERNEL_LOADADDR := 0x41080000
	KERNEL_DEPENDS = $$(wildcard $(DTS_DIR)/$$(DEVICE_DTS).dts)
	KERNEL_INITRAMFS_PREFIX := $$(IMG_PREFIX)-$(1)-initramfs
	KERNEL_PREFIX := $$(IMAGE_PREFIX)
	SUPPORTED_DEVICES = $$(BOARD_NAME)
	IMAGE/sysupgrade.bin = sysupgrade-tar | append-metadata
	IMAGE/sysupgrade.bin/squashfs :=
endef

define Device/LegacyImage
	KERNEL_SUFFIX := -uImage
	KERNEL = kernel-bin | append-dtb | uImage none
	KERNEL_NAME := zImage
endef

define Device/FitImage
	KERNEL_SUFFIX := -fit-uImage.itb
	KERNEL = kernel-bin | gzip | fit gzip $$(DTS_DIR)/$$(DEVICE_DTS).dtb
	KERNEL_NAME := Image
endef

define Device/FitImageLzma
	KERNEL_SUFFIX := -fit-uImage.itb
	KERNEL = kernel-bin | lzma | fit lzma $$(DTS_DIR)/$$(DEVICE_DTS).dtb
	KERNEL_NAME := Image
endef

define Device/UbiFit
	KERNEL_IN_UBI := 1
	IMAGES := nand-factory.bin nand-sysupgrade.bin
	IMAGE/nand-factory.bin := append-ubi
	IMAGE/nand-sysupgrade.bin := sysupgrade-tar | append-metadata
endef

define Device/xiaomi_ax9000
	$(call Device/FitImage)
	$(call Device/UbiFit)        
	DEVICE_DTS := ipq8074-ax9000
	DEVICE_DTS_CONFIG := config@hk14
	BLOCKSIZE := 128k
	PAGESIZE := 2048
	BOARD_NAME := ap-hk14
	DEVICE_TITLE := XIAOMI AX9000
endef
TARGET_DEVICES += xiaomi_ax9000

define Device/qcom_ap-hk14
	$(call Device/FitImage)
	$(call Device/UbiFit)        
	DEVICE_DTS := ipq8074-hk14
	DEVICE_DTS_CONFIG := config@hk14
	BLOCKSIZE := 128k
	PAGESIZE := 2048
	BOARD_NAME := ap-hk14
	DEVICE_TITLE := QCOM AP-HK14
endef
TARGET_DEVICES += qcom_ap-hk14

define Device/xiaomi_ax3600
	$(call Device/FitImage)
	$(call Device/UbiFit)        
	DEVICE_DTS := ipq8074-ax3600
	DEVICE_DTS_CONFIG := config@ac04
	BLOCKSIZE := 128k
	PAGESIZE := 2048
	BOARD_NAME := ap-ac04
	DEVICE_TITLE := XIAOMI AX3600
	DEVICE_PACKAGES := ax3600-firwame
endef
TARGET_DEVICES += xiaomi_ax3600

define Device/xiaomi_ax6
	$(call Device/FitImage)
	$(call Device/UbiFit)        
	DEVICE_DTS := ipq8074-ax6
	DEVICE_DTS_CONFIG := config@ac04
	BLOCKSIZE := 128k
	PAGESIZE := 2048
	BOARD_NAME := ap-ac04
	DEVICE_TITLE := XIAOMI AX6
	DEVICE_PACKAGES := ax6-firwame
endef
TARGET_DEVICES += xiaomi_ax6

define Device/zte_mf269
	$(call Device/FitImage)
	$(call Device/UbiFit)        
	DEVICE_DTS := ipq8074-mf269
	DEVICE_DTS_CONFIG := config@ac04
	BLOCKSIZE := 128k
	PAGESIZE := 2048
	BOARD_NAME := ap-ac04
	DEVICE_TITLE := ZTE MF269
	DEVICE_PACKAGES := ax3600-firwame
endef
TARGET_DEVICES += zte_mf269

define Device/askey_rt5000w
	$(call Device/FitImage)
	$(call Device/UbiFit)        
	DEVICE_DTS := ipq8074-rt5000w
	DEVICE_DTS_CONFIG := config@hk01.c1
	BLOCKSIZE := 128k
	PAGESIZE := 2048
	BOARD_NAME := ap-hk01-c1
	DEVICE_TITLE := Askey RT5000W-D187/REV1
	DEVICE_PACKAGES := ax3600-firwame
endef
TARGET_DEVICES += askey_rt5000w

define Device/qcom_ap-hk01-c1
	$(call Device/FitImage)
	$(call Device/UbiFit)        
	DEVICE_DTS := ipq8074-hk01
	DEVICE_DTS_CONFIG := config@hk01.c1
	BLOCKSIZE := 128k
	PAGESIZE := 2048
	BOARD_NAME := ap-hk01-c1
	DEVICE_TITLE := Qualcomm Technologies, Inc. IPQ8074/AP-HK01-C1
	DEVICE_PACKAGES := ax3600-firwame
endef
TARGET_DEVICES += qcom_ap-hk01-c1

$(eval $(call BuildImage))
