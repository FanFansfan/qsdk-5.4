#
# Copyright (C) 2015-2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v3.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=AdGuardHome
PKG_VERSION:=0.104.3
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Powerful adblock module to block ad.
	DEPENDS:=@(i386||x86_64||arm||mipsel||mips||aarch64)
	URL:=https://github.com/AdguardTeam/AdGuardHome/
endef

define Package/$(PKG_NAME)/description
Adbyby is a powerful adblock module to block ad,just like adblock.
endef

ifeq ($(ARCH),x86_64)
	AdGuardHome_DIR:=amd64
endif
ifeq ($(ARCH),mipsel)
	AdGuardHome_DIR:=mipsle
endif
ifeq ($(ARCH),mips)
	AdGuardHome_DIR:=mips
endif
ifeq ($(ARCH),i386)
	ADBYBY_DIR:=x86
endif
ifeq ($(ARCH),arm)
	AdGuardHome_DIR:=armv7
	ifeq ($(BOARD),bcm53xx)
		AdGuardHome_DIR:=arm
  endif
  ifeq ($(BOARD),kirkwood)
		AdGuardHome_DIR:=arm
  endif
endif
ifeq ($(ARCH),aarch64)
	AdGuardHome_DIR:=armv7
endif

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin/AdGuardHome
	$(INSTALL_BIN) ./files/$(AdGuardHome_DIR)/AdGuardHome $(1)/usr/bin/AdGuardHome/AdGuardHome
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
