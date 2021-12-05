include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ax3600-firwame
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk


define Package/ax3600-firwame
  SECTION:=QCA
  CATEGORY:=$(QTI_SOFTWARE_CATEGORY)
  URL:=http://www.qca.qualcomm.com
  MAINTAINER:=Qualcomm Atheros
  PKGARCH:=all
  DEPENDS:=
  TITLE:=Firwame for AX3600
endef

define Package/ax3600-firwame/description
	Firwame for AX3600.
endef



define Build/Configure
endef

define Build/Compile
endef

define Package/ax3600-firwame/install
        $(INSTALL_DIR) $(1)/lib/firmware/IPQ8074/WIFI_FW
	$(CP) ./files/* $(1)/lib/firmware/IPQ8074/WIFI_FW/
endef

$(eval $(call BuildPackage,ax3600-firwame))
