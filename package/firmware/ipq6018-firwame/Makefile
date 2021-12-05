include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ipq6018-firwame
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk


define Package/ipq6018-firwame
  SECTION:=QCA
  CATEGORY:=$(QTI_SOFTWARE_CATEGORY)
  URL:=http://www.qca.qualcomm.com
  MAINTAINER:=Qualcomm Atheros
  PKGARCH:=all
  DEPENDS:=
  TITLE:=Firwame for IPQ6018
endef

define Package/ipq6018-firwame/description
	Firwame for IPQ6018
endef



define Build/Configure
endef

define Build/Compile
endef

define Package/ipq6018-firwame/install
        $(INSTALL_DIR) $(1)/lib/firmware/IPQ6018/WIFI_FW
	$(CP) ./files/* $(1)/lib/firmware/IPQ6018/WIFI_FW/
endef

$(eval $(call BuildPackage,ipq6018-firwame))
