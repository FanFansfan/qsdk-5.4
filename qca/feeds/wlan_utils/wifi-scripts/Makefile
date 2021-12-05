
include $(TOPDIR)/rules.mk

PKG:=qca-wifi-scripts
PKG_NAME:=$(PKG)
PKG_VERSION:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=QCA
  CATEGORY:=QCA software
  URL:=http://www.qca.qualcomm.com
  MAINTAINER:=Qualcomm Atheros
  TITLE:= QCA wifi scripts for kernel5.4
  DEPENDS:=@TARGET_ipq807x||TARGET_ipq50xx||TARGET_ipq60xx
endef


define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/lib/preinit
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN)  ./files/81_load_wifi_board_bin $(1)/lib/preinit
	$(INSTALL_BIN)  ./files/01_preinit_do_ipq806x.sh $(1)/lib/preinit
	$(INSTALL_BIN)  ./files/update_ini $(1)/etc/init.d
	$(INSTALL_DATA) ./files/ipq806x.sh $(1)/lib
	$(INSTALL_BIN) ./files/read_caldata_to_fs.sh $(1)/lib
	$(INSTALL_BIN) ./files/wifi_interface_helper.sh $(1)/lib
	$(INSTALL_BIN) ./files/update_smp_affinity.sh $(1)/lib
	$(INSTALL_BIN) ./files/wifi_init_kernel54_config.sh $(1)/lib
	$(INSTALL_BIN) ./files/tempinfo $(1)/sbin
	$(INSTALL_BIN) ./files/setmac $(1)/sbin
	$(INSTALL_BIN) ./files/setmac_all $(1)/sbin
	$(INSTALL_BIN) ./files/getmac $(1)/sbin
endef
Build/Compile=true
$(eval $(call BuildPackage,$(PKG_NAME)))

