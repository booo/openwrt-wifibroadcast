include $(TOPDIR)/rules.mk

PKG_NAME:=wifibroadcast-svpcom
PKG_RELEASE:=0.0.0

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL=https://github.com/svpcom/wifibroadcast.git
PKG_SOURCE_VERSION:=master

PKG_BUILD_DIR=$(BUILD_DIR)/$(PKG_NAME)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
#include $(INCLUDE_DIR)/cmake.mk

define Package/wifibroadcast-svpcom
  SECTION:=net
  CATEGORY:=Network
  TITLE:=wifibroadcast-svpcom
  DEPENDS:=+libpcap +librt +libsodium +libstdcpp
  #PKG_BUILD_DEPENDS:=libpcap librt
endef

define Package/wifibroadcast-svpcom/description
 wifibroadcast-svpcom
endef

define Build/Prepare
	#$(CP) CMakeLists.txt $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

define Build/Configure
	$(call Build/Configure/Default)
endef

define Build/Compile
	$(call Build/Compile/Default, all_bin)
endef

define Package/wifibroadcast-svpcom/install
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wfb_rx $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wfb_tx $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wfb_keygen $(1)/usr/bin/
	#$(call Build/Install/Default)
endef

$(eval $(call BuildPackage,wifibroadcast-svpcom))
