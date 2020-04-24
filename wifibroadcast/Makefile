include $(TOPDIR)/rules.mk

PKG_NAME:=wifibroadcast
PKG_RELEASE:=0.0.0

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL=https://github.com/booo/wifibroadcast.git
PKG_SOURCE_VERSION:=master

PKG_BUILD_DIR=$(BUILD_DIR)/$(PKG_NAME)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/wifibroadcast
  SECTION:=net
  CATEGORY:=Network
  TITLE:=wifibroadcast
  DEPENDS:=+libpcap +librt
  #PKG_BUILD_DEPENDS:=libpcap librt
endef

define Package/wifibroadcast/description
 wifibroadcast
endef

define Build/Prepare
	$(CP) CMakeLists.txt $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

define Build/Configure
	$(call Build/Configure/Default)
endef

define Build/Compile
	$(call Build/Compile/Default)
endef

define Package/wifibroadcast/install
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rx $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tx $(1)/usr/bin/
	$(call Build/Install/Default)
endef

$(eval $(call BuildPackage,wifibroadcast))
