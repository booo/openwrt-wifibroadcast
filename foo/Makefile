include $(TOPDIR)/rules.mk

PKG_NAME:=foo
PKG_RELEASE:=0.0.0

#PKG_SOURCE_PROTO:=git
#PKG_SOURCE_URL=https://github.com/booo/foo.git
#PKG_SOURCE_VERSION:=master

PKG_BUILD_DIR=$(BUILD_DIR)/$(PKG_NAME)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/foo
  SECTION:=net
  CATEGORY:=Network
  TITLE:=foo
endef

define Package/foo/description
 foo
endef

define Build/Prepare
	$(CP) CMakeLists.txt $(PKG_BUILD_DIR)
	$(CP) capture.c $(PKG_BUILD_DIR)
	$(CP) transmit.c $(PKG_BUILD_DIR)
	$(CP) generate.c $(PKG_BUILD_DIR)
	$(CP) tcpdump.h $(PKG_BUILD_DIR)
	$(call Build/Prepare/Default)
endef

define Build/Configure
	$(call Build/Configure/Default)
endef

define Build/Compile
	$(call Build/Compile/Default)
endef

define Package/foo/install
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/capture $(1)/usr/bin/foo_capture
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/transmit $(1)/usr/bin/foo_transmit
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/generate $(1)/usr/bin/foo_generate
	$(call Build/Install/Default)
endef

$(eval $(call BuildPackage,foo))
