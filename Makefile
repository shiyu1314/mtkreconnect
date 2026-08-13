include $(TOPDIR)/rules.mk

PKG_NAME:=mtkreconnect
PKG_VERSION:=1.1
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define Package/mtkreconnect
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Applications
  TITLE:=Auto-reconnect for MTK WiFi
  DEPENDS:=+libuci
endef

define Package/mtkreconnect/description
  Userspace auto-reconnect daemon for MediaTek mt_wifi driver.
  Monitors STA interface connection status and triggers reconnection.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_CPPFLAGS) \
		$(PKG_BUILD_DIR)/mtkreconnect.c \
		-o $(PKG_BUILD_DIR)/mtkreconnect \
		$(TARGET_LDFLAGS) \
		-luci
endef

define Package/mtkreconnect/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mtkreconnect $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/mtkreconnect.init $(1)/etc/init.d/mtkreconnect
endef

$(eval $(call BuildPackage,mtkreconnect))
