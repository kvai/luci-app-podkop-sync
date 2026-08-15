# SPDX-License-Identifier: MIT
#
# luci-app-podkop-sync — синхронизация прокси-подписок для podkop (URLTest).

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-podkop-sync
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=htckvai <htckvai@gmail.com>
PKG_LICENSE:=MIT

LUCI_TITLE:=LuCI app to sync proxy subscriptions into Podkop (URLTest)
LUCI_DEPENDS:=+python3-light +curl +podkop
LUCI_PKGARCH:=all

# Чистое удаление: снять cron-задачу, отключить сервис, убрать реестр.
# Выполняется на устройстве при `opkg remove` (не при сборке образа).
define Package/luci-app-podkop-sync/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/podkop_sub disable 2>/dev/null
/etc/init.d/podkop_sub stop 2>/dev/null
sed -i '/# podkop_sub_sync/d' /etc/crontabs/root 2>/dev/null
/etc/init.d/cron restart 2>/dev/null
rm -rf /etc/podkop_sub.managed.d
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# luci.mk автоматически устанавливает ./htdocs -> /www и ./root -> /
# /etc/config/podkop_sub попадает в conffiles автоматически (сохраняется при
# обновлении, удаляется только при opkg remove --autoremove/purge).
# call BuildPackage - OpenWrt buildroot signature
