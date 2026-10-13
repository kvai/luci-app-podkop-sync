# SPDX-License-Identifier: MIT
#
# luci-app-podkop-sync — синхронизация прокси-подписок для podkop (URLTest).

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-podkop-sync
PKG_VERSION:=1.2.1
PKG_RELEASE:=1

PKG_MAINTAINER:=htckvai <htckvai@gmail.com>
PKG_LICENSE:=MIT

LUCI_TITLE:=LuCI app to sync proxy subscriptions into Podkop (URLTest)
LUCI_DEPENDS:=+python3-light +curl +podkop
LUCI_PKGARCH:=all

# Настройки пользователя (URL подписок, ручные ноды) — conffile: без этого
# объявления менеджер пакетов при обновлении перезаписывал бы их умолчаниями.
# Каталог реестра своих нод объявлен там же, чтобы он переживал sysupgrade
# (список conffiles попадает в /lib/upgrade/keep.d).
define Package/luci-app-podkop-sync/conffiles
/etc/config/podkop_sub
/etc/podkop_sub.managed.d/
endef

# Чистое удаление: снять cron-задачу, отключить сервис, убрать реестр.
# Выполняется на устройстве при удалении пакета (не при сборке образа).
# При ОБНОВЛЕНИИ opkg тоже зовёт prerm — тогда ничего не трогаем, иначе пропал
# бы реестр своих нод и cron-задача. Признак обновления — переменная
# PKG_UPGRADE=1: сценарий подключается системной default_prerm через «.», и
# позиционные аргументы в нём не «upgrade», а путь к обёртке (проверка "$$1"
# в 1.1.0-r1..r14 поэтому не срабатывала). apk (OpenWrt 25.12+) при обновлении
# prerm не вызывает вовсе, так что там эта защита просто не нужна.
define Package/luci-app-podkop-sync/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
[ "$${PKG_UPGRADE}" = "1" ] && exit 0
case " $$* " in *" upgrade "*) exit 0 ;; esac
# disable only — сервис демона не держит (procd reload-триггер), поэтому
# 'stop' лишь дёргает 'ubus service delete' и шумит 'Not found' при удалении.
/etc/init.d/podkop_sub disable 2>/dev/null
sed -i '/# podkop_sub_sync/d' /etc/crontabs/root 2>/dev/null
/etc/init.d/cron restart 2>/dev/null
rm -rf /etc/podkop_sub.managed.d
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# luci.mk автоматически устанавливает ./htdocs -> /www и ./root -> /
# /etc/config/podkop_sub объявлен в conffiles выше: сохраняется при обновлении.
# call BuildPackage - OpenWrt buildroot signature
