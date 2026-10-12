#!/bin/sh
# Установщик luci-app-podkop-sync для OpenWrt.
# Сам определяет менеджер пакетов (apk на OpenWrt 25.12+, opkg на 24.10 и старше),
# качает из GitHub Release 'latest' пакет нужного формата и ставит его.
# Той же командой пакет обновляется поверх установленного.
#
# Использование (на роутере):
#   wget -O - https://raw.githubusercontent.com/kvai/luci-app-podkop-sync/main/install.sh | sh
#
# Приватный репозиторий: передай токен с правом contents:read через env GH_TOKEN:
#   GH_TOKEN=ghp_xxx sh -c 'wget -O - --header="Authorization: token '"$GH_TOKEN"'" \
#     https://raw.githubusercontent.com/kvai/luci-app-podkop-sync/main/install.sh | GH_TOKEN=ghp_xxx sh'

set -e

# ─── настрой под свой репозиторий ──────────────────────────────────────────
REPO="kvai/luci-app-podkop-sync"
TAG="latest"
NAME="luci-app-podkop-sync"
# ───────────────────────────────────────────────────────────────────────────

# Менеджер пакетов. Смотрим не только на наличие программы, но и на её базу:
# так делает сам sysupgrade, и случайно оказавшийся в системе бинарник не собьёт.
if command -v apk >/dev/null 2>&1 && [ -d /lib/apk/db ]; then
	PM=apk
elif command -v opkg >/dev/null 2>&1; then
	PM=opkg
else
	echo "!! не найден ни apk, ни opkg — это точно OpenWrt?" >&2
	exit 1
fi
EXT=ipk
[ "$PM" = apk ] && EXT=apk

pkg_installed() {
	if [ "$PM" = apk ]; then
		apk info -e "$1" >/dev/null 2>&1
	else
		opkg list-installed 2>/dev/null | grep -q "^$1 "
	fi
}

# podkop — обязательная зависимость (из своего репозитория, не из фидов OpenWrt),
# поэтому проверяем заранее и даём понятную подсказку вместо ошибки менеджера.
if ! pkg_installed podkop; then
	echo "!! podkop не установлен — сначала поставьте его:" >&2
	echo "   https://github.com/itdoginfo/podkop  (README, установка одной командой)" >&2
	echo "   затем запустите этот установщик снова." >&2
	exit 1
fi

ASSET="${NAME}.${EXT}"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
TMP="/tmp/${ASSET}"

# заголовок авторизации для приватной репы (если задан GH_TOKEN)
AUTH_HDR=""
[ -n "$GH_TOKEN" ] && AUTH_HDR="Authorization: token ${GH_TOKEN}"

echo "==> OpenWrt $(. /etc/openwrt_release 2>/dev/null; echo "${DISTRIB_RELEASE:-?}"), менеджер пакетов: ${PM}"
echo "==> Downloading ${URL}"

download() {
	# $1 = url, $2 = out
	if command -v curl >/dev/null 2>&1; then
		if [ -n "$AUTH_HDR" ]; then
			curl -fL -H "$AUTH_HDR" -o "$2" "$1"
		else
			curl -fL -o "$2" "$1"
		fi
	elif command -v wget >/dev/null 2>&1; then
		if [ -n "$AUTH_HDR" ]; then
			wget --header="$AUTH_HDR" -O "$2" "$1"
		else
			wget -O "$2" "$1"
		fi
	elif command -v uclient-fetch >/dev/null 2>&1; then
		uclient-fetch -O "$2" "$1"
	else
		echo "!! need curl, wget or uclient-fetch" >&2
		return 1
	fi
}

trap 'rm -f "$TMP"' EXIT
if ! download "$URL" "$TMP"; then
	echo "!! не удалось скачать пакет: в релизе может ещё не быть файла .${EXT}," >&2
	echo "   а для ПРИВАТНОГО репозитория нужен GH_TOKEN=<PAT>." >&2
	exit 1
fi

echo "==> Installing package"
rc=0
if [ "$PM" = apk ]; then
	# пакет не подписан ключом фидов OpenWrt, отсюда --allow-untrusted
	apk update || true
	apk add --allow-untrusted "$TMP" || rc=$?
else
	opkg update || true
	opkg install "$TMP" || rc=$?
fi
[ "$rc" = 0 ] || { echo "!! установка не удалась (код $rc)" >&2; exit "$rc"; }

echo "==> Done. Open LuCI → Services → Podkop Sync"
