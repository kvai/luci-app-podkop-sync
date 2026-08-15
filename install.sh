#!/bin/sh
# Установщик luci-app-podkop-sync для OpenWrt.
# Качает готовый .ipk из GitHub Release 'latest' и ставит через opkg.
#
# Использование (на роутере):
#   wget -O - https://raw.githubusercontent.com/OWNER/REPO/main/install.sh | sh
#
# Приватный репозиторий: передай токен с правом contents:read через env GH_TOKEN:
#   GH_TOKEN=ghp_xxx sh -c 'wget -O - --header="Authorization: token '"$GH_TOKEN"'" \
#     https://raw.githubusercontent.com/OWNER/REPO/main/install.sh | GH_TOKEN=ghp_xxx sh'

set -e

# ─── настрой под свой репозиторий ──────────────────────────────────────────
REPO="OWNER/luci-app-podkop-sync"
TAG="latest"
ASSET="luci-app-podkop-sync.ipk"
# ───────────────────────────────────────────────────────────────────────────

IPK_URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
TMP="/tmp/${ASSET}"

# podkop — обязательная зависимость (из кастомного репо itdoginfo, не из фидов),
# поэтому проверяем заранее и даём понятную подсказку вместо ошибки opkg.
if ! opkg list-installed 2>/dev/null | grep -q '^podkop '; then
	echo "!! podkop не установлен — сначала поставьте его:" >&2
	echo "   https://github.com/itdoginfo/podkop  (README, установка одной командой)" >&2
	echo "   затем запустите этот установщик снова." >&2
	exit 1
fi

# заголовок авторизации для приватной репы (если задан GH_TOKEN)
AUTH_HDR=""
[ -n "$GH_TOKEN" ] && AUTH_HDR="Authorization: token ${GH_TOKEN}"

echo "==> Downloading ${IPK_URL}"

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

if ! download "$IPK_URL" "$TMP"; then
	echo "!! download failed. For a PRIVATE repo set GH_TOKEN=<PAT>." >&2
	exit 1
fi

echo "==> Installing package"
opkg update
opkg install "$TMP"
rm -f "$TMP"

echo "==> Done. Open LuCI → Services → Podkop Sync"
