#!/bin/sh
# Быстрый деплой исходников прямо на роутер (для итераций без пересборки .ipk).
# Файлы перезаписывают установленные пакетом — это ок для отладки; финальную
# версию потом собираем через CI и ставим чистым .ipk.
#
# Usage:
#   ./dev-deploy.sh 192.168.1.1
#   R=192.168.1.1 ./dev-deploy.sh
#   ./dev-deploy.sh 192.168.1.1 ui     # только main.js (быстро, UI-правки)

set -e
R="${1:-${R:-192.168.1.1}}"
MODE="${2:-all}"
D="$(dirname "$0")/luci-app-podkop-sync"

if [ "$MODE" = "ui" ]; then
	scp -O "$D/htdocs/luci-static/resources/view/podkop_sync/main.js" \
		root@"$R":/www/luci-static/resources/view/podkop_sync/main.js
else
	# Через tar с исключениями, а не scp -r: иначе на роутер уезжал бы
	# etc/config/podkop_sub с умолчаниями и затирал URL подписок и ручные ноды.
	# uci-defaults тоже не везём: он для первой установки пакета. COPYFILE_DISABLE —
	# чтобы macOS-tar не клал на роутер служебные файлы «._*».
	COPYFILE_DISABLE=1 tar -C "$D/root" --exclude='./etc/config' --exclude='./etc/uci-defaults' \
		--exclude='__pycache__' --exclude='.DS_Store' -cf - . \
		| ssh -o RemoteCommand=none root@"$R" 'tar -C / -xf -'
	scp -O -r "$D/htdocs/luci-static" root@"$R":/www/
	ssh -o RemoteCommand=none root@"$R" '
		chmod +x /usr/bin/podkop_sync.py /usr/libexec/podkop_sub_service \
			/usr/libexec/rpcd/luci.podkop_sub /etc/init.d/podkop_sub 2>/dev/null
		/etc/init.d/rpcd restart
	'
fi

ssh -o RemoteCommand=none root@"$R" 'rm -f /tmp/luci-indexcache* /tmp/luci-modulecache/* 2>/dev/null'
echo "OK → $R ($MODE). Обнови страницу: Cmd+Shift+R (или приватное окно)."
