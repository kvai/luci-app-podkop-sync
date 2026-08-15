# luci-app-podkop-sync

Лёгкий пакет для OpenWrt 24.10, который скачивает прокси-подписки, парсит их в
`vless://`-ссылки и применяет к секции [Podkop](https://github.com/itdoginfo/podkop)
в режиме **URLTest** — с управлением через веб-интерфейс LuCI.

Цель: Xiaomi Mi Router AX3000T (MediaTek MT7981B, `aarch64_cortex-a53`).

## Возможности

- Вход: **Xray/v2ray JSON**, **Base64-подписки**, обычные списки `vless://` — формат определяется автоматически.
- Протоколы: **VLESS** (REALITY/TCP, TLS + WebSocket/gRPC/xHTTP). Прочие (ss/trojan/vmess) молча пропускаются.
- Несколько подписок одновременно, глобальная дедупликация и авто-нумерация одноимённых нод (`#1`, `#2`).
- Fail-safe: при ошибке скачивания или 0 нод рабочий `/etc/config/podkop` не перезаписывается.
- Cron-расписание (6/12/24 ч), кнопка «Обновить сейчас», статус и таблица активных нод.

## Компоненты

| Путь | Назначение |
|------|-----------|
| `root/usr/bin/podkop_sync.py` | Парсер подписок → `vless://` (stdlib only, без `urllib`). |
| `root/usr/libexec/podkop_sub_service` | Бэкенд: `sync` / `update_cron` / `status`; curl, fail-safe, uci, cron. |
| `root/usr/libexec/rpcd/luci.podkop_sub` | rpcd-провайдер ubus для фронтенда. |
| `root/usr/share/rpcd/acl.d/…json` | ACL-права LuCI. |
| `root/usr/share/luci/menu.d/…json` | Пункт меню *Services → Podkop Sync*. |
| `root/etc/config/podkop_sub` | UCI-конфиг плагина. |
| `root/etc/init.d/podkop_sub` | procd-сервис: reload-триггер, пересобирает cron при изменении конфига. |
| `htdocs/luci-static/resources/view/podkop_sync/main.js` | Фронтенд (LuCI JS API). |

## Установка одной командой

На роутере (busybox ash не умеет `sh <(...)`, поэтому через пайп):

```sh
wget -O - https://raw.githubusercontent.com/OWNER/luci-app-podkop-sync/main/install.sh | sh
```

`install.sh` качает готовый `.ipk` из GitHub Release `latest` и ставит через
`opkg` (зависимости подтянутся сами). Замени `OWNER` на свой логин.

> **Публичный vs приватный.** Анонимный one-liner работает только с **публичным**
> репозиторием (raw-скрипт и Release-ассеты). Для **приватного** нужен токен
> (PAT, `contents:read`) — в `install.sh` он передаётся через env `GH_TOKEN`, и
> сам скрипт тоже придётся тянуть с заголовком авторизации. Проще для приватной
> репы — скачать `.ipk` из Actions/Releases на ПК и `scp`-нуть на роутер.

## Установка/удаление через LuCI

Установка `.ipk` (из Release/Actions) в веб-интерфейсе:

1. **System → Software** → **Update lists…** (чтобы opkg подтянул `python3-light`).
2. **Upload Package…** → выбрать `.ipk` → **Install** (зависимости ставятся сами).
3. Обновить LuCI → **Сервисы → Podkop Sync**.

Удаление: **System → Software → Installed** → `luci-app-podkop-sync` → **Remove**
(или `opkg remove luci-app-podkop-sync`). prerm-скрипт снимает cron-задачу,
отключает сервис и чистит реестр управляемых нод. Конфиг `/etc/config/podkop_sub`
сохраняется (полная чистка — `opkg remove --autoremove`).

> Если раньше ставили файлы вручную (scp), удалите их перед установкой `.ipk`,
> иначе будет конфликт файлов (они не принадлежат opkg).

## Сборка (CI)

`.github/workflows/build.yml` собирает `.ipk` через OpenWrt SDK
(`aarch64_cortex-a53`, тег ветки `24.10-SNAPSHOT`; пакет `all` — ставится на
любой 24.10.x) и публикует его в rolling-релиз `latest` со стабильным именем
`luci-app-podkop-sync.ipk`. Артефакт также доступен во вкладке **Actions**.

## Ручная установка для теста (без CI)

Ставится поверх рабочего OpenWrt. Важные грабли (проверено на железе):

- **Зависимость `python3-light` не входит в комплект** — ставится отдельно, иначе
  парсер падает с `python3: not found`.
- OpenWrt (dropbear) **не имеет sftp-server** → у `scp` нужен флаг **`-O`**.
- Копируем **содержимое** `root/` и `htdocs/` (со слешем-звёздочкой), а не сами
  папки — иначе файлы улетят в `/root/...` и `/www/htdocs/...`.

```sh
# --- на роутере: зависимость ---
opkg update && opkg install python3-light

# --- с рабочей машины (замените IP роутера) ---
R=192.168.1.1
scp -O -r root/* root@$R:/
scp -O -r htdocs/luci-static root@$R:/www/

# --- на роутере: права, инициализация, сервис cron ---
ssh -o RemoteCommand=none root@$R '
  chmod +x /usr/bin/podkop_sync.py /usr/libexec/podkop_sub_service /usr/libexec/rpcd/luci.podkop_sub /etc/init.d/podkop_sub
  sh /etc/uci-defaults/luci-app-podkop-sync
  /etc/init.d/podkop_sub enable
  /etc/init.d/podkop_sub start
  /etc/init.d/rpcd restart
  rm -f /tmp/luci-indexcache /tmp/luci-modulecache/*
'
```

> На zsh глоб `root/*` может ругаться `no matches found`, если вы не в каталоге
> репозитория — сначала `cd` в корень пакета.

Затем: LuCI → **Services → Podkop Sync**, вставьте URL подписки, выберите секцию,
нажмите «Обновить сейчас».

Отладка из консоли роутера:

```sh
/usr/libexec/podkop_sub_service sync      # запустить синхронизацию
/usr/libexec/podkop_sub_service status    # JSON статуса + нод
logread -e podkop_sub                      # логи
```

Проверка cron-триггера:

```sh
uci set podkop_sub.config.cron='6'; uci commit podkop_sub; reload_config; sleep 2
crontab -l | grep podkop_sub          # ждём '0 */6 * * *'
```

## Известное ограничение: подписки с TLS-гейтингом (HAPP)

Некоторые панели отдают реальный список нод только «своему» клиенту (например
HAPP), опознавая его по **TLS-отпечатку (uTLS)**, а не по User-Agent. Всем
остальным возвращается заглушка — одна нода `0.0.0.0:1` с именем вроде
«Приложение не поддерживается». Обычный `curl` на роутере такой отпечаток
подделать не может, поэтому подобные подписки через плагин не тянутся. Это
ограничение провайдера, а не парсера. Обходные пути: попросить у провайдера
не-гейтованную (universal/base64) ссылку. Подписки с гейтингом только по
User-Agent решаются полем **User-Agent** в настройках плагина.

## Тесты парсера (на любой машине с Python 3)

```sh
python3 tests/test_parser.py
```
