#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тесты бэкенда podkop_sub_service на заглушках (без роутера и сети).

Скрипт запускается как есть, с подменённым корнем (PODKOP_SUB_ROOT) и PATH
(PODKOP_SUB_PATH), где лежат заглушки uci, curl, podkop, pidof, logger, sleep.

Запуск: python3 -m unittest discover -s tests -p 'test_sync.py' -v
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..", "luci-app-podkop-sync", "root")
SERVICE = os.path.join(PKG, "usr", "libexec", "podkop_sub_service")
PARSER = os.path.join(PKG, "usr", "bin", "podkop_sync.py")

# ---- заглушка uci: JSON-хранилище с «неприменёнными» изменениями, как у настоящего ----
FAKE_UCI = r'''#!/usr/bin/env python3
import json, os, sys
DB, ST = os.environ["FAKE_UCI_DB"], os.environ["FAKE_UCI_DB"] + ".staged"
def load(p):
    try:
        with open(p, encoding="utf-8") as f: return json.load(f)
    except OSError: return {}
def save(p, d):
    with open(p, "w", encoding="utf-8") as f: json.dump(d, f, ensure_ascii=False)
args = [a for a in sys.argv[1:] if a != "-q"]
if not args: sys.exit(1)
cmd, rest = args[0], args[1:]
st = load(ST) if os.path.exists(ST) else load(DB)
def split(spec):
    key, eq, val = spec.partition("=")
    parts = key.split(".")
    return parts, (val if eq else None)
if cmd in ("get", "_list"):
    parts, _ = split(rest[0])
    try:
        v = st[parts[0]][parts[1]]
        if len(parts) == 3: v = v[parts[2]]
        else: v = v.get(".type", "section")
    except KeyError: sys.exit(1)
    if cmd == "_list":
        for x in (v if isinstance(v, list) else [v]): print(x)
    elif isinstance(v, list):
        # настоящий uci берёт элементы с пробелом в одинарные кавычки
        print(" ".join(("'%s'" % x) if " " in x else x for x in v))
    else: print(v)
elif cmd in ("set", "add_list"):
    parts, val = split(rest[0])
    if cmd == "add_list" and (os.path.exists(DB + ".fail_add") or any(ord(c) < 32 for c in val)):
        sys.exit(1)
    sec = st.setdefault(parts[0], {}).setdefault(parts[1], {})
    if len(parts) == 2: sec[".type"] = val
    elif cmd == "set": sec[parts[2]] = val
    else: sec.setdefault(parts[2], []).append(val)
    save(ST, st)
elif cmd == "delete":
    parts, _ = split(rest[0])
    try: del st[parts[0]][parts[1]][parts[2]]
    except KeyError: sys.exit(1)
    save(ST, st)
elif cmd == "commit":
    if os.path.exists(DB + ".fail_commit"): sys.exit(1)
    db = load(DB); db[rest[0]] = st.get(rest[0], {}); save(DB, db)
    with open(DB + ".commits", "a") as f: f.write(rest[0] + "\n")
elif cmd == "revert":
    db = load(DB); st[rest[0]] = db.get(rest[0], {}); save(ST, st)
else: sys.exit(1)
'''

FUNCTIONS_SH = r'''# заглушка /lib/functions.sh поверх поддельного uci
config_load() { __PKG="$1"; }
config_get() {
	local __v
	__v="$(uci -q get "$__PKG.$2.$3" 2>/dev/null)" || __v=""
	[ -n "$__v" ] || __v="$4"
	eval "$1=\"\$__v\""
}
config_list_foreach() {
	local __f="$PODKOP_SUB_ROOT/tmp/.cfl.$$" __l
	uci _list "$__PKG.$1.$2" > "$__f" 2>/dev/null
	while IFS= read -r __l; do "$3" "$__l"; done < "$__f"
	rm -f "$__f"
}
'''

CURL = r'''#!/bin/sh
# заглушка curl: http(s)://sub.test/NAME -> $STUB/subs/NAME, нет файла -> ошибка
echo "$*" >> "$STUB/curl.log"
out=""; url=""
while [ $# -gt 0 ]; do
	case "$1" in
		-o) out="$2"; shift ;;
		--) url="$2"; shift ;;
	esac
	shift
done
f="$STUB/subs/$(basename "$url")"
[ -f "$f" ] || exit 22
# повторные скачивания первой подписки (sample_2..4): свой вариант ответа, если он задан —
# так тесты изображают панель, которая каждый раз выдаёт другие SNI
case "$(basename "$out")" in
	sample_*) k="${out##*sample_}"; k="${k%.txt}"; [ -f "$f.s$k" ] && { cp "$f.s$k" "$out"; exit 0; } ;;
esac
cp "$f" "$out"
'''

JSONFILTER = r'''#!/usr/bin/env python3
# заглушка jsonfilter: -i FILE -e '@.a.b.c'
import json, sys
a = sys.argv[1:]
try:
    v = json.load(open(a[a.index("-i") + 1], encoding="utf-8"))
    for k in a[a.index("-e") + 1].lstrip("@.").split("."):
        v = v[k]
    print(v)
except (OSError, ValueError, KeyError, TypeError):
    sys.exit(1)
'''

N1 = ("vless://11111111-2222-4333-8444-555555555555@n1.example.net:443?encryption=none"
      "&fp=firefox&pbk=PBK_ONE&security=reality&sid=aa11&sni=www.example.com&type=tcp#%D0%9E%D0%B4%D0%B8%D0%BD")
N2 = ("vless://11111111-2222-4333-8444-555555555555@n2.example.net:443?encryption=none"
      "&fp=firefox&pbk=PBK_TWO&security=reality&sid=bb22&sni=www.example.org&type=tcp#%D0%94%D0%B2%D0%B0")
STUB_NODE = "vless://11111111-2222-4333-8444-555555555555@0.0.0.0:1?type=tcp&security=none#App%20not%20supported"


class SyncEnv(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.stub = os.path.join(self.root, "stub")
        for d in ("lib", "tmp", "etc/init.d", "etc/crontabs", "etc/sing-box", "usr/bin", "stub/bin", "stub/subs"):
            os.makedirs(os.path.join(self.root, d))
        shutil.copy(PARSER, os.path.join(self.root, "usr", "bin", "podkop_sync.py"))
        with open(os.path.join(self.root, "lib", "functions.sh"), "w") as f:
            f.write(FUNCTIONS_SH)
        b = os.path.join(self.stub, "bin")
        self._script(os.path.join(b, "uci"), FAKE_UCI.replace("#!/usr/bin/env python3", "#!" + sys.executable))
        self._script(os.path.join(b, "curl"), CURL)
        self._script(os.path.join(b, "jsonfilter"), JSONFILTER.replace("#!/usr/bin/env python3", "#!" + sys.executable))
        # конфиг sing-box с адресом Clash API; сам ответ API (stub/subs/proxies) кладут только тесты закрепления
        with open(os.path.join(self.root, "etc", "sing-box", "config.json"), "w") as f:
            json.dump({"experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}}}, f)
        # заглушка podkop: отдаёт features/версию; reload падает, если в списке есть «плохая» нода
        # (как настоящий: сначала останавливается, потом обнаруживает, что конфиг не собрать)
        self._script(os.path.join(b, "podkop"),
                     '#!/bin/sh\n'
                     'case "$1" in\n'
                     '  get_sing_box_features) cat "$STUB/features" 2>/dev/null || echo "[]"; exit 0 ;;\n'
                     '  show_version) cat "$STUB/version" 2>/dev/null || echo "v0.7.23"; exit 0 ;;\n'
                     'esac\n'
                     'echo "$*" >> "$STUB/podkop.log"\n'
                     '[ -f "$STUB/podkop_fail" ] && exit 1\n'
                     'if uci -q get podkop.main.urltest_proxy_links | grep -q "BADNODE\\|[?&]type=xhttp"; then\n'
                     '  [ -f "$STUB/xhttp_ok" ] && ! uci -q get podkop.main.urltest_proxy_links | grep -q BADNODE && exit 0\n'
                     '  touch "$STUB/singbox_dead"\n'
                     '  echo "podkop: [fatal] The xhttp transport is not supported by the installed sing-box. Aborted." >> "$STUB/syslog"\n'
                     '  echo "podkop: [fatal] Sing-box configuration /tmp/tmp.X is invalid. Aborted." >> "$STUB/syslog"\n'
                     '  [ -f "$STUB/term_parent" ] && kill -TERM $PPID\n'
                     '  exit 1\n'
                     'fi\n'
                     'rm -f "$STUB/singbox_dead"\nexit 0\n')
        # «системный лог»: туда пишут заглушки logger и podkop; в начале — старая, не относящаяся к делу fatal-строка
        with open(os.path.join(self.stub, "syslog"), "w") as f:
            f.write("podkop: [fatal] OLD unrelated failure from yesterday\n")
        self._script(os.path.join(b, "logread"), '#!/bin/sh\ncat "$STUB/syslog"\n')
        self._script(os.path.join(b, "pidof"),
                     '#!/bin/sh\n[ -f "$STUB/no_singbox" ] && exit 1\n[ -f "$STUB/singbox_dead" ] && exit 1\n'
                     '[ -f "$STUB/singbox_flapping" ] && { date +%N%s; exit 0; }\necho 4242\nexit 0\n')
        self._script(os.path.join(b, "sleep"), "#!/bin/sh\nexit 0\n")
        self._script(os.path.join(b, "logger"), '#!/bin/sh\necho "$*" >> "$STUB/syslog"\n')
        self._script(os.path.join(self.root, "etc", "init.d", "podkop"),
                     '#!/bin/sh\n[ "$1" = enabled ] && { [ -f "$STUB/podkop_disabled" ] && exit 1; exit 0; }\nexit 0\n')
        self._script(os.path.join(self.root, "etc", "init.d", "cron"),
                     '#!/bin/sh\necho "$1" >> "$STUB/cron.log"\n')
        # Заглушка пробной сборки (настоящая подключает /usr/bin/podkop и проверяется на роутере).
        # По умолчанию «недоступна» (код 3), чтобы прежние тесты проверяли путь с откатом.
        os.makedirs(os.path.join(self.root, "usr", "libexec"))
        self._script(os.path.join(self.root, "usr", "libexec", "podkop_sub_dryrun"),
                     '#!/bin/sh\necho "$1" >> "$STUB/dryrun.log"\n[ -f "$STUB/preflight_on" ] || exit 3\n'
                     'if grep -q "BADNODE" "$2"; then echo "[info] building" > "$3.log"; '
                     'echo "[fatal] Node bad.example.net is not acceptable. Aborted." >> "$3.log"; exit 1; fi\nexit 0\n')
        self.db = os.path.join(self.root, "uci.json")
        self.env = dict(os.environ, PODKOP_SUB_ROOT=self.root, STUB=self.stub, FAKE_UCI_DB=self.db,
                        PODKOP_SUB_PATH=os.pathsep.join(
                            [b, os.path.dirname(sys.executable), "/usr/bin", "/bin", "/usr/sbin", "/sbin"]))
        self.write_db({
            "podkop": {"main": {".type": "section", "proxy_config_type": "urltest"}},
            "podkop_sub": {"config": {".type": "podkop_sub", "enabled": "1", "section": "main",
                                      "preserve_manual": "1", "cron": "24",
                                      "url": ["https://sub.test/one"]}},
        })
        self.sub("one", N1 + "\n" + N2 + "\n")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    # ---- помощники ----
    def _script(self, path, body):
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        os.chmod(path, 0o755)

    def write_db(self, data):
        with open(self.db, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        if os.path.exists(self.db + ".staged"):
            os.remove(self.db + ".staged")

    def read_db(self):
        with open(self.db, encoding="utf-8") as f:
            return json.load(f)

    def set_opt(self, pkg, sec, opt, val):
        d = self.read_db()
        d[pkg][sec][opt] = val
        self.write_db(d)

    auto_noise = False

    def sub(self, name, text, noisy=None):
        """Задать ответ подписки. noisy=True: при повторных скачиваниях панель выдаёт другие SNI
        (как 3x-ui со списком из нескольких имён); False: всегда один и тот же ответ."""
        import re
        base = os.path.join(self.stub, "subs", name)
        with open(base, "w", encoding="utf-8") as f:
            f.write(text)
        noisy = self.auto_noise if noisy is None else noisy
        for k in (2, 3, 4):
            if noisy:
                with open("%s.s%d" % (base, k), "w", encoding="utf-8") as f:
                    f.write(re.sub(r"sni=([^&#\n]+)", lambda m: "sni=r%d.%s" % (k, m.group(1)), text))
            elif os.path.exists("%s.s%d" % (base, k)):
                os.remove("%s.s%d" % (base, k))

    def flag(self, name, on=True):
        p = os.path.join(self.stub, name)
        if on:
            open(p, "w").close()
        elif os.path.exists(p):
            os.remove(p)

    def run_svc(self, *args):
        return subprocess.run(["sh", SERVICE] + list(args), env=self.env, capture_output=True,
                              text=True, timeout=60)

    def sync(self):
        return self.run_svc("sync").returncode

    def links(self):
        return self.read_db()["podkop"]["main"].get("urltest_proxy_links", [])

    def status(self):
        c = self.read_db()["podkop_sub"]["config"]
        return c.get("last_status"), c.get("last_message", "")

    def health(self, **delays):
        """Ответ Clash API: health(**{"main-1-out": 120, "main-2-out": None}); None = нода не работает."""
        proxies = {tag: {"type": "VLESS", "history": ([{"time": "t", "delay": d}] if d else [])}
                   for tag, d in delays.items()}
        self.sub("proxies", json.dumps({"proxies": proxies}))

    def log(self, name):
        p = os.path.join(self.stub, name)
        if not os.path.exists(p):
            return []
        with open(p, encoding="utf-8") as f:
            return f.read().splitlines()

    def reloads(self):
        return self.log("podkop.log").count("reload")

    def podkop_commits(self):
        p = self.db + ".commits"
        if not os.path.exists(p):
            return 0
        with open(p) as f:
            return f.read().split().count("podkop")


class SyncTests(SyncEnv):
    def test_first_sync_writes_and_reloads(self):
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [N1, N2])
        self.assertEqual(self.reloads(), 1)
        st, msg = self.status()
        self.assertEqual(st, "ok")
        self.assertIn("#1=2", msg)
        self.assertIn("Podkop перезапущен", msg)
        with open(os.path.join(self.root, "etc", "podkop_sub.managed.d", "main")) as f:
            self.assertEqual(f.read().split(), [N1, N2])
        self.assertFalse(os.path.exists(os.path.join(self.root, "tmp", "podkop_sub.lock")))
        self.assertFalse(os.path.exists(os.path.join(self.root, "tmp", "podkop_sub")))

    def test_unchanged_list_does_not_touch_podkop(self):
        self.sync()
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.reloads(), 1, "без изменений podkop не перезапускается")
        self.assertEqual(self.podkop_commits(), 1, "и конфиг podkop не переписывается")
        self.assertIn("Без изменений", self.status()[1])
        self.assertEqual(self.status()[0], "ok")

    def test_changed_public_key_reloads(self):
        """Имя и адрес ноды прежние, сменился только публичный ключ — это изменение."""
        self.sync()
        self.sub("one", N1.replace("PBK_ONE", "PBK_NEW") + "\n" + N2 + "\n")
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.reloads(), 2)
        self.assertIn("pbk=PBK_NEW", self.links()[0])
        self.assertEqual(len(self.links()), 2)

    def test_changed_sni_and_short_id_reload(self):
        self.sync()
        self.sub("one", N1.replace("sni=www.example.com", "sni=cdn.example.com") + "\n" + N2 + "\n")
        self.sync()
        self.assertEqual(self.reloads(), 2)
        self.sub("one", N1.replace("sni=www.example.com", "sni=cdn.example.com") + "\n"
                 + N2.replace("sid=bb22", "sid=cc33") + "\n")
        self.sync()
        self.assertEqual(self.reloads(), 3)
        self.assertIn("sid=cc33", self.links()[1])

    def test_rename_only_updates_config_without_reload(self):
        self.sync()
        renamed = N1.split("#")[0] + "#Renamed"
        self.sub("one", renamed + "\n" + N2 + "\n")
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [renamed, N2])
        self.assertEqual(self.reloads(), 1, "podkop имя ноды не использует")
        self.assertIn("только имена или порядок", self.status()[1])

    def test_reorder_only_does_not_reload(self):
        self.sync()
        self.sub("one", N2 + "\n" + N1 + "\n")
        self.sync()
        self.assertEqual(self.links(), [N2, N1])
        self.assertEqual(self.reloads(), 1)

    def test_download_failure_keeps_config(self):
        self.sync()
        os.remove(os.path.join(self.stub, "subs", "one"))
        self.assertEqual(self.sync(), 1)
        self.assertEqual(self.links(), [N1, N2])
        self.assertEqual(self.reloads(), 1)
        st, msg = self.status()
        self.assertEqual(st, "error")
        self.assertIn("конфиг не изменён", msg)

    def test_one_of_two_subscriptions_failing_keeps_config(self):
        self.set_opt("podkop_sub", "config", "url", ["https://sub.test/one", "https://sub.test/two"])
        n3 = N2.replace("n2.example.net", "n3.example.net").split("#")[0] + "#Three"
        self.sub("two", n3 + "\n")
        self.sync()
        self.assertEqual(self.links(), [N1, N2, n3])
        os.remove(os.path.join(self.stub, "subs", "two"))
        self.assertEqual(self.sync(), 1)
        self.assertEqual(self.links(), [N1, N2, n3], "ноды недоступной подписки не удаляются")
        self.assertIn("#2=нет_сети", self.status()[1])

    def test_panel_stub_does_not_replace_nodes(self):
        self.sync()
        self.sub("one", STUB_NODE + "\n")
        self.assertEqual(self.sync(), 1)
        self.assertEqual(self.links(), [N1, N2])
        self.assertEqual(self.status()[0], "error")

    def test_external_node_with_space_survives_intact(self):
        ext = "vless://ext@ext.example.net:443?type=tcp#My Node"
        d = self.read_db()
        d["podkop"]["main"]["urltest_proxy_links"] = [ext]
        self.write_db(d)
        self.sync()
        self.sync()
        self.assertEqual(self.links(), [ext, N1, N2], "ссылка с пробелом не рвётся на куски")

    def test_three_kinds_of_nodes_and_their_order(self):
        """Внешние (добавлены прямо в podkop) -> ручные из поля плагина -> подписка."""
        ext = "vless://ext@ext.example.net:443?type=tcp#external"
        man = "vless://m@manual.example.net:443?type=tcp#manual"
        d = self.read_db()
        d["podkop"]["main"]["urltest_proxy_links"] = [ext]
        d["podkop_sub"]["config"]["manual_nodes"] = man + "\nне ссылка\n"
        self.write_db(d)
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [ext, man, N1, N2])
        self.assertIn("вручную: 1, внешних: 1, всего: 4", self.status()[1])
        # подписка сократилась: уходит только её нода, внешняя и ручная на месте
        self.sub("one", N1 + "\n")
        self.sync()
        self.assertEqual(self.links(), [ext, man, N1])
        # ручную убрали из поля: она удаляется, внешняя остаётся
        self.set_opt("podkop_sub", "config", "manual_nodes", "")
        self.sync()
        self.assertEqual(self.links(), [ext, N1])

    def test_preserve_off_removes_external_nodes(self):
        ext = "vless://ext@ext.example.net:443?type=tcp#external"
        d = self.read_db()
        d["podkop"]["main"]["urltest_proxy_links"] = [ext]
        d["podkop_sub"]["config"]["preserve_manual"] = "0"
        self.write_db(d)
        self.sync()
        self.assertEqual(self.links(), [N1, N2])

    def test_node_moved_from_external_to_manual_field_is_owned_by_plugin(self):
        """Список в podkop не меняется, но нода теперь «наша»: после удаления из поля она должна уйти."""
        man = "vless://m@manual.example.net:443?type=tcp#manual"
        d = self.read_db()
        d["podkop"]["main"]["urltest_proxy_links"] = [man]     # сначала добавлена прямо в podkop
        self.write_db(d)
        self.sync()
        self.assertEqual(self.links(), [man, N1, N2])
        self.set_opt("podkop_sub", "config", "manual_nodes", man)   # перенесли в поле плагина
        self.sync()
        self.assertEqual(self.links(), [man, N1, N2])
        self.assertEqual(self.reloads(), 1, "набор нод тот же — перезапуска нет")
        self.set_opt("podkop_sub", "config", "manual_nodes", "")    # и убрали из поля
        self.sync()
        self.assertEqual(self.links(), [N1, N2])

    def test_deduplicate_option(self):
        twin = N1.split("#")[0] + "#Twin"
        self.sub("one", N1 + "\n" + twin + "\n")
        self.sync()
        self.assertEqual(len(self.links()), 1, "дубликат сервера убран")
        self.set_opt("podkop_sub", "config", "deduplicate", "0")
        self.sync()
        self.assertEqual(len(self.links()), 2)

    def test_user_agent_is_passed_to_curl(self):
        self.set_opt("podkop_sub", "config", "user_agent", "Happ/1.60.0")
        self.sync()
        self.assertIn("-A Happ/1.60.0", self.log("curl.log")[0])

    def test_other_section_is_targeted(self):
        d = self.read_db()
        d["podkop"]["second"] = {".type": "section", "proxy_config_type": "urltest"}
        d["podkop_sub"]["config"]["section"] = "second"
        self.write_db(d)
        self.sync()
        self.assertEqual(self.read_db()["podkop"]["second"]["urltest_proxy_links"], [N1, N2])
        self.assertEqual(self.links(), [])
        d = self.read_db()
        d["podkop_sub"]["config"]["section"] = "missing"
        self.write_db(d)
        self.assertEqual(self.sync(), 1)
        self.assertIn("не найдена", self.status()[1])

    def test_empty_result_is_never_written(self):
        self.sync()
        self.set_opt("podkop_sub", "config", "url", [])
        self.assertEqual(self.sync(), 1)
        self.assertEqual(self.links(), [N1, N2], "пустой список в podkop не пишется")
        self.assertEqual(self.reloads(), 1)
        self.assertIn("пуст", self.status()[1])

    def test_no_subscription_keeps_manual_nodes(self):
        self.sync()
        self.set_opt("podkop_sub", "config", "url", [])
        man = "vless://m@manual.example.net:443?type=tcp#manual"
        self.set_opt("podkop_sub", "config", "manual_nodes", man)
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [man])
        self.assertEqual(self.reloads(), 2)

    def test_lock_blocks_parallel_run_and_stale_lock_is_ignored(self):
        lock = os.path.join(self.root, "tmp", "podkop_sub.lock")
        os.mkdir(lock)
        with open(os.path.join(lock, "pid"), "w") as f:
            f.write(str(os.getpid()))          # живой процесс: блокировка занята
        self.assertEqual(self.sync(), 2)
        self.assertEqual(self.links(), [])
        self.assertTrue(os.path.isdir(lock), "чужую блокировку не снимаем")
        p = subprocess.Popen(["true"])
        p.wait()
        with open(os.path.join(lock, "pid"), "w") as f:
            f.write(str(p.pid))                # процесс уже умер: блокировка брошена
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [N1, N2])
        self.assertFalse(os.path.exists(lock))

    def test_disabled_podkop_is_not_started(self):
        self.flag("podkop_disabled")
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [N1, N2])
        self.assertEqual(self.reloads(), 0)
        self.assertIn("Podkop выключен", self.status()[1])

    def test_non_urltest_section_is_not_reloaded(self):
        self.set_opt("podkop", "main", "proxy_config_type", "url")
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.reloads(), 0)
        self.assertEqual(self.status()[0], "warn")

    def test_failed_reload_is_reported(self):
        self.flag("podkop_fail")
        self.assertEqual(self.sync(), 1)
        st, msg = self.status()
        self.assertEqual(st, "error")
        self.assertIn("podkop не запустился", msg)

    def test_singbox_not_running_after_reload_is_reported(self):
        self.flag("no_singbox")
        self.assertEqual(self.sync(), 1)
        self.assertEqual(self.status()[0], "error")

    def test_bad_urls_never_reach_curl(self):
        for bad in ("-o/etc/passwd", "file:///etc/passwd", "ftp://sub.test/one", "--config=/tmp/x"):
            self.set_opt("podkop_sub", "config", "url", [bad])
            self.assertEqual(self.sync(), 1, bad)
            self.assertEqual(self.log("curl.log"), [], bad)
            self.assertIn("плохой_URL", self.status()[1])
        self.assertEqual(self.links(), [])

    def test_curl_is_called_safely_and_url_not_logged(self):
        self.set_opt("podkop_sub", "config", "url", ["https://sub.test/one?token=SECRET"])
        self.sub("one?token=SECRET", N1 + "\n")
        self.assertEqual(self.sync(), 0)
        line = self.log("curl.log")[0]
        self.assertIn("--proto =http,https", line)
        self.assertIn("--max-filesize", line)
        self.assertIn(" -- https://sub.test/one?token=SECRET", line)
        os.remove(os.path.join(self.stub, "subs", "one?token=SECRET"))
        self.sync()
        self.assertNotIn("SECRET", "\n".join(self.log("syslog")))
        self.assertNotIn("SECRET", self.status()[1])

    def test_commit_failure_reverts(self):
        self.sync()
        self.sub("one", N1 + "\n")
        open(self.db + ".fail_commit", "w").close()
        self.assertEqual(self.sync(), 1)
        os.remove(self.db + ".fail_commit")
        self.assertEqual(self.links(), [N1, N2])
        self.assertEqual(self.reloads(), 1)
        self.assertEqual(self.sync(), 0, "после сбоя следующая синхронизация проходит")
        self.assertEqual(self.links(), [N1])

    def test_add_list_failure_reverts(self):
        self.sync()
        self.sub("one", N1 + "\n")
        open(self.db + ".fail_add", "w").close()
        self.assertEqual(self.sync(), 1)
        os.remove(self.db + ".fail_add")
        self.assertEqual(self.links(), [N1, N2])
        self.assertEqual(self.reloads(), 1)

    def test_malicious_subscription_content_is_dropped(self):
        evil = ("vless://u@<img/src=x/onerror=alert(1)>:443?type=tcp#x\n"
                "vless://u@a b:443?type=tcp#y\n"
                "vless://u@[2001:db8::1]:443?type=tcp#v6\n" + N1 + "\n")
        self.sub("one", evil)
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [N1])

    def test_status_json_is_valid(self):
        d = self.read_db()
        d["podkop"]["main"]["urltest_proxy_links"] = [
            'vless://e@e.example.net:443?type=tcp#quo"te\\back', "ss://not-vless@h:1#x", N1]
        d["podkop_sub"]["config"]["last_update"] = "not-a-number"
        d["podkop_sub"]["config"]["last_message"] = 'he said "hi"'
        self.write_db(d)
        out = self.run_svc("status").stdout
        st = json.loads(out)
        self.assertEqual(st["count"], 2)
        self.assertEqual(st["last_update"], 0)
        self.assertEqual(st["nodes"][0], 'vless://e@e.example.net:443?type=tcp#quo"te\\back')
        self.assertEqual(st["message"], 'he said "hi"')


class StickyTests(SyncEnv):
    """Подписка (3x-ui) каждый раз выдаёт случайные SNI и short id из списков ноды."""
    N1_ROLLED = N1.replace("sni=www.example.com", "sni=other.example.com").replace("sid=aa11", "sid=ff99")
    N2_ROLLED = N2.replace("sid=bb22", "sid=ee88")
    auto_noise = True       # в этих тестах панель при каждом скачивании выдаёт другой SNI

    def test_working_nodes_keep_sni_and_short_id(self):
        self.sync()
        self.health(**{"main-1-out": 120, "main-2-out": 95})
        for _ in range(3):
            self.sub("one", self.N1_ROLLED + "\n" + self.N2_ROLLED + "\n")
            self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [N1, N2], "у работающих нод ссылки прежние")
        self.assertEqual(self.reloads(), 1, "podkop не перезапускается")
        self.assertEqual(self.podkop_commits(), 1)
        st, msg = self.status()
        self.assertEqual(st, "ok")
        self.assertIn("Без изменений", msg)
        self.assertIn("сохранены у работающих: 2", msg)

    def test_server_listed_twice_does_not_grow_the_list(self):
        """Как у Liberty: один сервер приходит и отдельной строкой, и в «авто»-группе,
        а SNI/short id при каждом скачивании случайные. Список не должен расти и меняться."""
        def fetch(n):
            a = N1.replace("sni=www.example.com", "sni=r%d.example.com" % n).replace("sid=aa11", "sid=%04d" % n)
            return a.split("#")[0] + "#Auto\n" + a.split("#")[0] + "#Poland\n" + N2 + "\n"
        self.sub("one", fetch(1))
        self.assertEqual(self.sync(), 0)
        first = self.links()
        self.assertEqual(len(first), 2, "две копии одного сервера — одна нода")
        self.health(**{"main-1-out": 120, "main-2-out": 95})
        for n in (2, 3, 4):
            self.sub("one", fetch(n))
            self.assertEqual(self.sync(), 0)
            self.assertEqual(self.links(), first, "повторное скачивание с другими SNI ничего не меняет")
        self.assertEqual(self.reloads(), 1)
        self.assertIn("Без изменений", self.status()[1])

    def test_broken_node_gets_fresh_values(self):
        """На сервере убрали имя — нода встала: ей берём свежие SNI/short id, рабочую не трогаем."""
        self.sync()
        self.health(**{"main-1-out": None, "main-2-out": 95})
        self.sub("one", self.N1_ROLLED + "\n" + self.N2_ROLLED + "\n")
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [self.N1_ROLLED, N2])
        self.assertEqual(self.reloads(), 2)
        self.assertIn("сохранены у работающих: 1", self.status()[1])

    def test_dead_node_is_refreshed_once_then_left_alone(self):
        """Лежащая нода не должна менять список при каждой синхронизации."""
        self.sync()
        self.health(**{"main-1-out": None, "main-2-out": 95})
        self.sub("one", self.N1_ROLLED + "\n" + N2 + "\n")
        self.assertEqual(self.sync(), 0)                       # первая попытка вылечить: свежие значения
        self.assertEqual(self.links(), [self.N1_ROLLED, N2])
        self.assertEqual(self.reloads(), 2)
        self.assertIn("не отвечают: 1", self.status()[1])
        again = self.N1_ROLLED.replace("sni=other.example.com", "sni=third.example.com").replace("sid=ff99", "sid=1234")
        for _ in range(3):                                     # нода всё ещё лежит, панель выдаёт всё новые SNI
            self.sub("one", again + "\n" + N2 + "\n")
            self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [self.N1_ROLLED, N2], "список не меняется")
        self.assertEqual(self.reloads(), 2, "и podkop не перезапускается")
        self.assertIn("Без изменений", self.status()[1])
        # по кнопке (force) — ещё одна попытка
        self.assertEqual(self.run_svc("sync", "force").returncode, 0)
        self.assertEqual(self.links(), [again, N2])
        self.assertEqual(self.reloads(), 3)
        # а лежащую ноду ИЗ ВТОРОЙ подписки кнопка не трогает: чужие серверы не повод перезапускаться
        self.set_opt("podkop_sub", "config", "url", ["https://sub.test/one", "https://sub.test/two"])
        ext1 = N2.replace("n2.example.net", "x7.example.net").replace("PBK_TWO", "PBK_X7").split("#")[0] + "#Foreign"
        self.sub("one", again + "\n" + N2 + "\n")
        self.sub("two", ext1 + "\n")
        self.health(**{"main-1-out": 110, "main-2-out": 95})
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [again, N2, ext1])
        n = self.reloads()
        self.health(**{"main-1-out": 110, "main-2-out": 95, "main-3-out": None})
        ext2 = ext1.replace("sid=bb22", "sid=7777")
        self.sub("two", ext2 + "\n")
        self.assertEqual(self.sync(), 0)                       # первая попытка — как у всех
        self.assertEqual(self.reloads(), n + 1)
        self.sub("two", ext1.replace("sid=bb22", "sid=8888") + "\n")
        self.assertEqual(self.run_svc("sync", "force").returncode, 0)
        self.assertEqual(self.links(), [again, N2, ext2], "по кнопке чужая лежащая нода не меняется")
        self.assertEqual(self.reloads(), n + 1)
        self.set_opt("podkop_sub", "config", "url", ["https://sub.test/one"])
        self.sub("one", self.N1_ROLLED + "\n" + N2 + "\n")
        self.sync()
        # нода ожила — отметка снимается, дальше обычное закрепление
        self.health(**{"main-1-out": 110, "main-2-out": 95})
        self.sub("one", self.N1_ROLLED + "\n" + N2 + "\n")
        self.sync()
        self.assertEqual(self.links(), [again, N2])
        self.assertNotIn("не отвечают", self.status()[1])

    def test_changed_public_key_is_never_stuck(self):
        self.sync()
        self.health(**{"main-1-out": 120, "main-2-out": 95})
        new1 = self.N1_ROLLED.replace("PBK_ONE", "PBK_NEW")
        self.sub("one", new1 + "\n" + N2 + "\n")
        self.sync()
        self.assertEqual(self.links(), [new1, N2], "смена ключа — другая нода, закрепление не действует")
        self.assertEqual(self.reloads(), 2)

    def test_changed_address_or_port_is_never_stuck(self):
        self.sync()
        self.health(**{"main-1-out": 120, "main-2-out": 95})
        moved = self.N1_ROLLED.replace("n1.example.net:443", "n9.example.net:8443")
        self.sub("one", moved + "\n" + N2 + "\n")
        self.sync()
        self.assertEqual(self.links(), [moved, N2])
        self.assertEqual(self.reloads(), 2)

    def test_no_health_data_means_no_sticking(self):
        """Clash API недоступен (выключен YACD): безопаснее взять свежие значения."""
        self.sync()
        self.sub("one", self.N1_ROLLED + "\n" + N2 + "\n")
        self.sync()
        self.assertEqual(self.links(), [self.N1_ROLLED, N2])
        self.assertEqual(self.reloads(), 2)
        self.assertNotIn("сохранены", self.status()[1])

    def test_node_without_history_is_treated_as_broken(self):
        self.sync()
        self.health(**{"main-2-out": 95})          # про main-1-out данных нет вовсе
        self.sub("one", self.N1_ROLLED + "\n" + self.N2_ROLLED + "\n")
        self.sync()
        self.assertEqual(self.links(), [self.N1_ROLLED, N2])

    def test_option_off_disables_sticking(self):
        self.sync()
        self.health(**{"main-1-out": 120, "main-2-out": 95})
        self.set_opt("podkop_sub", "config", "sticky", "0")
        self.sub("one", self.N1_ROLLED + "\n" + N2 + "\n")
        self.sync()
        self.assertEqual(self.links(), [self.N1_ROLLED, N2])
        self.assertEqual(self.reloads(), 2)

    def test_rename_with_sticking_updates_name_only(self):
        self.sync()
        self.health(**{"main-1-out": 120, "main-2-out": 95})
        self.sub("one", self.N1_ROLLED.split("#")[0] + "#Renamed\n" + N2 + "\n")
        self.sync()
        self.assertEqual(self.links(), [N1.split("#")[0] + "#Renamed", N2])
        self.assertEqual(self.reloads(), 1)

    def test_manual_and_external_nodes_are_not_touched_by_sticking(self):
        ext = "vless://ext@ext.example.net:443?type=tcp&sni=e.example#external"
        man = "vless://m@manual.example.net:443?type=tcp&sni=old.example#manual"
        d = self.read_db()
        d["podkop"]["main"]["urltest_proxy_links"] = [ext]
        d["podkop_sub"]["config"]["manual_nodes"] = man
        self.write_db(d)
        self.sync()
        self.assertEqual(self.links(), [ext, man, N1, N2])
        # порядок в секции: 1 — внешняя, 2 — ручная, 3 и 4 — из подписки
        self.health(**{"main-1-out": 50, "main-2-out": 60, "main-3-out": 120, "main-4-out": 95})
        man2 = man.replace("sni=old.example", "sni=new.example")     # пользователь сам поменял SNI ручной ноды
        self.set_opt("podkop_sub", "config", "manual_nodes", man2)
        self.sub("one", self.N1_ROLLED + "\n" + self.N2_ROLLED + "\n")
        self.sync()
        self.assertEqual(self.links(), [ext, man2, N1, N2], "ручная правка применена, ноды подписки закреплены")
        self.assertEqual(self.reloads(), 2)

    def test_health_is_requested_from_clash_api(self):
        self.sync()
        self.assertTrue(any("http://127.0.0.1:9090/proxies" in l for l in self.log("curl.log")))


class ChosenSniTests(SyncEnv):
    """Владелец оставил на сервере одно имя SNI: оно должно примениться, даже если прежнее ещё работает."""
    NEW = N1.replace("sni=www.example.com", "sni=api.example.ru")

    def test_consistent_new_sni_is_applied_to_a_working_node(self):
        self.sync()
        self.health(**{"main-1-out": 120, "main-2-out": 95})
        self.sub("one", self.NEW + "\n" + N2 + "\n")            # все скачивания дают одно и то же имя
        self.assertEqual(self.sync(), 0)
        self.assertIn("sni=api.example.ru", self.links()[0])
        self.assertEqual(self.links()[1], N2, "вторая нода не менялась — её не трогаем")
        self.assertEqual(self.reloads(), 2)
        self.assertIn("приняты новые SNI с сервера: 1", self.status()[1])
        self.assertEqual(self.sync(), 0)                           # дальше тихо
        self.assertEqual(self.reloads(), 2)
        self.assertIn("Без изменений", self.status()[1])
        self.assertEqual(len([l for l in self.log("curl.log") if "sample_" in l]) % 3, 0, "по три доп. скачивания на синк")

    def test_random_sni_is_still_ignored(self):
        self.sync()
        self.health(**{"main-1-out": 120, "main-2-out": 95})
        self.sub("one", self.NEW + "\n" + N2 + "\n", noisy=True)  # панель выдаёт случайные имена
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [N1, N2])
        self.assertEqual(self.reloads(), 1)

    def test_consistent_sni_revives_a_frozen_dead_node(self):
        self.sync()
        self.health(**{"main-1-out": None, "main-2-out": 95})
        rolled = N1.replace("sni=www.example.com", "sni=bad.example.com")
        self.sub("one", rolled + "\n" + N2 + "\n", noisy=True)
        self.sync()                                                # нода не отвечает: свежие значения, один раз
        dead_link = self.links()[0]
        self.sub("one", rolled.replace("bad.example.com", "bad2.example.com") + "\n" + N2 + "\n", noisy=True)
        self.sync()
        self.assertEqual(self.links()[0], dead_link, "лежащую ноду со случайными именами больше не трогаем")
        self.sub("one", self.NEW + "\n" + N2 + "\n")            # владелец оставил одно имя
        n = self.reloads()
        self.assertEqual(self.sync(), 0)
        self.assertIn("sni=api.example.ru", self.links()[0])
        self.assertEqual(self.reloads(), n + 1)

    def test_only_first_subscription_is_sampled(self):
        self.set_opt("podkop_sub", "config", "url", ["https://sub.test/one", "https://sub.test/two"])
        foreign = N2.replace("n2.example.net", "x7.example.net").replace("PBK_TWO", "PBK_X7").split("#")[0] + "#Foreign"
        self.sub("two", foreign + "\n")
        self.sync()
        self.health(**{"main-1-out": 120, "main-2-out": 95, "main-3-out": 80})
        self.sub("two", foreign.replace("sni=www.example.org", "sni=other.example.org") + "\n")
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links()[2], foreign, "чужая подписка: одно скачивание, имя остаётся закреплённым")
        self.assertFalse(any("sample_" in l and "two" in l for l in self.log("curl.log")))


class VersionTests(SyncEnv):
    def test_version_matches_makefile_and_is_reported(self):
        with open(os.path.join(HERE, "..", "luci-app-podkop-sync", "Makefile"), encoding="utf-8") as f:
            mk = [l.split(":=")[1].strip() for l in f if l.startswith("PKG_VERSION:=")][0]
        st = json.loads(self.run_svc("status").stdout)
        self.assertEqual(st["version"], mk + "-dev", "VERSION в podkop_sub_service должна совпадать с PKG_VERSION")

    def test_ci_build_number_is_shown(self):
        """Сборка на GitHub подставляет номер запуска той же командой sed, что в build.yml."""
        with open(SERVICE, encoding="utf-8") as f:
            src = f.read()
        self.assertEqual(src.count('\nRELEASE="dev"\n'), 1)
        stamped = os.path.join(self.root, "svc_stamped")
        self._script(stamped, src.replace('\nRELEASE="dev"\n', '\nRELEASE="57"\n'))
        out = subprocess.run(["sh", stamped, "status"], env=self.env, capture_output=True, text=True).stdout
        self.assertTrue(json.loads(out)["version"].endswith("-r57"), out)


class ProtectionTests(SyncEnv):
    """Нода, которую podkop не понимает, не должна оставлять дом без интернета."""
    # параметры в алфавитном порядке — так их выдаёт парсер
    XH = ("vless://11111111-2222-4333-8444-555555555555@x1.example.net:8443?encryption=none&fp=firefox"
          "&mode=stream-one&path=%2Fapi&pbk=PBK_X&security=reality&sid=dd44&sni=x.example.com&type=xhttp#XH")
    WS = ("vless://11111111-2222-4333-8444-555555555555@w1.example.net:443?encryption=none&fp=edge"
          "&host=w1.example.net&path=%2Ffeed&security=tls&sni=w1.example.net&type=ws#WS")
    KCP = "vless://11111111-2222-4333-8444-555555555555@k1.example.net:443?type=kcp&security=none#KCP"
    BAD = "vless://11111111-2222-4333-8444-555555555555@bad.example.net:443?type=tcp&security=none&x=BADNODE#Bad"
    BAD_R = ("vless://11111111-2222-4333-8444-555555555555@bad2.example.net:443?encryption=none&fp=firefox"
             "&pbk=PBK_B&security=reality&sid=77&sni=b.example.com&type=tcp&x=BADNODE#Bad")

    def sing_box_alive(self):
        return not os.path.exists(os.path.join(self.stub, "singbox_dead"))

    def test_xhttp_nodes_are_dropped_when_not_supported(self):
        """Сценарий с подпиской Liberty: xhttp-ноды отсекаются до записи, podkop не падает."""
        self.sub("one", N1 + "\n" + self.XH + "\n" + self.WS + "\n" + self.KCP + "\n" + N2 + "\n")
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [N1, self.WS, N2])
        self.assertTrue(self.sing_box_alive())
        st, msg = self.status()
        self.assertEqual(st, "ok")
        self.assertIn("#1=3", msg)
        self.assertIn("не поддерживаются podkop и пропущены: 2 (kcp: 1, xhttp: 1)", msg)

    def test_xhttp_nodes_are_kept_when_sing_box_supports_them(self):
        with open(os.path.join(self.stub, "features"), "w") as f:
            f.write('["tools.decode-link","with_quic"]')
        self.flag("xhttp_ok")
        self.sub("one", N1 + "\n" + self.XH + "\n")
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [N1, self.XH])
        self.assertNotIn("пропущены", self.status()[1])

    def test_manual_xhttp_node_is_skipped(self):
        ok_manual = "vless://m@manual.example.net:443?security=none#no-type-means-tcp"
        self.set_opt("podkop_sub", "config", "manual_nodes",
                     self.XH + "\n" + self.KCP + "\n" + self.XH.replace("type=xhttp", "type=XHTTP").replace("x1.", "x2.")
                     + "\n" + ok_manual + "\nvless://m@h.example.net:443?type=tcp#name-with-type=xhttp-inside")
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [ok_manual, "vless://m@h.example.net:443?type=tcp#name-with-type=xhttp-inside", N1, N2])
        self.assertIn("пропущено ручных с неподдерживаемым транспортом: 3", self.status()[1])

    def test_rollback_when_podkop_rejects_new_nodes(self):
        self.sync()
        self.assertEqual(self.reloads(), 1)
        self.sub("one", N1 + "\n" + N2 + "\n" + self.BAD + "\n")     # транспорт допустимый, но podkop её не переварит
        self.assertEqual(self.sync(), 1)
        self.assertEqual(self.links(), [N1, N2], "возвращён прежний список")
        self.assertTrue(self.sing_box_alive(), "после отката podkop снова работает")
        self.assertEqual(self.reloads(), 3, "попытка + откат")
        st, msg = self.status()
        self.assertEqual(st, "error")
        self.assertIn("возвращён прежний список (2)", msg)
        self.assertIn("Причина: The xhttp transport is not supported", msg)     # первая fatal-строка ЭТОЙ попытки
        self.assertNotIn("is invalid", msg)
        self.assertNotIn("OLD unrelated", msg)
        c = self.read_db()["podkop_sub"]["config"]
        self.assertEqual((c["last_sub"], c["last_count"]), ("2", "2"), "плитки показывают то, что реально применено")
        with open(os.path.join(self.root, "etc", "podkop_sub.managed.d", "main")) as f:
            self.assertEqual(f.read().split(), [N1, N2], "реестр тоже возвращён")

    def test_rejected_set_is_not_applied_again(self):
        """Ночной cron не должен ронять сеть каждый раз одной и той же плохой подпиской."""
        self.sync()
        self.sub("one", N1 + "\n" + N2 + "\n" + self.BAD + "\n")
        self.sync()
        n = self.reloads()
        # панель при следующем скачивании выдала другие SNI/short id — набор по сути тот же
        rolled = (N1.replace("sni=www.example.com", "sni=zzz.example.com").replace("sid=aa11", "sid=9999") + "\n" + N2 + "\n"
                  + self.BAD_R.replace("sni=b.example.com", "sni=other.example.com").replace("sid=77", "sid=88").replace("#Bad", "#Renamed") + "\n")
        self.sub("one", N1 + "\n" + N2 + "\n" + self.BAD_R + "\n")
        self.assertEqual(self.sync(), 1)                 # другой плохой набор — честная попытка и откат
        n = self.reloads()
        self.sub("one", rolled)
        self.assertEqual(self.sync(), 1)
        self.assertEqual(self.sync(), 1)
        self.assertEqual(self.reloads(), n, "podkop больше не дёргаем: набор тот же с точностью до SNI/short id/имён")
        self.assertEqual(self.links(), [N1, N2])
        self.assertIn("уже отверг", self.status()[1])
        # кнопка в LuCI (force) — человек просит попробовать ещё раз
        self.assertEqual(self.run_svc("sync", "force").returncode, 1)
        self.assertEqual(self.reloads(), n + 2, "по кнопке попытка делается")
        n = self.reloads()
        # podkop обновили — пробуем снова (и снова откатываемся, раз нода всё ещё плохая)
        with open(os.path.join(self.stub, "version"), "w") as f:
            f.write("v0.8.0")
        self.assertEqual(self.sync(), 1)
        self.assertEqual(self.reloads(), n + 2)
        # плохую ноду убрали из подписки — всё применяется, отметка об отказе снята
        self.sub("one", N1 + "\n")
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [N1])
        self.assertFalse(os.path.exists(os.path.join(self.root, "etc", "podkop_sub.managed.d", "main.rejected")))

    def test_rollback_keeps_external_and_manual_nodes(self):
        ext = "vless://ext@ext.example.net:443?type=tcp#external"
        d = self.read_db()
        d["podkop"]["main"]["urltest_proxy_links"] = [ext]
        self.write_db(d)
        self.sync()
        self.assertEqual(self.links(), [ext, N1, N2])
        self.set_opt("podkop_sub", "config", "manual_nodes", self.BAD)
        self.assertEqual(self.sync(), 1)
        self.assertEqual(self.links(), [ext, N1, N2])
        self.assertTrue(self.sing_box_alive())

    def test_no_previous_list_means_nothing_to_roll_back_to(self):
        self.sub("one", self.BAD + "\n")
        self.assertEqual(self.sync(), 1)
        st, msg = self.status()
        self.assertEqual(st, "error")
        self.assertIn("вернуть нечего", msg)

    def test_rollback_failure_is_reported_and_not_remembered(self):
        """Podkop не поднялся и на прежнем списке: виноваты не ноды, отказ запоминать нельзя."""
        self.sync()
        n3 = N2.replace("n2.example.net", "n3.example.net").split("#")[0] + "#Three"
        self.sub("one", N1 + "\n" + N2 + "\n" + n3 + "\n")          # набор хороший
        self.flag("podkop_fail")                                      # но podkop сейчас не запускается вообще
        self.assertEqual(self.sync(), 1)
        self.assertEqual(self.links(), [N1, N2], "прежний список всё равно записан")
        self.assertIn("ни на новых нодах, ни на прежних", self.status()[1])
        self.assertFalse(os.path.exists(os.path.join(self.root, "etc", "podkop_sub.managed.d", "main.rejected")))
        self.flag("podkop_fail", False)                               # причину устранили
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [N1, N2, n3], "хороший набор применяется при следующем запуске")

    def test_write_failure_during_rollback_is_reported_honestly(self):
        self.sync()
        self.sub("one", N1 + "\n" + self.BAD + "\n")
        # запись нового списка проходит, а при откате uci начинает отказывать
        self._script(os.path.join(self.stub, "bin", "podkop"),
                     '#!/bin/sh\ncase "$1" in get_sing_box_features) echo "[]"; exit 0;; show_version) echo v; exit 0;; esac\n'
                     'echo "$*" >> "$STUB/podkop.log"\ntouch "$FAKE_UCI_DB.fail_add"\ntouch "$STUB/singbox_dead"\nexit 1\n')
        self.assertEqual(self.sync(), 1)
        msg = self.status()[1]
        self.assertIn("вернуть прежний список не удалось", msg)
        self.assertNotIn("был пуст", msg)
        self.assertFalse(os.path.exists(os.path.join(self.root, "etc", "podkop_sub.managed.d", "main.rejected")))

    def test_termination_signal_during_reload_does_not_skip_rollback(self):
        self.sync()
        self.sub("one", N1 + "\n" + N2 + "\n" + self.BAD + "\n")
        self.flag("term_parent")                 # во время podkop reload процессу sync прилетает SIGTERM
        self.sync()
        self.assertEqual(self.links(), [N1, N2], "откат выполнен, несмотря на сигнал")
        self.assertTrue(self.sing_box_alive())
        self.assertEqual(self.status()[0], "error")
        self.assertFalse(os.path.exists(os.path.join(self.root, "tmp", "podkop_sub.lock")))

    def test_subscription_with_only_unsupported_nodes_does_not_block_others(self):
        """Ровно сценарий инцидента: добавили вторую подписку, а в ней один xhttp."""
        self.set_opt("podkop_sub", "config", "url", ["https://sub.test/one", "https://sub.test/two"])
        self.sub("two", self.XH + "\n")
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [N1, N2])
        st, msg = self.status()
        self.assertEqual(st, "ok")
        self.assertIn("#2=0(транспорт не поддерживается)", msg)
        self.sub("one", N1 + "\n")              # первая подписка продолжает обновляться
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [N1])

    def test_flapping_sing_box_is_not_taken_for_success(self):
        """sing-box стартует и сразу падает, procd его перезапускает: pid каждый раз новый."""
        self.sync()
        self.sub("one", N1 + "\n")
        self.flag("singbox_flapping")
        self.assertEqual(self.sync(), 1)
        self.assertEqual(self.status()[0], "error")

    def test_dead_podkop_is_revived_when_nothing_changed(self):
        self.sync()
        self.flag("no_singbox")
        self.assertEqual(self.sync(), 1)
        self.assertIn("podkop не запускается", self.status()[1])
        self.flag("no_singbox", False)
        self.flag("singbox_dead")                # sing-box лежит, список не менялся; reload его поднимет
        n = self.reloads()
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.reloads(), n + 1)
        self.assertIn("Podkop не работал — перезапущен", self.status()[1])

    def test_status_reports_running_sync(self):
        self.assertFalse(json.loads(self.run_svc("status").stdout)["running"])
        lock = os.path.join(self.root, "tmp", "podkop_sub.lock")
        os.mkdir(lock)
        with open(os.path.join(lock, "pid"), "w") as f:
            f.write(str(os.getpid()))
        self.assertTrue(json.loads(self.run_svc("status").stdout)["running"])


class OriginsTests(SyncEnv):
    """Плагин сообщает, из какой подписки каждая нода: по этому проба проверяет только «свои»."""

    def origins(self):
        p = os.path.join(self.root, "etc", "podkop_sub.managed.d", "main.origins")
        if not os.path.exists(p):
            return None
        with open(p, encoding="utf-8") as f:
            return [tuple(l.rstrip("\n").split("\t", 1)) for l in f if l.strip()]

    def test_origins_follow_subscription_order(self):
        ext = "vless://ext@ext.example.net:443?type=tcp#external"
        man = "vless://m@manual.example.net:443?type=tcp#manual"
        n3 = N2.replace("n2.example.net", "n3.example.net").split("#")[0] + "#Three"
        d = self.read_db()
        d["podkop"]["main"]["urltest_proxy_links"] = [ext]
        d["podkop_sub"]["config"]["manual_nodes"] = man
        d["podkop_sub"]["config"]["url"] = ["https://sub.test/one", "https://sub.test/two"]
        self.write_db(d)
        self.sub("two", n3 + "\n" + N1 + "\n")           # N1 есть в обеих: считается нодой первой подписки
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [ext, man, N1, N2, n3])
        self.assertEqual(self.origins(), [("0", man), ("1", N1), ("1", N2), ("2", n3)],
                         "внешней ноды в файле нет, ручная — 0, дальше по номерам подписок")

    def test_origins_are_kept_in_sync_without_changes_and_on_rollback(self):
        self.sync()
        self.assertEqual(self.origins(), [("1", N1), ("1", N2)])
        os.remove(os.path.join(self.root, "etc", "podkop_sub.managed.d", "main.origins"))
        self.sync()                                        # список не менялся, файл восстановлен
        self.assertEqual(self.origins(), [("1", N1), ("1", N2)])
        self.sub("one", N1 + "\n" + N2 + "\n" + ProtectionTests.BAD + "\n")
        self.assertEqual(self.sync(), 1)                   # откат
        self.assertEqual(self.origins(), [("1", N1), ("1", N2)], "после отката источники тоже прежние")

    def test_origins_use_sticky_links(self):
        self.sync()
        self.health(**{"main-1-out": 120, "main-2-out": 95})
        self.sub("one", StickyTests.N1_ROLLED + "\n" + N2 + "\n", noisy=True)
        self.sync()
        self.assertEqual(self.origins(), [("1", N1), ("1", N2)], "в файле те же ссылки, что записаны в podkop")


class PreflightTests(SyncEnv):
    """Проверка до применения: podkop не должен падать вовсе, если отказ можно предвидеть."""
    BAD = ProtectionTests.BAD

    def setUp(self):
        super().setUp()
        self.flag("preflight_on")

    def test_bad_set_is_refused_without_touching_podkop(self):
        self.sync()
        self.assertEqual(self.reloads(), 1)
        commits = self.podkop_commits()
        self.sub("one", N1 + "\n" + N2 + "\n" + self.BAD + "\n")
        self.assertEqual(self.sync(), 1)
        self.assertEqual(self.reloads(), 1, "podkop не перезапускался — простоя не было")
        self.assertEqual(self.podkop_commits(), commits, "конфиг podkop не переписывался")
        self.assertEqual(self.links(), [N1, N2])
        st, msg = self.status()
        self.assertEqual(st, "error")
        self.assertIn("не сможет запуститься", msg)
        self.assertIn("список НЕ изменён", msg)
        self.assertIn("Причина: Node bad.example.net is not acceptable", msg)
        self.assertFalse(os.path.exists(os.path.join(self.root, "etc", "podkop_sub.managed.d", "main.rejected")),
                         "простоя не было — запоминать отказ незачем")
        with open(os.path.join(self.root, "etc", "podkop_sub.managed.d", "main")) as f:
            self.assertEqual(f.read().split(), [N1, N2], "реестр не тронут")

    def test_good_set_passes_preflight_and_is_applied(self):
        self.sync()
        n3 = N2.replace("n2.example.net", "n3.example.net").split("#")[0] + "#Three"
        self.sub("one", N1 + "\n" + N2 + "\n" + n3 + "\n")
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.links(), [N1, N2, n3])
        self.assertEqual(self.reloads(), 2)

    def test_preflight_runs_only_when_a_reload_is_coming(self):
        self.sync()
        n = len(self.log("dryrun.log"))
        self.assertEqual(n, 1)
        self.sync()                                              # без изменений
        self.sub("one", N1.split("#")[0] + "#Renamed\n" + N2 + "\n")
        self.sync()                                              # только имя
        self.assertEqual(len(self.log("dryrun.log")), n, "лишний раз конфиг не собираем")

    def test_unavailable_preflight_falls_back_to_rollback(self):
        self.sync()
        self.flag("preflight_on", False)                         # у «новой версии podkop» другое устройство
        self.sub("one", N1 + "\n" + N2 + "\n" + self.BAD + "\n")
        self.assertEqual(self.sync(), 1)
        self.assertEqual(self.links(), [N1, N2])
        self.assertIn("возвращён прежний список", self.status()[1])


class PackageScriptTests(SyncEnv):
    def _prerm(self):
        with open(os.path.join(HERE, "..", "luci-app-podkop-sync", "Makefile"), encoding="utf-8") as f:
            mk = f.read()
        body = mk.split("define Package/luci-app-podkop-sync/prerm\n", 1)[1].split("\nendef", 1)[0]
        return body.replace("$$", "$")

    def test_prerm_does_nothing_on_upgrade(self):
        """Система подключает prerm через «.» из default_prerm: $1 там — путь к обёртке,
        а признак обновления — PKG_UPGRADE=1. При обновлении реестр и cron трогать нельзя."""
        body = self._prerm()
        self.assertIn("rm -rf /etc/podkop_sub.managed.d", body)
        guard = body.index("PKG_UPGRADE")
        self.assertLess(guard, body.index("rm -rf"), "проверка обновления должна стоять до любых действий")
        self.assertLess(guard, body.index("sed -i"))
        script = os.path.join(self.root, "prerm-pkg")
        self._script(script, body)
        b = os.path.join(self.stub, "bin")
        for tool in ("rm", "sed"):
            self._script(os.path.join(b, tool), '#!/bin/sh\necho "%s $*" >> "$STUB/prerm.log"\n' % tool)
        # как в /lib/functions.sh: default_prerm <путь к обёртке> upgrade <версия>
        wrapper = 'default_prerm() { ( . "%s" ); }\ndefault_prerm /usr/lib/opkg/info/x.prerm upgrade 1.1.0-r1\n' % script
        env = dict(self.env, PATH=b, PKG_UPGRADE="1")
        env.pop("IPKG_INSTROOT", None)
        p = subprocess.run(["/bin/sh", "-c", wrapper], env=env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.log("prerm.log"), [], "при обновлении prerm не должен ничего удалять")
        # и по одному только аргументу «upgrade» (на случай прямого вызова) тоже
        env2 = dict(self.env, PATH=b)
        env2.pop("PKG_UPGRADE", None)
        p = subprocess.run(["/bin/sh", script, "upgrade", "1.1.0-r1"], env=env2, capture_output=True, text=True)
        self.assertEqual(self.log("prerm.log"), [])

    def test_postinst_removes_opkg_leftover_config(self):
        with open(os.path.join(PKG, "etc", "uci-defaults", "luci-app-podkop-sync"), encoding="utf-8") as f:
            self.assertIn("rm -f /etc/config/podkop_sub-opkg", f.read())


class CronTests(SyncEnv):
    CRON = "etc/crontabs/root"
    FOREIGN = ["13 9 * * * /usr/bin/podkop list_update",
               "*/5 * * * * /usr/bin/python3 /usr/share/vpnprobe/vpnprobe.py run >/dev/null 2>&1 # vpnprobe"]

    def cron(self):
        with open(os.path.join(self.root, self.CRON)) as f:
            return f.read().splitlines()

    def write_cron(self, lines):
        with open(os.path.join(self.root, self.CRON), "w") as f:
            f.write("".join(l + "\n" for l in lines))

    def test_foreign_lines_survive_and_cron_restarts_only_on_change(self):
        self.write_cron(self.FOREIGN)
        self.assertEqual(self.run_svc("update_cron").returncode, 0)
        ours = "0 4 * * * /usr/libexec/podkop_sub_service sync >/dev/null 2>&1 # podkop_sub_sync"
        self.assertEqual(self.cron(), self.FOREIGN + [ours])
        self.assertEqual(self.log("cron.log").count("restart"), 1)
        self.run_svc("update_cron")
        self.run_svc("update_cron")
        self.assertEqual(self.cron(), self.FOREIGN + [ours])
        self.assertEqual(self.log("cron.log").count("restart"), 1, "без изменений cron не перезапускается")
        # podkop при перезапуске переставляет строки: порядок другой, наша строка та же
        self.write_cron([ours] + self.FOREIGN[::-1])
        self.run_svc("update_cron")
        self.assertEqual(self.cron(), [ours] + self.FOREIGN[::-1])
        self.assertEqual(self.log("cron.log").count("restart"), 1, "перестановка чужих строк — не изменение")
        self.set_opt("podkop_sub", "config", "cron", "6")
        self.run_svc("update_cron")
        self.assertEqual(self.cron()[-1].split(" /usr")[0], "0 */6 * * *")
        self.assertEqual(len(self.cron()), 3)
        self.set_opt("podkop_sub", "config", "enabled", "0")
        self.run_svc("update_cron")
        self.assertEqual(sorted(self.cron()), sorted(self.FOREIGN))

    def test_only_our_line_then_disable_leaves_empty_file(self):
        self.run_svc("update_cron")
        self.assertEqual(len(self.cron()), 1)
        self.set_opt("podkop_sub", "config", "cron", "0")
        self.assertEqual(self.run_svc("update_cron").returncode, 0)
        self.assertEqual(self.cron(), [])

    def test_missing_cron_option_defaults_to_daily(self):
        d = self.read_db()
        del d["podkop_sub"]["config"]["cron"]
        self.write_db(d)
        self.run_svc("update_cron")
        self.assertTrue(self.cron()[0].startswith("0 4 * * *"))


if __name__ == "__main__":
    unittest.main()
