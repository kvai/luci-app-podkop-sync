#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
podkop_sync.py — универсальный парсер прокси-подписок для podkop (VLESS only).

Вход (stdin или файл):
  * Xray/v2ray JSON config: объект с "outbounds" или массив таких объектов.
  * Base64-подписка: base64 от списка URI (по одному на строку).
  * Plain-список URI: текст со строками vless://...

Выход: готовые vless://...#name ссылки в формате podkop, по одной на строку в stdout.
Диагностика идёт в stderr, чтобы не мешать пайпу.

Зависимости: только стандартная библиотека, доступная в python3-light
(json, base64, sys, argparse, re, collections). urllib НЕ используется —
percent-encoding/decoding реализованы вручную.
"""

import argparse
import base64
import binascii
import json
import re
import sys
from collections import defaultdict

# Незарезервированные символы RFC 3986 — их quote_plus не кодирует.
_UNRESERVED = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~"
)


def q(value):
    """Аналог urllib.parse.quote_plus для значений query-параметров.

    Кодирует всё, кроме незарезервированных символов; пробел -> '+'.
    Совпадает с тем, как значения (spx=/... -> spx=%2F...) хранит podkop.
    """
    s = str(value)
    out = []
    for ch in s:
        if ch == " ":
            out.append("+")
        elif ch in _UNRESERVED:
            out.append(ch)
        else:
            for b in ch.encode("utf-8"):
                out.append("%%%02X" % b)
    return "".join(out)


def unq(value, plus=True):
    """Аналог urllib.parse.unquote(_plus): %XX -> байт.

    plus=True (для query-значений): '+' -> ' '.
    plus=False (для фрагмента #имя): '+' остаётся литеральным.
    """
    if value is None:
        return ""
    s = str(value)
    if plus:
        s = s.replace("+", " ")
    if "%" not in s:
        return s
    out = bytearray()
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "%" and i + 2 < n:
            try:
                out.append(int(s[i + 1:i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        out.extend(c.encode("utf-8"))
        i += 1
    return out.decode("utf-8", "replace")


def encode_fragment(name):
    """Фрагмент (#имя): полный percent-encode UTF-8, литеральны только
    незарезервированные ASCII. Пробел -> %20 (не '+').

    Совпадает с тем, как podkop/панель хранит имена
    (эмодзи-флаги и кириллица кодируются побайтно: 🇱 -> %F0%9F%87%B1).
    """
    out = []
    for ch in name:
        if ch in _UNRESERVED:
            out.append(ch)
        else:
            for b in ch.encode("utf-8"):
                out.append("%%%02X" % b)
    return "".join(out)


def build_query(params):
    """Собрать query-строку из dict с сортировкой ключей по алфавиту."""
    return "&".join("%s=%s" % (k, q(params[k])) for k in sorted(params))


# --------------------------------------------------------------------------
# Промежуточное представление узла
# --------------------------------------------------------------------------
# node = {
#   "uuid": str, "address": str, "port": int|str,
#   "params": {ключ: значение}, "raw_remark": str (декодированное имя)
# }

def _node_signature(node):
    """Что считать «тем же сервером» при удалении дубликатов.

    SNI сюда не входит: панели выдают его случайно из списка, и одна и та же
    нода может прийти дважды с разными SNI (например, отдельной строкой и в
    составе «авто»-группы) — это один сервер, а не два.
    """
    p = node["params"]
    return (
        node["address"],
        str(node["port"]),
        p.get("type", "tcp"),
        p.get("security", "none"),
        p.get("pbk", ""),
        p.get("path", p.get("serviceName", "")),
    )


# --------------------------------------------------------------------------
# Проверка полей ноды
# --------------------------------------------------------------------------
# Содержимое подписки — чужие данные: оно попадает в UCI, в конфиг podkop и в
# таблицу LuCI. Поэтому всё, что не похоже на нормальную ноду, отбрасываем.

_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
_UUID_RE = re.compile(r"^[A-Za-z0-9._~%-]+$")
_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_BAD_CHARS_RE = re.compile(r"[\s\x00-\x1f\x7f]")


def skip(reason, what=""):
    print("Пропущена нода (%s)%s" % (reason, (": " + str(what)[:60]) if what else ""),
          file=sys.stderr)
    return None


def check_endpoint(uuid, address, port):
    """Вернуть (uuid, address, port:int) или None, если нода непригодна."""
    uuid, address = str(uuid or ""), str(address or "")
    if not _UUID_RE.match(uuid):
        return skip("некорректный идентификатор")
    if ":" in address or address.startswith("["):
        # podkop разбирает адрес по первому «:» и на IPv6 не стартует вовсе
        return skip("IPv6-адрес не поддерживается podkop", address)
    if not _HOST_RE.match(address):
        return skip("некорректный адрес", address)
    try:
        port = int(str(port))
    except ValueError:
        return skip("некорректный порт", port)
    if not 1 <= port <= 65535:
        return skip("некорректный порт", port)
    # панели отдают заглушку вида 0.0.0.0:1 «приложение не поддерживается»
    if address == "0.0.0.0" or address.startswith("127.") or port < 2:
        return skip("заглушка, а не нода", "%s:%s" % (address, port))
    return uuid, address, port


# --------------------------------------------------------------------------
# Разбор Xray/v2ray JSON outbound -> node
# --------------------------------------------------------------------------

def node_from_outbound(outbound, raw_remark):
    if outbound.get("protocol") != "vless":
        return None

    vnext = outbound.get("settings", {}).get("vnext", [])
    if not vnext:
        return None
    server = vnext[0]
    address = server.get("address")
    port = server.get("port", 443)
    if not address:
        return None

    user = (server.get("users") or [{}])[0]
    uuid = user.get("id")
    if not uuid:
        return None
    checked = check_endpoint(uuid, address, port)
    if not checked:
        return None
    uuid, address, port = checked

    stream = outbound.get("streamSettings", {})
    network = stream.get("network", "tcp")
    security = stream.get("security", "none")

    params = {
        "type": network,
        "security": security,
        "encryption": user.get("encryption", "none"),
    }
    if user.get("flow"):
        params["flow"] = user["flow"]

    if security == "reality":
        r = stream.get("realitySettings", {})
        if r.get("publicKey"):
            params["pbk"] = r["publicKey"]
        if r.get("serverName"):
            params["sni"] = r["serverName"]
        if r.get("shortId"):
            params["sid"] = r["shortId"]
        params["fp"] = r.get("fingerprint") or "chrome"
        if r.get("spiderX"):
            params["spx"] = r["spiderX"]
    elif security == "tls":
        t = stream.get("tlsSettings", {})
        if t.get("serverName"):
            params["sni"] = t["serverName"]
        params["fp"] = t.get("fingerprint") or "chrome"
        if t.get("alpn"):
            alpn = t["alpn"]
            params["alpn"] = alpn if isinstance(alpn, str) else ",".join(alpn)

    if network == "ws":
        ws = stream.get("wsSettings", {})
        if ws.get("path"):
            params["path"] = ws["path"]
        host = (ws.get("headers") or {}).get("Host")
        if host:
            params["host"] = host
    elif network == "grpc":
        g = stream.get("grpcSettings", {})
        if g.get("serviceName"):
            params["serviceName"] = g["serviceName"]
    elif network == "xhttp":
        x = stream.get("xhttpSettings", {})
        if x.get("mode"):
            params["mode"] = x["mode"]
        if x.get("path"):
            params["path"] = x["path"]
        if x.get("host"):
            params["host"] = x["host"]
        if "extra" in x and x["extra"] not in (None, "", {}):
            params["extra"] = json.dumps(x["extra"], separators=(",", ":"))

    return {
        "uuid": uuid,
        "address": address,
        "port": port,
        "params": params,
        "raw_remark": (raw_remark or "Server").strip(),
    }


def nodes_from_json(data):
    if isinstance(data, dict) and "outbounds" in data:
        items = [data]
    elif isinstance(data, list):
        items = data
    else:
        items = []

    nodes = []
    for item in items:
        if not isinstance(item, dict):
            continue
        remark = item.get("remarks", "Server")
        found = []
        for ob in item.get("outbounds", []) or []:
            node = node_from_outbound(ob, remark)
            if node:
                found.append(node)
        # Профиль с несколькими серверами — это группа (автовыбор, балансировщик):
        # его название относится к группе, а не к каждому серверу в ней.
        for node in found:
            node["group_size"] = len(found)
        nodes.extend(found)
    return nodes


# --------------------------------------------------------------------------
# Разбор готовой vless:// ссылки -> node
# --------------------------------------------------------------------------

def node_from_uri(uri):
    uri = uri.strip()
    if not uri.lower().startswith("vless://"):
        return None
    # Сначала отрезаем #имя и ?параметры, и только потом делим host:port —
    # иначе «:цифры» в имени (node-1.2.3.4:8443) принимались за порт.
    body, _, frag = uri[len("vless://"):].partition("#")
    body, _, query = body.partition("?")
    uuid, at, hostport = body.rpartition("@")
    if not at:
        return None
    host, colon, port = hostport.rstrip("/").rpartition(":")
    if not colon:
        return None
    checked = check_endpoint(uuid, host, port)
    if not checked:
        return None
    uuid, host, port = checked

    params = {}
    for pair in query.split("&"):
        if not pair:
            continue
        if "=" in pair:
            k, v = pair.split("=", 1)
        else:
            k, v = pair, ""
        if not _KEY_RE.match(k):
            continue
        params[k] = unq(v)

    params.setdefault("type", "tcp")
    params.setdefault("security", "none")
    params.setdefault("encryption", "none")
    if params["security"] in ("reality", "tls") and not params.get("fp"):
        params["fp"] = "chrome"

    frag = unq(frag, plus=False).strip()
    return {
        "uuid": uuid,
        "address": host,
        "port": port,
        "params": params,
        "raw_remark": frag or "Server",
    }


def nodes_from_uri_list(text):
    nodes = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("vless://"):
            node = node_from_uri(line)
            if node:
                nodes.append(node)
    return nodes


# --------------------------------------------------------------------------
# Авто-детект формата входных данных
# --------------------------------------------------------------------------

def _try_base64(text):
    """Вернуть декодированный текст, если это похоже на base64-подписку, иначе None."""
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 8:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return None
    # поддержка url-safe алфавита
    compact = compact.replace("-", "+").replace("_", "/")
    pad = (-len(compact)) % 4
    compact += "=" * pad
    try:
        decoded = base64.b64decode(compact).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None
    if "://" in decoded:
        return decoded
    return None


def parse_input(text):
    """Определить формат и вернуть список узлов."""
    stripped = text.strip()
    if not stripped:
        return []

    # 1) JSON
    if stripped[0] in "{[":
        try:
            return nodes_from_json(json.loads(stripped))
        except (ValueError, TypeError) as e:
            print("Не удалось разобрать как JSON: %s" % e, file=sys.stderr)

    # 2) уже готовые vless:// ссылки в открытом виде
    if "vless://" in stripped:
        return nodes_from_uri_list(stripped)

    # 3) base64-подписка
    decoded = _try_base64(stripped)
    if decoded is not None:
        return nodes_from_uri_list(decoded)

    return []


# --------------------------------------------------------------------------
# Закрепление SNI и short id у работающих нод
# --------------------------------------------------------------------------
# Панели (3x-ui) при каждом скачивании подписки выдают случайные SNI и short id
# из списков, заданных на ноде. Без закрепления ссылки «меняются» при каждой
# синхронизации, а очередное случайное имя может оказаться заблокированным.
# Правило: если такая же нода уже стоит в podkop И сейчас работает — оставляем
# её SNI и short id. Не работает или данных о здоровье нет — берём свежие из
# подписки (так лечится и случай «на сервере убрали имя, нода встала»).

STICKY_FIELDS = ("sni", "sid")


def sticky_key(node):
    """Всё, что определяет ноду, кроме закрепляемых полей и имени."""
    p = node["params"]
    return (node["uuid"], node["address"], str(node["port"]),
            tuple(sorted((k, v) for k, v in p.items() if k not in STICKY_FIELDS)))


def load_health(path):
    """Ответ Clash API sing-box (/proxies) -> {тег: работает ли}. None, если данных нет.

    sing-box хранит историю проверок urltest; после неудачной проверки запись
    удаляется, поэтому «работает» = есть запись с задержкой больше нуля.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            proxies = json.load(f)["proxies"]
        health = {}
        for tag, info in proxies.items():
            hist = info.get("history") or []
            health[tag] = bool(hist) and (hist[-1].get("delay") or 0) > 0
        return health
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


def keep_current_order(nodes, current_links):
    """Расставить ноды в том порядке, в каком они уже стоят в podkop.

    Некоторые панели при каждом скачивании перемешивают серверы. Без этого список
    в podkop переписывался бы при каждой синхронизации, а нумерация одноимённых
    нод (#1, #2) прыгала бы. Новая нода (или нода, у которой сменился адрес/ключ)
    встаёт сразу после той, за которой она шла в подписке.
    """
    position = {}
    for i, link in enumerate(current_links):
        cur = node_from_uri(link)
        if cur:
            position.setdefault(sticky_key(cur), i)
    place, last = {}, -1.0
    for n in nodes:
        pos = position.get(sticky_key(n))
        if pos is None:
            pos = last + 0.5        # новая: держится за своей соседкой по подписке
        else:
            last = float(pos)
        place[id(n)] = pos
    # сортировка устойчивая: ноды с одинаковым местом сохраняют взаимный порядок
    nodes.sort(key=lambda n: place[id(n)])


def key_of_link(link):
    """Ключ ноды по ссылке, строкой (для файлов состояния); None для негодной ссылки."""
    node = node_from_uri(link)
    return repr(sticky_key(node)) if node else None


def sni_consensus(samples):
    """По нескольким скачиваниям одной подписки: {ключ ноды: SNI}, если во ВСЕХ
    скачиваниях нода пришла с одним и тем же SNI.

    Панель выдаёт SNI случайно из списка ноды. Если несколько скачиваний подряд
    дали одно имя — в списке (почти наверняка) только оно, то есть владелец
    сервера выбрал именно его. Такое имя нужно применять, даже если прежнее
    ещё работает.
    """
    if len(samples) < 3:
        return {}
    seen = defaultdict(list)
    for sample in samples:
        got = {}
        for node in sample:
            got.setdefault(repr(sticky_key(node)), set()).add(node["params"].get("sni", ""))
        for key, snis in got.items():
            seen[key].append(snis)
    out = {}
    for key, per_sample in seen.items():
        if len(per_sample) == len(samples) and all(len(x) == 1 for x in per_sample):
            names = set().union(*per_sample)
            if len(names) == 1:
                out[key] = next(iter(names))
    return out


def apply_sticky(nodes, current_links, health, section, assume_working=False,
                 frozen=None, dead_out=None, retry_own=False, consensus=None, switched=None):
    """Вернуть число нод, которым оставлены прежние SNI/short id (nodes правится на месте).

    assume_working: данных о здоровье ещё нет (sing-box только что запущен) —
    считаем все текущие ноды работающими, чтобы не менять их вслепую.
    frozen: ключи нод, которые не работали и в прошлый раз, хотя им уже выдавали
    свежие значения. Повторно их не трогаем: иначе нода, которая просто лежит,
    получала бы новый случайный SNI при каждой синхронизации, и список менялся
    бы вечно. Новая попытка — по кнопке в интерфейсе.
    dead_out: сюда (если передан список) кладутся ключи неработающих сейчас нод.
    consensus: {ключ: SNI}, которые подписка выдаёт неизменно (см. sni_consensus).
    Если у текущей ноды SNI другой — берём новый, даже если нода работает или
    «заморожена». switched (список) получает ключи таких нод.
    retry_own: человек нажал «обновить»: «своим» неработающим нодам (первая
    подписка) даём свежие значения ещё раз. Ноды дополнительных подписок по
    кнопке не трогаем — иначе чужие лежащие серверы вызывали бы перезапуск при
    каждом нажатии.
    """
    if not health and not assume_working:
        return 0
    health = health or {}
    frozen = frozen or set()
    consensus = consensus or {}
    own = set(repr(sticky_key(n)) for n in nodes if n.get("source", 1) <= 1)
    present = set(repr(sticky_key(n)) for n in nodes)
    working = defaultdict(list)     # ключ ноды -> работающие текущие ноды с таким ключом
    for i, link in enumerate(current_links, 1):
        # podkop называет выходы <секция>-<номер ссылки>-out
        cur = node_from_uri(link)
        if not cur:
            continue
        wanted = consensus.get(repr(sticky_key(cur)))
        if wanted is not None and wanted != cur["params"].get("sni", ""):
            # подписка неизменно выдаёт другое имя — закреплять старое нельзя
            if switched is not None:
                switched.append(repr(sticky_key(cur)))
            continue
        if not assume_working and not health.get("%s-%d-out" % (section, i)):
            key_text = repr(sticky_key(cur))
            # ноду, которой в новом наборе уже нет (подписку убрали), неработающей не считаем
            if dead_out is not None and key_text in present:
                dead_out.append(key_text)
            if key_text not in frozen or (retry_own and key_text in own):
                continue            # не работает впервые (или просят повторить) — свежие значения
        working[sticky_key(cur)].append(cur)
    taken, kept = defaultdict(int), 0
    for node in nodes:
        key = sticky_key(node)
        if key not in working:
            continue
        # Обычно текущая нода с таким ключом одна. Если тот же сервер пришёл в
        # подписке несколько раз, все копии получают ОДНИ И ТЕ ЖЕ значения —
        # иначе копии с разными SNI считались бы разными нодами и список рос бы.
        # Несколько текущих нод с одним ключом (сервер намеренно записан дважды
        # с разными SNI) раздаются по порядку.
        cur = working[key][min(taken[key], len(working[key]) - 1)]
        taken[key] += 1
        for field in STICKY_FIELDS:
            if field in cur["params"]:
                node["params"][field] = cur["params"][field]
            else:
                node["params"].pop(field, None)
        kept += 1
    return kept


# --------------------------------------------------------------------------
# Дедуп, нумерация, генерация ссылок
# --------------------------------------------------------------------------

def render_links(nodes, deduplicate=True, origins=None):
    """origins — список, в который (если передан) кладутся номера источников
    для каждой выданной ссылки, в том же порядке."""
    if deduplicate:
        # Из копий одного сервера оставляем одну — на месте первой. Какую именно,
        # не должно зависеть от порядка выдачи, иначе имя прыгало бы между
        # скачиваниями. Предпочтение, по убыванию важности:
        #   1) копия из профиля, где этот сервер один (там имя — имя сервера, а не
        #      группы вроде «Авто | Лучший сервер» или балансировщика с «приманкой»);
        #   2) копия с именем, которое встречается реже;
        #   3) при прочих равных — по самому имени.
        freq = defaultdict(int)
        for node in nodes:
            freq[node["raw_remark"]] += 1
        best, order = {}, []
        for node in nodes:
            sig = _node_signature(node)
            if sig not in best:
                best[sig] = node
                order.append(sig)
            else:
                # при равной редкости выбор тоже не должен зависеть от порядка выдачи
                old = best[sig]
                a, b = node["raw_remark"], old["raw_remark"]
                if (node.get("group_size", 1), freq[a], b) < (old.get("group_size", 1), freq[b], a):
                    best[sig] = node
        nodes = [best[sig] for sig in order]

    counts = defaultdict(int)
    for node in nodes:
        counts[node["raw_remark"]] += 1

    idx = defaultdict(int)
    links = []
    for node in nodes:
        name = node["raw_remark"]
        idx[name] += 1
        if counts[name] > 1:
            name = "%s #%d" % (name, idx[name])
        query = build_query(node["params"])
        frag = encode_fragment(name)
        link = "vless://%s@%s:%s?%s#%s" % (
            node["uuid"], node["address"], node["port"], query, frag)
        # последний рубеж: в ссылке не должно быть пробелов и управляющих символов
        if _BAD_CHARS_RE.search(link):
            skip("недопустимые символы в ссылке")
            continue
        links.append(link)
        if origins is not None:
            origins.append(node.get("source", 0))
    return links


# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Парсер VLESS-подписок (JSON/Base64/URI) -> vless:// ссылки для podkop"
    )
    ap.add_argument("files", nargs="*", default=None,
                    help="Файлы подписок (каждый парсится как отдельный "
                         "источник со своим форматом; без аргументов — stdin)")
    ap.add_argument("--all", action="store_true",
                    help="Не удалять дубликаты (сохранить все ноды)")
    ap.add_argument("--transports", metavar="LIST",
                    help="Транспорты (type=…), которые понимает установленный podkop, "
                         "через запятую. Ноды с другими транспортами отбрасываются: "
                         "podkop на них не стартует и роняет всю сеть")
    ap.add_argument("--origins", metavar="FILE",
                    help="Записать сюда «номер подписки<TAB>ссылка» для каждой выданной "
                         "ноды (номер = порядковый номер файла в аргументах, с 1)")
    ap.add_argument("--stick", metavar="FILE",
                    help="Файл с текущими ссылками секции podkop: у работающих "
                         "нод сохранить прежние SNI и short id")
    ap.add_argument("--health", metavar="FILE",
                    help="Сохранённый ответ Clash API sing-box (/proxies)")
    ap.add_argument("--frozen", metavar="FILE",
                    help="Файл с ключами нод, которые не работали и в прошлый раз: "
                         "их значения повторно не обновляются")
    ap.add_argument("--dead-out", metavar="FILE",
                    help="Записать сюда ключи нод, которые сейчас не работают")
    ap.add_argument("--sample", metavar="FILE", action="append", default=[],
                    help="Ещё одно скачивание ПЕРВОЙ подписки (можно несколько раз): если все "
                         "скачивания дают ноде один и тот же SNI, он применяется сразу")
    ap.add_argument("--retry-own", action="store_true",
                    help="Неработающим нодам первой подписки выдать свежие значения ещё раз")
    ap.add_argument("--assume-working", action="store_true",
                    help="Считать все текущие ноды работающими (sing-box только что "
                         "запущен и ещё не успел их проверить)")
    ap.add_argument("--section", default="main",
                    help="Имя секции podkop (для тегов выходов sing-box)")
    args = ap.parse_args()

    # Каждый источник (файл) детектится и парсится отдельно — форматы могут
    # различаться (base64 / JSON / plain). Дедуп и нумерация — глобально.
    nodes = []
    try:
        if args.files:
            for index, path in enumerate(args.files, 1):
                # utf-8-sig: BOM в начале файла не должен «съедать» первую ноду
                with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
                    parsed = parse_input(f.read())
                for node in parsed:
                    node["source"] = index
                nodes.extend(parsed)
        else:
            nodes.extend(parse_input(sys.stdin.read()))
    except OSError as e:
        print("Ошибка чтения входных данных: %s" % e, file=sys.stderr)
        return 1

    if args.transports:
        allowed = set(t.strip() for t in args.transports.split(",") if t.strip())
        kept_nodes, dropped = [], defaultdict(int)
        for node in nodes:
            transport = node["params"].get("type", "tcp")
            if transport in allowed:
                kept_nodes.append(node)
            else:
                dropped[transport] += 1
        nodes = kept_nodes
        if dropped:
            # одна строка для бэкенда: он покажет её в статусе
            print("Пропущено из-за транспорта: %d (%s)" % (
                sum(dropped.values()),
                ", ".join("%s: %d" % (k, v) for k, v in sorted(dropped.items()))), file=sys.stderr)

    if args.stick:
        try:
            with open(args.stick, "r", encoding="utf-8") as f:
                current = [l.strip() for l in f if l.strip()]
        except OSError:
            current = []
        frozen = set()
        if args.frozen:
            try:
                with open(args.frozen, "r", encoding="utf-8") as f:
                    frozen = set(l.rstrip("\n") for l in f if l.strip())
            except OSError:
                pass
        dead = [] if args.dead_out else None
        samples = [[n for n in nodes if n.get("source") == 1]]
        for path in args.sample:
            try:
                with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
                    samples.append(parse_input(f.read()))
            except OSError:
                pass
        switched = []
        kept = apply_sticky(nodes, current, load_health(args.health or ""), args.section,
                            assume_working=args.assume_working, frozen=frozen, dead_out=dead,
                            retry_own=args.retry_own, consensus=sni_consensus(samples),
                            switched=switched)
        if switched:
            print("Принято новых SNI: %d" % len(set(switched)), file=sys.stderr)
        if args.dead_out:
            try:
                with open(args.dead_out, "w", encoding="utf-8") as f:
                    for k in sorted(set(dead)):
                        f.write(k + "\n")
            except OSError as e:
                print("Не удалось записать список неработающих нод: %s" % e, file=sys.stderr)
        keep_current_order(nodes, current)
        print("Закреплено нод: %d" % kept, file=sys.stderr)

    origins = [] if args.origins else None
    links = render_links(nodes, deduplicate=not args.all, origins=origins)
    if args.origins:
        try:
            with open(args.origins, "w", encoding="utf-8") as f:
                for src, link in zip(origins, links):
                    f.write("%d\t%s\n" % (src, link))
        except OSError as e:
            print("Не удалось записать источники нод: %s" % e, file=sys.stderr)

    for link in links:
        sys.stdout.write(link + "\n")

    print("Распознано нод: %d%s"
          % (len(links), "" if not args.all else " (дедуп отключён)"),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
