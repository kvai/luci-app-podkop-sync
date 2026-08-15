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
(json, base64, sys, os, argparse, re, collections). urllib НЕ используется —
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
    p = node["params"]
    return (
        node["address"],
        str(node["port"]),
        p.get("type", "tcp"),
        p.get("security", "none"),
        p.get("pbk", ""),
        p.get("sni", ""),
        p.get("path", p.get("serviceName", "")),
    )


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
            params["alpn"] = ",".join(t["alpn"])

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
        for ob in item.get("outbounds", []):
            node = node_from_outbound(ob, remark)
            if node:
                nodes.append(node)
    return nodes


# --------------------------------------------------------------------------
# Разбор готовой vless:// ссылки -> node
# --------------------------------------------------------------------------

_VLESS_RE = re.compile(
    r"^vless://"
    r"(?P<uuid>[^@]+)@"
    r"(?P<host>.+):(?P<port>\d+)"
    r"(?:\?(?P<query>[^#]*))?"
    r"(?:#(?P<frag>.*))?$",
    re.IGNORECASE,
)


def node_from_uri(uri):
    m = _VLESS_RE.match(uri.strip())
    if not m:
        return None

    params = {}
    query = m.group("query") or ""
    for pair in query.split("&"):
        if not pair:
            continue
        if "=" in pair:
            k, v = pair.split("=", 1)
        else:
            k, v = pair, ""
        params[k] = unq(v)

    params.setdefault("type", "tcp")
    params.setdefault("security", "none")
    params.setdefault("encryption", "none")
    if params["security"] in ("reality", "tls") and not params.get("fp"):
        params["fp"] = "chrome"

    frag = unq(m.group("frag") or "", plus=False).strip()
    return {
        "uuid": m.group("uuid"),
        "address": m.group("host"),
        "port": m.group("port"),
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
# Дедуп, нумерация, генерация ссылок
# --------------------------------------------------------------------------

def render_links(nodes, deduplicate=True):
    if deduplicate:
        seen = set()
        unique = []
        for node in nodes:
            sig = _node_signature(node)
            if sig in seen:
                continue
            seen.add(sig)
            unique.append(node)
        nodes = unique

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
        links.append(
            "vless://%s@%s:%s?%s#%s"
            % (node["uuid"], node["address"], node["port"], query, frag)
        )
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
    args = ap.parse_args()

    # Каждый источник (файл) детектится и парсится отдельно — форматы могут
    # различаться (base64 / JSON / plain). Дедуп и нумерация — глобально.
    nodes = []
    try:
        if args.files:
            for path in args.files:
                with open(path, "r", encoding="utf-8") as f:
                    nodes.extend(parse_input(f.read()))
        else:
            nodes.extend(parse_input(sys.stdin.read()))
    except OSError as e:
        print("Ошибка чтения входных данных: %s" % e, file=sys.stderr)
        return 1

    links = render_links(nodes, deduplicate=not args.all)

    for link in links:
        sys.stdout.write(link + "\n")

    print("Распознано нод: %d%s"
          % (len(links), "" if not args.all else " (дедуп отключён)"),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
