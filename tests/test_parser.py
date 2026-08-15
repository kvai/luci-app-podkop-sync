#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Локальные тесты подкоп-парсера (без сети, без роутера)."""

import base64
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.join(HERE, "..", "root", "usr", "bin", "podkop_sync.py")

spec = importlib.util.spec_from_file_location("podkop_sync", MOD)
ps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ps)

failures = 0


def check(name, cond, detail=""):
    global failures
    status = "OK  " if cond else "FAIL"
    if not cond:
        failures += 1
    print("[%s] %s %s" % (status, name, ("- " + detail) if detail else ""))


# --- реальная нода из /etc/config/podkop пользователя ---
REAL = ("vless://11111111-2222-4333-8444-555555555555@domain.net:443?"
        "encryption=none&flow=xtls-rprx-vision&fp=firefox&"
        "pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&security=reality&"
        "sid=0123456789ab&sni=timeline.www.cloudflare.com&spx=%2F0123456789abcde&"
        "type=tcp#%F0%9F%87%B1%F0%9F%87%B9%20%D0%9B%D0%B8%D1%82%D0%B2%D0%B0-home-router")

# 1) round-trip готовой ссылки: разобрали -> собрали -> должно совпасть байт-в-байт
node = ps.node_from_uri(REAL)
check("uri parse: not None", node is not None)
roundtrip = ps.render_links([node], deduplicate=True)[0]
check("uri round-trip byte-identical", roundtrip == REAL,
      "\n    got: %s\n    exp: %s" % (roundtrip, REAL))

# 2) q() совпадает с ожидаемым кодированием spx
check("q(): slash -> %2F", ps.q("/0123456789abcde") == "%2F0123456789abcde")
check("q(): keeps unreserved", ps.q("xtls-rprx-vision") == "xtls-rprx-vision")

# 3) фрагмент: полный percent-encode UTF-8 (как в реальном конфиге podkop)
check("fragment: full utf-8 percent-encode",
      ps.encode_fragment("Литва тест")
      == "%D0%9B%D0%B8%D1%82%D0%B2%D0%B0%20%D1%82%D0%B5%D1%81%D1%82")
check("fragment: keeps ascii unreserved",
      ps.encode_fragment("home-router") == "home-router")

# 4) JSON (Xray) -> VLESS REALITY
XRAY = {
    "remarks": "🇵🇱⚡Польша",
    "outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": "pl.example.com", "port": 443,
            "users": [{"id": "uuid-123", "flow": "xtls-rprx-vision", "encryption": "none"}]
        }]},
        "streamSettings": {
            "network": "tcp", "security": "reality",
            "realitySettings": {
                "publicKey": "PUBKEY", "serverName": "www.cloudflare.com",
                "shortId": "abc123", "fingerprint": "firefox", "spiderX": "/path"
            }
        }
    }]
}
links = ps.render_links(ps.nodes_from_json(XRAY))
check("json: one link", len(links) == 1, str(links))
check("json: reality params present",
      len(links) == 1 and "security=reality" in links[0]
      and "pbk=PUBKEY" in links[0] and "spx=%2Fpath" in links[0], str(links))
check("json: fingerprint preserved", len(links) == 1 and "fp=firefox" in links[0])

# 5) fallback fp=chrome при TLS без fingerprint
XRAY_TLS = {
    "remarks": "ws-node",
    "outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "h", "port": 443, "users": [{"id": "u"}]}]},
        "streamSettings": {
            "network": "ws", "security": "tls",
            "tlsSettings": {"serverName": "h"},
            "wsSettings": {"path": "/ws", "headers": {"Host": "h"}}
        }
    }]
}
tls_links = ps.render_links(ps.nodes_from_json(XRAY_TLS))
check("tls: fallback fp=chrome", "fp=chrome" in tls_links[0], str(tls_links))
check("ws: path encoded", "path=%2Fws" in tls_links[0], str(tls_links))

# 6) base64-подписка
sub_plain = REAL + "\n" + REAL.replace("domain.net", "domain2.net")
sub_b64 = base64.b64encode(sub_plain.encode()).decode()
b64_nodes = ps.parse_input(sub_b64)
check("base64: two nodes decoded", len(b64_nodes) == 2, str(len(b64_nodes)))

# 7) дедупликация одинаковых узлов
dup_nodes = ps.parse_input(REAL + "\n" + REAL)
check("dedup: collapses identical", len(ps.render_links(dup_nodes, True)) == 1)
check("--all: keeps duplicates", len(ps.render_links(dup_nodes, False)) == 2)

# 8) авто-нумерация одинаковых имён
same = [ps.node_from_uri(REAL),
        ps.node_from_uri(REAL.replace("domain.net", "other.net"))]
numbered = ps.render_links(same, deduplicate=True)
check("numbering: appends #1/#2",
      any("%20%231" in l for l in numbered) and any("%20%232" in l for l in numbered),
      str(numbered))

# 9) не-VLESS протоколы молча пропускаются
mixed = "vless://u@h:443?type=tcp#a\nss://xxxx@h:8388#b\ntrojan://p@h:443#c"
check("non-vless skipped", len(ps.parse_input(mixed)) == 1)

print()
print("FAILURES:", failures)
sys.exit(1 if failures else 0)
