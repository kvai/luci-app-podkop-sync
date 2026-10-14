#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Локальные тесты подкоп-парсера (без сети, без роутера)."""

import base64
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.join(HERE, "..", "luci-app-podkop-sync", "root", "usr", "bin", "podkop_sync.py")

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


# --- ссылка в том виде, как её хранит podkop (все значения вымышленные) ---
REAL = ("vless://11111111-2222-4333-8444-555555555555@node.example.net:443?"
        "encryption=none&flow=xtls-rprx-vision&fp=firefox&"
        "pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&security=reality&"
        "sid=0123456789ab&sni=www.example.com&spx=%2F0123456789abcde&"
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
sub_plain = REAL + "\n" + REAL.replace("node.example.net", "node2.example.net")
sub_b64 = base64.b64encode(sub_plain.encode()).decode()
b64_nodes = ps.parse_input(sub_b64)
check("base64: two nodes decoded", len(b64_nodes) == 2, str(len(b64_nodes)))

# 7) дедупликация одинаковых узлов
dup_nodes = ps.parse_input(REAL + "\n" + REAL)
check("dedup: collapses identical", len(ps.render_links(dup_nodes, True)) == 1)
check("--all: keeps duplicates", len(ps.render_links(dup_nodes, False)) == 2)

# 8) авто-нумерация одинаковых имён
same = [ps.node_from_uri(REAL),
        ps.node_from_uri(REAL.replace("node.example.net", "other.example.net"))]
numbered = ps.render_links(same, deduplicate=True)
check("numbering: appends #1/#2",
      any("%20%231" in l for l in numbered) and any("%20%232" in l for l in numbered),
      str(numbered))

# 9) не-VLESS протоколы молча пропускаются
mixed = "vless://u@h:443?type=tcp#a\nss://xxxx@h:8388#b\ntrojan://p@h:443#c"
check("non-vless skipped", len(ps.parse_input(mixed)) == 1)

# ---------------------------------------------------------------------------
# Чужие данные из подписки: что должно отбрасываться и что не должно ломаться
# ---------------------------------------------------------------------------
import tempfile

BASE = "vless://11111111-2222-4333-8444-555555555555@%s?type=tcp&security=none#%s"

# 10) «:цифры» в имени ноды не принимаются за порт
n = ps.node_from_uri(BASE % ("h.example:443", "node-1.2.3.4:8443"))
check("name with ':digits' keeps host/port",
      n is not None and n["address"] == "h.example" and n["port"] == 443
      and n["raw_remark"] == "node-1.2.3.4:8443", str(n))

# 11) IPv6 (podkop его не понимает и не стартует) — отбрасывается и в URI, и в JSON
check("ipv6 uri dropped", ps.node_from_uri(BASE % ("[2001:db8::1]:443", "v6")) is None)
check("ipv6 bare uri dropped", ps.node_from_uri(BASE % ("2001:db8::1:443", "v6")) is None)
v6json = {"remarks": "v6", "outbounds": [{"protocol": "vless", "settings": {"vnext": [
    {"address": "2001:db8::1", "port": 443, "users": [{"id": "u-1"}]}]}}]}
check("ipv6 json dropped", ps.nodes_from_json(v6json) == [])

# 12) заглушка панели «приложение не поддерживается» — не нода
check("stub 0.0.0.0:1 dropped", ps.node_from_uri(BASE % ("0.0.0.0:1", "stub")) is None)
check("stub 127.0.0.1 dropped", ps.node_from_uri(BASE % ("127.0.0.1:443", "stub")) is None)
check("port 0 dropped", ps.node_from_uri(BASE % ("h.example:0", "x")) is None)
check("port 70000 dropped", ps.node_from_uri(BASE % ("h.example:70000", "x")) is None)

# 13) HTML/пробелы/переводы строк в адресе и идентификаторе не проходят (XSS, порча UCI)
check("html in host dropped", ps.node_from_uri(BASE % ("<img/src=x/onerror=alert(1)>:443", "x")) is None)
check("space in host dropped", ps.node_from_uri(BASE % ("a b:443", "x")) is None)
check("html in uuid dropped",
      ps.node_from_uri("vless://<b>@h.example:443?type=tcp#x") is None)
nljson = {"remarks": "x", "outbounds": [{"protocol": "vless", "settings": {"vnext": [
    {"address": "h.example\nvless://evil@h:443", "port": 443, "users": [{"id": "u-1"}]}]}}]}
check("newline in json address dropped", ps.nodes_from_json(nljson) == [])
badkey = ps.node_from_uri("vless://u-1@h.example:443?type=tcp&foo bar=1&<x>=2&sni=a.example#n")
check("bad param keys dropped, good kept",
      badkey is not None and set(badkey["params"]) >= {"type", "sni"}
      and "foo bar" not in badkey["params"] and "<x>" not in badkey["params"], str(badkey))
# значение параметра с HTML остаётся закодированным и ссылка без пробелов
enc = ps.render_links([ps.node_from_uri("vless://u-1@h.example:443?type=%3Cimg%20src%3Dx%3E#n")])
check("html in param value stays percent-encoded",
      len(enc) == 1 and "<" not in enc[0] and " " not in enc[0], str(enc))
for l in ps.render_links(ps.parse_input(sub_plain)):
    check("no whitespace in rendered link", not any(c.isspace() for c in l))

# 14) файл с BOM: первая нода не теряется
with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as f:
    f.write(b"\xef\xbb\xbf" + (BASE % ("h1.example:443", "a")).encode() + b"\n"
            + (BASE % ("h2.example:443", "b")).encode() + b"\n")
old_argv, old_out = sys.argv, sys.stdout
import io
buf = io.StringIO()
sys.argv, sys.stdout = ["podkop_sync.py", f.name], buf
try:
    ps.main()
finally:
    sys.argv, sys.stdout = old_argv, old_out
os.unlink(f.name)
check("bom: both nodes parsed", buf.getvalue().count("vless://") == 2, buf.getvalue())

# 15) alpn строкой не разваливается на буквы
alpnjson = {"remarks": "t", "outbounds": [{"protocol": "vless", "settings": {"vnext": [
    {"address": "h.example", "port": 443, "users": [{"id": "u-1"}]}]},
    "streamSettings": {"network": "tcp", "security": "tls",
                       "tlsSettings": {"serverName": "a.example", "alpn": "h2"}}}]}
al = ps.render_links(ps.nodes_from_json(alpnjson))
check("alpn string kept", len(al) == 1 and "alpn=h2&" in al[0], str(al))

# 16) повторный разбор собственного вывода ничего не меняет (иначе podkop
#     перезапускался бы при каждой синхронизации)
once = ps.render_links(ps.parse_input(sub_plain))
twice = ps.render_links(ps.parse_input("\n".join(once)))
check("parse(render(x)) is stable", once == twice)

# 17) закрепление SNI/short id у работающих нод
cur_links = ["vless://u-1@h1.example:443?pbk=K1&security=reality&sid=aa&sni=old.example&type=tcp#A",
             "vless://u-1@h2.example:443?pbk=K2&security=reality&sid=bb&sni=old2.example&type=tcp#B"]
fresh = ps.parse_input("vless://u-1@h1.example:443?pbk=K1&security=reality&sid=zz&sni=new.example&type=tcp#A\n"
                       "vless://u-1@h2.example:443?pbk=K2&security=reality&sid=yy&sni=new2.example&type=tcp#B")
kept = ps.apply_sticky(fresh, cur_links, {"main-1-out": True, "main-2-out": False}, "main")
out = ps.render_links(fresh)
check("sticky: working node keeps sni+sid", kept == 1 and "sni=old.example" in out[0] and "sid=aa" in out[0], str(out))
check("sticky: broken node takes fresh", "sni=new2.example" in out[1] and "sid=yy" in out[1], str(out))
fresh2 = ps.parse_input("vless://u-1@h1.example:443?pbk=K1&security=reality&sid=zz&sni=new.example&type=tcp#A")
check("sticky: no health data -> nothing kept", ps.apply_sticky(fresh2, cur_links, None, "main") == 0)
check("sticky: other section tags do not match",
      ps.apply_sticky(fresh2, cur_links, {"main-1-out": True}, "second") == 0)
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as hf:
    hf.write('{"proxies": {"main-1-out": {"history": [{"delay": 120}]}, "main-2-out": {"history": []},'
             ' "main-3-out": {"history": [{"delay": 0}]}, "GLOBAL": {}}}')
h = ps.load_health(hf.name)
os.unlink(hf.name)
check("health: parsed from clash api", h == {"main-1-out": True, "main-2-out": False, "main-3-out": False, "GLOBAL": False}, str(h))
check("health: missing file -> None", ps.load_health("/nonexistent/x.json") is None)

# 18) фильтр транспортов: то, что podkop не умеет, в список не попадает
mixed_tr = ("vless://u-1@h1.example:443?type=tcp&security=none#a\n"
            "vless://u-1@h2.example:443?type=xhttp&security=none&path=%2Fx#b\n"
            "vless://u-1@h3.example:443?type=ws&security=tls&path=%2Fw#c\n"
            "vless://u-1@h4.example:443?security=none#d\n")
with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tf:
    tf.write(mixed_tr)
def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    old = sys.argv, sys.stdout, sys.stderr
    sys.argv, sys.stdout, sys.stderr = ["podkop_sync.py"] + list(argv), out, err
    try:
        ps.main()
    finally:
        sys.argv, sys.stdout, sys.stderr = old
    return out.getvalue(), err.getvalue()
o, e = run_main("--transports", "tcp,raw,ws,grpc", tf.name)
check("transports: xhttp dropped, default tcp kept", o.count("vless://") == 3 and "h2.example" not in o, o)
check("transports: summary line for backend", "Пропущено из-за транспорта: 1 (xhttp: 1)" in e, e)
o, e = run_main("--transports", "tcp,raw,ws,grpc,xhttp,splithttp", tf.name)
check("transports: xhttp kept when allowed", o.count("vless://") == 4 and "Пропущено" not in e, o)
o, e = run_main(tf.name)
check("transports: no filter without the option", o.count("vless://") == 4)
os.unlink(tf.name)

# 19) один сервер, пришедший дважды с разными SNI (отдельно и в «авто»-группе), — одна нода
twice = ("vless://u-1@h1.example:443?pbk=K1&security=reality&sid=s1&sni=aaa.example&type=tcp#Авто\n"
         "vless://u-1@h1.example:443?pbk=K1&security=reality&sid=s2&sni=bbb.example&type=tcp#Польша\n"
         "vless://u-1@h2.example:443?pbk=K2&security=reality&sid=s3&sni=ccc.example&type=tcp#Другая\n")
dd = ps.render_links(ps.parse_input(twice))
check("dedup: same server with different sni is one node", len(dd) == 2 and "h1.example" in dd[0], str(dd))
check("--all keeps both copies", len(ps.render_links(ps.parse_input(twice), deduplicate=False)) == 3)
# закрепление: обе копии получают SNI работающей текущей ноды, список не растёт
cur_one = ["vless://u-1@h1.example:443?pbk=K1&security=reality&sid=s0&sni=old.example&type=tcp#Авто"]
fresh3 = ps.parse_input(twice)
k3 = ps.apply_sticky(fresh3, cur_one, {"main-1-out": True}, "main")
out3 = ps.render_links(fresh3)
check("sticky: copies of one server collapse to the current link",
      len(out3) == 2 and "sni=old.example" in out3[0] and "sid=s0" in out3[0] and k3 == 2, str(out3))
# если в текущем списке уже накопились две копии сервера — следующий разбор сводит их к одной
cur_two = ["vless://u-1@h1.example:443?pbk=K1&security=reality&sid=s0&sni=old.example&type=tcp#Авто",
           "vless://u-1@h1.example:443?pbk=K1&security=reality&sid=s9&sni=zzz.example&type=tcp#Польша"]
fresh4 = ps.parse_input(twice)
ps.apply_sticky(fresh4, cur_two, {"main-1-out": True, "main-2-out": True}, "main")
out4 = ps.render_links(fresh4)
check("sticky: accumulated duplicates heal on next sync", len(out4) == 2 and "h1.example" in out4[0], str(out4))
# и результат устойчив: следующий разбор от уже «вылеченного» списка ничего не меняет
fresh5 = ps.parse_input(twice)
ps.apply_sticky(fresh5, out4, {"main-1-out": True, "main-2-out": True}, "main")
ps.keep_current_order(fresh5, out4)
check("sticky: healed list is a fixed point", ps.render_links(fresh5) == out4, str(ps.render_links(fresh5)))

# 20) порядок: панель перемешала серверы — в podkop они остаются на своих местах;
#     новая нода встаёт за той, за которой шла в подписке
cur_ord = ["vless://u-1@h1.example:443?pbk=K1&security=reality&sid=s0&sni=a.example&type=tcp#Один",
           "vless://u-1@h2.example:443?pbk=K2&security=reality&sid=s0&sni=b.example&type=tcp#Два"]
shuffled = ps.parse_input("vless://u-1@h2.example:443?pbk=K2&security=reality&sid=x&sni=zz.example&type=tcp#Два\n"
                          "vless://u-1@h3.example:443?pbk=K3&security=reality&sid=x&sni=c.example&type=tcp#Три\n"
                          "vless://u-1@h1.example:443?pbk=K1&security=reality&sid=x&sni=yy.example&type=tcp#Один\n")
ps.apply_sticky(shuffled, cur_ord, {"main-1-out": True, "main-2-out": True}, "main")
ps.keep_current_order(shuffled, cur_ord)
o20 = ps.render_links(shuffled)
check("order: current order kept, new node follows its neighbour",
      [l.split("@")[1].split(":")[0] for l in o20] == ["h1.example", "h2.example", "h3.example"], str(o20))
check("order+sticky: unchanged nodes are byte-identical to current",
      o20[:2] == ps.render_links(ps.parse_input("\n".join(cur_ord))), str(o20[:2]))
# 21) sing-box только что запущен: истории нет, но ноды не считаем сломанными
fresh21 = ps.parse_input("vless://u-1@h1.example:443?pbk=K1&security=reality&sid=x&sni=yy.example&type=tcp#Один")
k21 = ps.apply_sticky(fresh21, cur_ord, {}, "main", assume_working=True)
check("assume_working: keeps current values without health data",
      k21 == 1 and "sni=a.example" in ps.render_links(fresh21)[0])

# 22) из копий одного сервера остаётся та, у которой имя уникально, в любом порядке выдачи
auto_first = ("vless://u-1@h1.example:443?pbk=K1&security=reality&sni=a.example&type=tcp#Авто\n"
              "vless://u-1@h2.example:443?pbk=K2&security=reality&sni=b.example&type=tcp#Авто\n"
              "vless://u-1@h1.example:443?pbk=K1&security=reality&sni=c.example&type=tcp#Польша\n")
country_first = "\n".join(reversed(auto_first.strip().split("\n")))
n_a = [ps.unq(l.split("#")[1], plus=False) for l in ps.render_links(ps.parse_input(auto_first))]
n_c = [ps.unq(l.split("#")[1], plus=False) for l in ps.render_links(ps.parse_input(country_first))]
check("dedup: unique name wins over group name", sorted(n_a) == sorted(n_c) == ["Авто", "Польша"], "%s / %s" % (n_a, n_c))
# 23) нода, которая не работала и в прошлый раз, повторно не обновляется
cur23 = ["vless://u-1@h1.example:443?pbk=K1&security=reality&sid=s0&sni=old.example&type=tcp#A"]
def fresh23(): return ps.parse_input("vless://u-1@h1.example:443?pbk=K1&security=reality&sid=zz&sni=new.example&type=tcp#A")
dead = []
f1 = fresh23(); ps.apply_sticky(f1, cur23, {"main-1-out": False, "x": True}, "main", dead_out=dead)
check("dead: first time takes fresh values", "sni=new.example" in ps.render_links(f1)[0] and len(dead) == 1)
f2 = fresh23(); k = ps.apply_sticky(f2, cur23, {"main-1-out": False, "x": True}, "main", frozen=set(dead), dead_out=[])
check("dead: second time keeps current values (no churn)", "sni=old.example" in ps.render_links(f2)[0] and k == 1)
check("dead: key file format matches key_of_link", dead[0] == ps.key_of_link(cur23[0]))

# 24) две копии сервера с одинаково редкими именами: выбор не зависит от порядка
tie = ("vless://u-1@h1.example:443?pbk=K1&security=reality&sni=a.example&type=tcp#Заголовок\n"
       "vless://u-1@h1.example:443?pbk=K1&security=reality&sni=c.example&type=tcp#Швейцария\n")
t1 = ps.render_links(ps.parse_input(tie))[0].split("#")[1]
t2 = ps.render_links(ps.parse_input("\n".join(reversed(tie.strip().split("\n")))))[0].split("#")[1]
check("dedup: tie between equally rare names is order-independent", t1 == t2, "%s / %s" % (t1, t2))

# 25) сервер из одиночного профиля и он же как «приманка» в группе-балансировщике:
#     имя берётся из одиночного профиля, в любом порядке выдачи
def prof(name, hosts):
    return {"remarks": name, "outbounds": [{"protocol": "vless", "settings": {"vnext": [
        {"address": h, "port": 443, "users": [{"id": "u-1"}]}]},
        "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"publicKey": "K" + h, "serverName": "x.example"}}}
        for h in hosts]}
solo, group = prof("Швеция", ["h1.example"]), prof("Турция (БС-4)", ["h1.example", "h9.example"])
for label, data in (("group first", [group, solo]), ("solo first", [solo, group])):
    names = sorted(ps.unq(l.split("#")[1], plus=False) for l in ps.render_links(ps.nodes_from_json(data)))
    check("dedup: single-server profile name wins (%s)" % label, names == ["Турция (БС-4)", "Швеция"]
          and any("h1.example" in l and l.endswith(ps.encode_fragment("Швеция")) for l in ps.render_links(ps.nodes_from_json(data))), str(names))

# 26) имя, которое подписка выдаёт неизменно, применяется даже к работающей ноде
def smp(sni): return ps.parse_input("vless://u-1@h1.example:443?pbk=K1&security=reality&sid=zz&sni=%s&type=tcp#A" % sni)
cons = ps.sni_consensus([smp("api.example"), smp("api.example"), smp("api.example"), smp("api.example")])
check("consensus: same sni in all samples", list(cons.values()) == ["api.example"], str(cons))
check("consensus: differing samples give nothing", ps.sni_consensus([smp("a.example"), smp("b.example"), smp("a.example")]) == {})
check("consensus: too few samples give nothing", ps.sni_consensus([smp("a.example"), smp("a.example")]) == {})
cur26 = ["vless://u-1@h1.example:443?pbk=K1&security=reality&sid=s0&sni=old.example&type=tcp#A"]
f26 = smp("api.example"); sw = []
k26 = ps.apply_sticky(f26, cur26, {"main-1-out": True}, "main", consensus=cons, switched=sw)
check("consensus: working node takes the chosen sni", "sni=api.example" in ps.render_links(f26)[0] and k26 == 0 and len(sw) == 1)
f27 = smp("api.example")
k27 = ps.apply_sticky(f27, ["vless://u-1@h1.example:443?pbk=K1&security=reality&sid=s0&sni=api.example&type=tcp#A"],
                      {"main-1-out": True}, "main", consensus=cons, switched=[])
check("consensus: already on the chosen sni -> stays sticky (short id kept)", k27 == 1 and "sid=s0" in ps.render_links(f27)[0])

print()
# JSON-подписка 3x-ui: «плоская» форма VLESS (адрес, порт и id прямо в settings, без vnext),
# первым идёт профиль-балансировщик со всеми серверами, дальше каждый сервер отдельно.
def _flat(tag, host, sni):
    return {"protocol": "vless", "tag": tag,
            "settings": {"address": host, "port": 443, "id": "11111111-2222-4333-8444-555555555555",
                         "encryption": "none", "flow": "xtls-rprx-vision", "level": 8},
            "streamSettings": {"network": "tcp", "security": "reality",
                               "realitySettings": {"fingerprint": "firefox", "mldsa65Verify": "", "show": False,
                                                   "publicKey": "PBKPBKPBKPBKPBKPBKPBKPBKPBKPBKPBKPBKPBKPBKP",
                                                   "serverName": sni, "shortId": "abcd1234", "spiderX": "/x"},
                               "tcpSettings": {"header": {"type": "none"}}}}

XUI = [
    {"remarks": "Авто | Лучший сервер", "burstObservatory": {}, "routing": {"balancers": [{"tag": "balancer"}]},
     "outbounds": [_flat("bal-1-vless", "se.example.net", "www.example.com"),
                   _flat("bal-1-vless-2", "de.example.net", "api.example.org"),
                   {"protocol": "freedom", "tag": "direct"}]},
    {"remarks": "Швеция", "outbounds": [_flat("proxy", "se.example.net", "www.example.com"),
                                         {"protocol": "freedom", "tag": "direct"}]},
    {"remarks": "Франкфурт", "outbounds": [_flat("proxy", "de.example.net", "api.example.org")]},
]
xui_nodes = ps.nodes_from_json(XUI)
check("3x-ui json: flat vless is parsed", len(xui_nodes) == 4, str(len(xui_nodes)))
xui_links = ps.render_links(xui_nodes)
check("3x-ui json: balancer copies collapse to one link per server", len(xui_links) == 2, str(xui_links))
check("3x-ui json: names come from single-server profiles, not from the balancer",
      any(l.endswith("#" + ps.encode_fragment("Швеция")) for l in xui_links)
      and any(l.endswith("#" + ps.encode_fragment("Франкфурт")) for l in xui_links), str(xui_links))
check("3x-ui json: flow, key, sni and short id survive",
      all("flow=xtls-rprx-vision" in l and "pbk=PBK" in l and "sid=abcd1234" in l and "fp=firefox" in l for l in xui_links)
      and any("sni=www.example.com" in l for l in xui_links), str(xui_links))
check("3x-ui json: garbage in settings does not crash",
      ps.nodes_from_json({"remarks": "x", "outbounds": [{"protocol": "vless", "settings": {"vnext": ["oops"]}},
                                                         {"protocol": "vless", "settings": None},
                                                         {"protocol": "vless", "settings": {"address": "", "id": "x"}}]}) == [])

print("FAILURES:", failures)
sys.exit(1 if failures else 0)
