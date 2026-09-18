"""Parse subscription content into a normalized node list.

Handles:
  - Clash / Mihomo / Clash Meta YAML  (proxies: ...)
  - base64-encoded YAML
  - line-based subscription feeds where each line is a
    ss:// vmess:// vless:// trojan:// hysteria:// hysteria2:// link
  - plain YAML with a top-level `proxies` key

A single node failing to parse MUST NOT crash the whole run.
"""
from __future__ import annotations

import base64
import json
import logging
import re
import urllib.parse

import yaml

log = logging.getLogger("cfa.parser")

SUPPORTED_TYPES = {
    "ss", "ss2", "vmess", "vless", "trojan", "hysteria", "hysteria2",
    "tuic", "socks", "http",
}

# link schemes -> clash type
SCHEME_MAP = {
    "ss": "ss", "ss://": "ss",
    "vmess": "vmess", "vmess://": "vmess",
    "vless": "vless", "vless://": "vless",
    "trojan": "trojan", "trojan://": "trojan",
    "hysteria": "hysteria", "hysteria://": "hysteria",
    "hysteria2": "hysteria2", "hysteria2://": "hysteria2",
    "tuic": "tuic", "tuic://": "tuic",
    "socks": "socks", "socks5": "socks",
}


def _try_b64_yaml(text: str):
    s = text.strip()
    if not s or len(s) < 40:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=\s]+", s):
        return None
    try:
        decoded = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except Exception:
        return None
    d = decoded.decode("utf-8", "replace")
    # accept only if it actually looks like YAML with proxies
    if "proxies:" in d or "proxy-groups:" in d:
        return d
    return None


def _parse_yaml_proxies(text: str) -> list[dict]:
    try:
        data = yaml.safe_load(text)
    except Exception as e:
        log.debug("yaml parse failed: %s", e)
        return []
    if not isinstance(data, dict):
        return []
    proxies = data.get("proxies")
    if not isinstance(proxies, list):
        return []
    out = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        p = dict(p)
        p.setdefault("type", "unknown")
        p.setdefault("name", p.get("name", ""))
        out.append(p)
    return out


def _extract_params(qs: dict, key: str, default=None):
    v = qs.get(key)
    if v is None and "tag" in qs:
        v = qs.get("tag")
    return v if v is not None else default


def _parse_link(line: str) -> dict | None:
    line = line.strip()
    m = re.match(r"^([a-zA-Z][\w\+.-]+):\/\/(.*)$", line)
    if not m:
        return None
    scheme, rest = m.group(1).lower(), m.group(2)
    ptype = SCHEME_MAP.get(scheme)
    if not ptype:
        return None

    out: dict = {"type": ptype}

    # SS links: scheme:base64info@server:port#tag   or  scheme://base64user:pass@host:port#tag
    if ptype == "ss":
        # rest may contain @server or base64 user:pass@host
        hostport, _, tag = rest.partition("#")
        server = port = method = user = password = None
        if "@" in hostport:
            userinfo, _, hostpart = hostport.partition("@")
            b64 = userinfo
            try:
                raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=False).decode("utf-8", "replace")
                user, _, password = raw.partition(":")
                method = password or "chacha20-ietf-poly1305"
                user = user or "clash"
            except Exception:
                user, _, password = hostport.partition(":")
                method, password = "chacha20-ietf-poly1305", (password or "")
            server, port = _split_hostport(hostpart)
        else:
            server, port = _split_hostport(hostport)
        out.update(server=server, port=port, method=method,
                   password=password or "", cidr=None)
    else:
        # generic: scheme://userinfo@host:port?query
        userinfo = ""
        hostport = rest
        if "@" in rest:
            userinfo, hostport = rest.split("@", 1)
        # vless/vmess query carries params
        sep = "?"
        query = ""
        if sep in hostport:
            hostport, query = hostport.split(sep, 1)
        params = {k: v[0] for k, v in urllib.parse.parse_qsl(query)}
        server, port = _split_hostport(hostport)
        name = params.get("tag") or params.get("name") or (f"{ptype}@{server}")
        out["name"] = name
        out["server"] = server
        out["port"] = port
        if ptype == "vmess":
            uuid = None
            if userinfo:
                uuid = userinfo.split("@")[0] if "@" in userinfo else userinfo
            out["uuid"] = uuid or params.get("id", "")
            out["alterId"] = int(params.get("aid", 0) or 0)
            out["security"] = params.get("security", "auto")
            net = params.get("type", "ws")
            out["network"] = net
            if net == "ws":
                out["ws-headers"] = {"Host": params.get("host", "")}
                path = params.get("path", "")
                if path:
                    out["ws-headers"]["Path"] = path
                sni = params.get("sni", "")
                if sni:
                    out["ws-headers"]["Host"] = sni
        elif ptype == "vless":
            out["uuid"] = params.get("id", "") or (userinfo if userinfo else "")
            out["flow"] = params.get("flow", "")
            out["security"] = "reality" if "pbk" in params else (params.get("security", "tls"))
            if "public" in params:
                out["reality-pub"] = params.get("public", "")
            if "sni" in params:
                out["sni"] = params.get("sni", "")
            net = params.get("type", "grpc") if "type" in params else "tcp"
            out["network"] = net
        elif ptype == "trojan":
            out["password"] = params.get("id", "") or (userinfo or "")
            out["sni"] = params.get("sni", server)
        elif ptype in ("hysteria", "hysteria2"):
            out["password"] = userinfo or params.get("id", "")
            out["sni"] = params.get("sni", server)
            out["authBase64"] = params.get("authBase64", "")
            net = params.get("type", "tcp")
            out["network"] = net
            out["port"] = port
            out["server"] = server
    return out


def _split_hostport(hostport: str):
    """Return (server, port_or_None) from 'host:port' / '[v6]:port' / 'host'."""
    hostport = hostport.strip()
    if not hostport:
        return (None, None)
    if hostport.startswith("["):
        # ipv6
        close = hostport.find("]")
        if close != -1:
            host = hostport[1:close]
            rest = hostport[close + 1:]
            port = rest.lstrip(":")
            port = port if port else None
            try:
                port = int(port) if port else None
            except Exception:
                port = None
            return host, port
        return hostport, None
    if hostport.count(":") == 1:
        h, _, p = hostport.rpartition(":")
        try:
            p = int(p)
        except Exception:
            p = None
        return h, p
    return hostport, None


def parse_subscription(raw: str, source_name: str = "") -> list[dict]:
    """Parse raw subscription text into list of raw node dicts (un-normalized).

    Never raises; returns [] on any fatal parse problem.
    """
    raw = raw or ""
    raw = raw.lstrip("\ufeff")

    # 1) base64 of YAML
    b64 = _try_b64_yaml(raw)
    if b64:
        nodes = _parse_yaml_proxies(b64)
        if nodes:
            for n in nodes:
                n["_source"] = source_name
            return nodes

    # 2) plain YAML
    if raw.lstrip().startswith(("- ", "proxies", "proxy-groups", "mixed-port")) or "\nproxies:" in raw or raw.lstrip().startswith("proxies:"):
        nodes = _parse_yaml_proxies(raw)
        if nodes:
            for n in nodes:
                n["_source"] = source_name
            return nodes
        # maybe it is a JSON array of v2ray json configs
        j = _try_json_list(raw)
        if j:
            for n in j:
                n["_source"] = source_name
            return j

    # 3) JSON array of configs
    j = _try_json_list(raw)
    if j:
        for n in j:
            n["_source"] = source_name
        return j

    # 4) line-based links
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        node = _parse_link(line)
        if node:
            node["_source"] = source_name
            out.append(node)
    return out


def _try_json_list(text: str) -> list[dict]:
    t = text.strip()
    if not (t.startswith("[") or t.startswith("{")):
        return []
    try:
        data = json.loads(t)
    except Exception:
        return []
    items = data if isinstance(data, list) else [data]
    nodes = []
    for it in items:
        if not isinstance(it, dict):
            continue
        n = dict(it)
        if "network" in n and "server" in n:
            pass
        node = _convert_v2ray_json(n)
        if node:
            nodes.append(node)
    return nodes


def _convert_v2ray_json(v: dict) -> dict | None:
    """Convert a v2ray JSON outbounds entry to a clash node dict."""
    proxy = v.get("proxy") or v.get("type")
    servers = v.get("server", [])
    if not servers:
        return None
    s = servers[0] if isinstance(servers, list) else servers
    port = v.get("port") or s.get("port") if isinstance(s, dict) else v.get("port")
    server = s.get("address") if isinstance(s, dict) else s
    if not server or not port:
        return None
    n: dict = {"name": v.get("name") or f"{proxy or 'vmess'}@{server}",
               "server": server, "port": int(port)}
    n["type"] = proxy or v.get("type", "vmess")
    if n["type"] == "vmess":
        n["uuid"] = (s.get("uuid") if isinstance(s, dict) else None) or v.get("uuid", "")
        n["alterId"] = int(s.get("alterId", 0) if isinstance(s, dict) else v.get("alterId", 0) or 0)
        n["security"] = v.get("security", "auto")
        n["network"] = v.get("network", "ws")
    return n


if __name__ == "__main__":
    import sys

    txt = open(sys.argv[1], "rb").read().decode("utf-8", "replace")
    nodes = parse_subscription(txt, "cli")
    print(f"parsed {len(nodes)} nodes")
    for n in nodes[:5]:
        print(n)
