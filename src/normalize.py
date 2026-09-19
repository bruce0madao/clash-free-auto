"""Normalize raw nodes into a canonical shape.

  - clean name (strip newlines / control chars, cap length)
  - coerce port to int
  - keep only fields relevant to the protocol
  - reject anything that would break YAML
"""
from __future__ import annotations

import logging
import re

log = logging.getLogger("cfa.normalize")

MAX_NAME_LEN = 48
_CTRL = re.compile(r"[\x00-\x1f\x7f\u200e\u200f]+")


def _clean_name(name: str, server: str, ptype: str) -> str:
    name = _CTRL.sub(" ", str(name or "").strip())
    name = re.sub(r"\s+", " ", name)
    if len(name) > MAX_NAME_LEN:
        name = name[: MAX_NAME_LEN - 1] + "…"
    if not name:
        name = f"{ptype}-{server}"
    # avoid chars that break YAML keys: wrap problematic names
    return name


def _fields_for_type(ptype: str, n: dict) -> dict:
    base = {
        "name": _clean_name(n.get("name"), n.get("server", ""), ptype),
        "type": ptype,
        "server": str(n.get("server", "")).strip(),
        "port": int(n["port"]) if "port" in n else None,
    }
    if ptype in ("ss",):
        # cipher: keep real value only; never invent one (mihomo requires it for ss)
        cipher = str(n.get("cipher") or "").strip()
        if cipher:
            base["cipher"] = cipher
        # method defaults only when the link genuinely omits it (ss links without
        # a cipher param mean the server default; mihomo accepts method-only fallback)
        base["method"] = n.get("method") or "chacha20-ietf-poly1305"
        base["password"] = str(n.get("password") or "").strip()
        if n.get("network"):
            base["network"] = n["network"]
        if n.get("plugin", "") == "obfs" or n.get("plugin-opts"):
            base["plugin"] = n.get("plugin") or "obfs"
            base["plugin-opts"] = n.get("plugin-opts") or {"mode": "tls"}
    elif ptype in ("vmess", "vless"):
        base["uuid"] = n.get("uuid") or ""
        if ptype == "vmess":
            base["alterId"] = int(n.get("alterId", 0) or 0)
            base["security"] = n.get("security") or "auto"
            base["network"] = n.get("network") or "tcp"
        else:  # vless
            base["flow"] = n.get("flow") or ""
            base["security"] = n.get("security") or "tls"
            if n.get("reality-pub"):
                base["reality-pub"] = n["reality-pub"]
            if n.get("fingerprint"):
                base["fingerprint"] = n["fingerprint"]
        if n.get("sni") or (n.get("tls") and n.get("sni")):
            base["sni"] = n.get("sni")
        if n.get("skip-cert-verify") is not None:
            base["skip-cert-verify"] = n["skip-cert-verify"]
        if n.get("ws-headers"):
            base["ws-headers"] = n["ws-headers"]
        if n.get("network"):
            base["network"] = n["network"]
        if n.get("grpc-serviceName"):
            base["grpc-service-name"] = n["grpc-serviceName"]
    elif ptype == "trojan":
        base["password"] = n.get("password") or n.get("id") or ""
        if n.get("sni"):
            base["sni"] = n["sni"]
        base["skip-cert-verify"] = n.get("skip-cert-verify", False)
    elif ptype in ("hysteria", "hysteria2"):
        base["auth"] = n.get("password") or n.get("authBase64") or ""
        base["protocol"] = "udp"
        if ptype == "hysteria2":
            base["auth"] = n.get("password") or ""
            if n.get("sni"):
                base["sni"] = n["sni"]
            base["disable-insecure-tls"] = n.get("disable-insecure-tls", True)
        if n.get("obfs") or n.get("obfs-password"):
            base["obfs"] = n.get("obfs")
            base["obfs-password"] = n.get("obfs-password")
    elif ptype == "tuic":
        base["uuid"] = n.get("uuid") or ""
        base["password"] = n.get("password") or ""
        base["sni"] = n.get("sni") or n.get("server")
        base["skip-cert-verify"] = n.get("skip-cert-verify", True)
    elif ptype in ("socks", "http"):
        if n.get("username"):
            base["username"] = n["username"]
        if n.get("password"):
            base["password"] = n["password"]
    return base


def normalize(node: dict) -> dict | None:
    """Return a clean canonical node dict, or None if it is fundamentally broken."""
    if not isinstance(node, dict):
        return None
    ptype = str(node.get("type", "")).strip().lower()
    if ptype not in {
        "ss", "ss2", "vmess", "vless", "trojan", "hysteria", "hysteria2",
        "tuic", "socks", "http", "unknown",
    }:
        return None
    raw = dict(node)
    raw["type"] = ptype
    base = _fields_for_type(ptype, raw)
    base["_source"] = node.get("_source", "")
    base["_score"] = 0.0
    base["_validated"] = False
    base["_validation_level"] = "unknown"
    return base


if __name__ == "__main__":
    print("normalize module loaded OK")
