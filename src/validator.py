"""Lightweight node validator.

Per spec we MUST NOT pretend a node is "available" when we cannot
actually confirm a real handshake. In a GitHub Actions sandbox we can:
  - basic: only structural checks (always safe)
  - tcp:   try a TCP connect to server:port with a short timeout

We cap how many nodes we TCP-probe per run so a single hung run cannot
wedge the Actions job. The record-kept level (`tcp` / `basic`) is used
by scoring; we never mark a node validated beyond what we actually confirmed.
"""
from __future__ import annotations

import logging
import re
import socket

log = logging.getLogger("cfa.validator")

TCP_TIMEOUT = 3
MAX_TCP_PROBES = 200   # cap on how many nodes get a real TCP probe
PARALLEL_WORKERS = 10


def _tcp_probe(server: str, port: int, timeout: int = TCP_TIMEOUT) -> bool:
    try:
        with socket.create_connection((server, port), timeout=timeout):
            return True
    except Exception:
        return False


SS_CIPHERS = {
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr",
    "aes-256-ctr", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "camellia-128-cfb",
    "camellia-192-cfb", "camellia-256-cfb", "chacha20", "chacha20-poly1305",
    "chacha20-ietf", "chacha20-ietf-poly1305", "xchacha20", "xchacha20-ietf",
}

# mihomo requires cipher on ss proxies; keep in sync with _structural_ok below
SS_REQUIRED = ("cipher", "password", "server", "port")
VMESS_REQUIRED = ("uuid", "server", "port")
VLESS_REQUIRED = ("uuid", "server", "port")
TROJAN_REQUIRED = ("password", "server", "port")
HYSTERA_REQUIRED = ("auth", "server", "port")
TUIC_REQUIRED = ("uuid", "server", "port")
SOCKS_REQUIRED = ("server", "port")
HTTP_REQUIRED = ("server", "port")

_NAME_BAD = re.compile(r"^[\s:;,]+" )  # names made only of whitespace/punctuation


def schema_ok(n: dict) -> tuple[bool, str]:
    """Strict per-protocol schema check. Returns (ok, reason).

    No auto-filling: a missing required field means the node is dropped.
    """
    ptype = str(n.get("type", "")).strip().lower()

    # name sanity: must exist, non-trivial (not just "O:" / ":" / control junk)
    name = str(n.get("name", "") or "").strip()
    if not name or len(name) < 2 or _NAME_BAD.match(name):
        # allow fall-back name only when we can rebuild something meaningful
        fallback = "%s-%s" % (ptype, n.get("server", ""))
        if not fallback or fallback in ("ss-", "vmess-", "vless-", "trojan-", "unknown-"):
            return False, "invalid name: %r" % n.get("name")
        n["name"] = fallback

    if ptype == "ss":
        cipher = str(n.get("cipher", "") or "").strip()
        if cipher and cipher not in SS_CIPHERS:
            return False, "ss unknown cipher: %s" % cipher
        if not n.get("cipher"):
            return False, "ss missing cipher"
        if not str(n.get("password") or "").strip():
            return False, "ss missing password"
    elif ptype == "vmess":
        if not str(n.get("uuid") or "").strip():
            return False, "vmess missing uuid"
    elif ptype == "vless":
        if not str(n.get("uuid") or "").strip():
            return False, "vless missing uuid"
    elif ptype in ("trojan", "hysteria", "hysteria2"):
        if ptype == "trojan" and not str(n.get("password") or "").strip():
            return False, "trojan missing password"
        if ptype.startswith("hysteria") and not str(n.get("auth") or "").strip():
            return False, "hysteria missing auth"
    elif ptype == "tuic":
        if not str(n.get("uuid") or "").strip():
            return False, "tuic missing uuid"
    elif ptype in ("socks", "http"):
        pass  # server/port checked by _structural_ok
    elif ptype in ("unknown", ""):
        return False, "unknown protocol type"

    return True, ""


def _structural_ok(n: dict) -> bool:
    ptype = n.get("type")
    if not n.get("server") or not n.get("port"):
        return False
    port = n.get("port")
    if not isinstance(port, int) or port <= 0 or port > 65535:
        return False
    if ptype == "ss" and not n.get("password"):
        return False
    if ptype in ("vmess", "vless") and not n.get("uuid"):
        return False
    if ptype in ("trojan", "hysteria", "hysteria2", "tuic") and not (n.get("password") or n.get("auth")):
        return False
    return True


def validate(nodes: list[dict], do_tcp: bool = True,
             max_probes: int = MAX_TCP_PROBES) -> list[dict]:
    """Attach `_validated` and `_validation_level` to each node.

    TCP probing is limited to the first `max_probes` structurally-valid
    nodes, so a run with thousands of nodes still finishes in seconds.
    The rest are marked `basic` (structurally valid, unverified) and
    scored lower.
    """
    candidates: list[dict] = []
    for n in nodes:
        ok_struct = _structural_ok(n)
        ok_schema, schema_reason = schema_ok(n)
        if ok_struct and ok_schema:
            n["_validation_level"] = "basic"
            n["_validated"] = True
            if do_tcp:
                candidates.append(n)
        else:
            n["_validation_level"] = "unknown"
            n["_validated"] = False
            n["_drop_reason"] = schema_reason or "structural check failed"
            log.debug("node dropped (%s): %s", n.get("name"), n["_drop_reason"])

    probe_set = candidates[:max_probes]
    for n in probe_set:
        ok = _tcp_probe(n.get("server", ""), int(n.get("port", 0)))
        n["_validation_level"] = "tcp" if ok else "basic"
        n["_validated"] = ok
        if not ok:
            log.debug("tcp probe failed for %s:%s", n.get("server"), n.get("port"))

    return nodes


if __name__ == "__main__":
    print("validator module loaded OK")
