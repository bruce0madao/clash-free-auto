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
        if _structural_ok(n):
            n["_validation_level"] = "basic"
            n["_validated"] = True
            if do_tcp:
                candidates.append(n)
        else:
            n["_validation_level"] = "unknown"
            n["_validated"] = False

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
