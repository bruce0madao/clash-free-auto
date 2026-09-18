"""Node scoring.

Score composition (0-100):
  - base            : format completeness (0-30)
  - validation      : tcp-validated (40) / basic (10) / unknown (0)
  - latency hint    : reserved, 0 in CI (no HTTP test)
  - dedup bonus     : implicit
  - protocol quality: +5 for well-supported protocols

Thresholds (from spec):
  90-100 excellent
  75-89  good
  60-74  ok
  <60    eliminated

We NEVER rank on latency alone.
"""
from __future__ import annotations

import logging

log = logging.getLogger("cfa.scoring")

MIN_KEEP = 30
# Floor: when we could confirm via TCP, raise the floor to drop weak nodes
MIN_KEEP_TCP = 60


def _base_completeness(n: dict) -> float:
    ptype = n.get("type", "")
    pts = 0.0
    if n.get("name"):
        pts += 5
    if n.get("server"):
        pts += 10
    if n.get("port"):
        pts += 5
    if ptype in ("ss",) and n.get("password"):
        pts += 5
    if ptype in ("vmess", "vless") and n.get("uuid"):
        pts += 5
    if ptype in ("trojan", "hysteria", "hysteria2", "tuic") and (n.get("password") or n.get("auth")):
        pts += 5
    if ptype in ("socks", "http"):
        pts += 5
    return min(pts, 30.0)


def _validation_score(n: dict) -> float:
    lvl = n.get("_validation_level", "unknown")
    if lvl == "tcp":
        return 40.0
    if lvl == "http":
        return 45.0
    if lvl == "basic":
        return 10.0
    return 0.0


def _protocol_bonus(n: dict) -> float:
    ptype = n.get("type", "")
    if ptype in ("trojan", "vless", "vmess", "ss"):
        return 5.0
    return 0.0


def score_nodes(nodes: list[dict]) -> list[dict]:
    for n in nodes:
        s = _base_completeness(n) + _validation_score(n) + _protocol_bonus(n)
        n["_score"] = round(max(0.0, min(100.0, s)), 2)
    return nodes


def keep_nodes(nodes: list[dict], min_score: float = MIN_KEEP, max_nodes: int = 100) -> list[dict]:
    qualified = [n for n in nodes if n.get("_score", 0) >= min_score]
    # sort: score desc, then tcp-validated first, then type preference
    qualified.sort(
        key=lambda x: (
            -x.get("_score", 0),
            0 if x.get("_validation_level") == "tcp" else 1,
            x.get("type", ""),
        ),
    )
    return qualified[:max_nodes]
