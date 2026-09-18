"""Deduplicate normalized nodes.

Key = (type, server, port). Different display names of the same node
are collapsed into one (keep the first, or the one with a higher score).
"""
from __future__ import annotations

import logging

log = logging.getLogger("cfa.dedup")


def dedupe(nodes: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for n in nodes:
        ptype = n.get("type", "")
        server = (n.get("server") or "").lower().strip()
        port = n.get("port")
        key = (ptype, server, port)
        if key in seen:
            # keep the higher score if one exists
            if n.get("_score", 0) > seen[key].get("_score", 0):
                seen[key] = n
        else:
            seen[key] = n
    return list(seen.values())
