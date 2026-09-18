"""Fetch public subscription sources listed in config/sources.yaml.

Design goals (from spec):
  - timeout / exception / HTTP-error / encoding / empty-content handling
  - one source failing must NOT abort the run
  - produce stats: sources_total / sources_success / sources_failed
"""
from __future__ import annotations

import base64
import logging
import os
import re

import requests
import yaml

log = logging.getLogger("cfa.fetch")

DEFAULT_TIMEOUT = 30
MAX_BODY_BYTES = 5 * 1024 * 1024  # 5 MB safety cap
USER_AGENT = "Mozilla/5.0 (compatible; clash-free-auto/1.0)"


class FetchResult:
    def __init__(self):
        self.items: list[dict] = []          # [{"name":..., "url":..., "raw_text":...}]
        self.sources_total = 0
        self.sources_success = 0
        self.sources_failed = 0
        self.errors: list[dict] = []

    def summary(self) -> dict:
        return {
            "sources_total": self.sources_total,
            "sources_success": self.sources_success,
            "sources_failed": self.sources_failed,
        }


def load_sources(config_path: str | None = None) -> list[dict]:
    """Read enabled sources from sources.yaml. Returns [] if file missing/empty."""
    if config_path is None:
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config",
            "sources.yaml",
        )
    if not os.path.exists(config_path):
        log.warning("sources config not found: %s", config_path)
        return []
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        log.error("failed to parse sources.yaml: %s", e)
        return []
    sources = data.get("sources", []) or []
    out = []
    for s in sources:
        if not isinstance(s, dict):
            continue
        url = (s.get("url") or "").strip()
        enabled = s.get("enabled", True)
        if not url or not enabled:
            continue
        out.append(
            {
                "name": str(s.get("name") or url),
                "url": url,
                "type": s.get("type", "auto"),
            }
        )
    return out


def _try_text(data: bytes) -> str:
    """Decode bytes robustly."""
    for enc in ("utf-8", "gb18030", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def _looks_base64(text: str) -> bool:
    s = text.strip()
    if len(s) < 40:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=\s]+", s):
        return False
    # must have reasonable length and be decodable as base64
    try:
        base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
        return True
    except Exception:
        return False


def fetch_all(sources: list[dict], timeout: int = DEFAULT_TIMEOUT) -> FetchResult:
    res = FetchResult()
    res.sources_total = len(sources)
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    for src in sources:
        name, url = src["name"], src["url"]
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code >= 400:
                raise RuntimeError(f"HTTP {r.status_code}")
            data = r.content
            if len(data) > MAX_BODY_BYTES:
                data = data[:MAX_BODY_BYTES]
            text = _try_text(data)
            if not text or not text.strip():
                raise RuntimeError("empty body")
            # if the body is base64 of YAML, decode it
            if text.strip().startswith(("hQ", "Zg", "YQ", "LQ", "LS0t")) or _looks_base64(text):
                try:
                    decoded = base64.b64decode(text.strip()).decode("utf-8", "replace")
                    if "proxies:" in decoded:
                        text = decoded
                        log.info("[%s] decoded base64 -> yaml", name)
                except Exception:
                    pass
            if not text or not text.strip():
                raise RuntimeError("no usable content")
            res.items.append({"name": name, "url": url, "raw_text": text})
            res.sources_success += 1
            log.info("[%s] OK, %d bytes", name, len(text))
        except Exception as e:
            res.sources_failed += 1
            res.errors.append({"name": name, "url": url, "error": str(e)[:200]})
            log.warning("[%s] fetch failed: %s", name, e)
    return res


if __name__ == "__main__":
    import json

    srcs = load_sources()
    fr = fetch_all(srcs)
    print(json.dumps(fr.summary(), indent=2))
    for it in fr.items:
        print(f"  {it['name']}: {len(it['raw_text'])} bytes")
