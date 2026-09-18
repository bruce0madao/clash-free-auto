"""Main pipeline: fetch -> parse -> normalize -> dedup -> validate -> score
-> generate clash.yaml -> status.json -> commit-if-changed.

Safety (spec #18 #28):
  - if fewer than MIN_FINAL nodes survive, we DO NOT overwrite clash.yaml
    and we print "Update skipped: insufficient valid proxies".
  - status.json is written every run so the dashboard can observe progress.
  - main exits 0 on a clean run even when we skip the update.
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import sys

from .fetch import load_sources, fetch_all
from .parser import parse_subscription
from .normalize import normalize
from .deduplicate import dedupe
from .validator import validate
from .scoring import score_nodes, keep_nodes, MIN_KEEP, MIN_KEEP_TCP
from .generator import build_config, write_clash_yaml

log = logging.getLogger("cfa.main")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLASH_OUT = os.path.join(ROOT, "output", "clash.yaml")
STATUS_OUT = os.path.join(ROOT, "output", "status.json")

# Safety floor: below this count we refuse to publish.
MIN_FINAL_NODES = 3


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(do_commit: bool = True) -> int:
    """Execute the pipeline. Returns 0 on success (including skip)."""
    logging.basicConfig(level=os.environ.get("CFA_LOGLEVEL", "INFO"), stream=sys.stdout)
    log.info("=== clash-free-auto pipeline start ===")

    # 1. fetch
    sources = load_sources(os.path.join(ROOT, "config", "sources.yaml"))
    log.info("loaded %d enabled sources", len(sources))
    fr = fetch_all(sources)

    # 2. parse each source
    raw_nodes: list[dict] = []
    for item in fr.items:
        parsed = parse_subscription(item["raw_text"], source_name=item["name"])
        log.info("source %s -> %d raw nodes", item["name"], len(parsed))
        raw_nodes.extend(parsed)
    log.info("total raw nodes parsed: %d", len(raw_nodes))

    # 3. normalize (drops broken ones)
    normalized = [n for n in (normalize(x) for x in raw_nodes) if n is not None]
    log.info("normalized: %d", len(normalized))

    # 4. dedup
    deduped = dedupe(normalized)
    log.info("dedup: %d -> %d", len(normalized), len(deduped))

    # 5. validate (tcp probe where safe)
    do_tcp = os.environ.get("CFA_NO_TCP", "0") != "1"
    validated = validate(deduped, do_tcp=do_tcp, max_probes=200)
    n_tcp = sum(1 for n in validated if n.get("_validation_level") == "tcp")
    log.info("validated: %d (tcp-confirmed: %d, do_tcp=%s)", len(validated), n_tcp, do_tcp)

    # 6. score
    scored = score_nodes(validated)
    any_tcp = n_tcp > 0
    floor = MIN_KEEP_TCP if any_tcp else MIN_KEEP
    kept = keep_nodes(scored, min_score=floor, max_nodes=100)
    log.info("kept: %d (score>=%d, %s)", len(kept), floor, "TCP-confirmed floor" if any_tcp else "basic floor")

    # 7. status.json (always written)
    status = {
        "updated_at": _now_iso(),
        "sources_total": fr.sources_total,
        "sources_success": fr.sources_success,
        "sources_failed": fr.sources_failed,
        "raw_nodes": len(raw_nodes),
        "parsed_nodes": len(normalized),
        "deduplicated_nodes": len(deduped),
        "validated_nodes": len(validated),
        "validated_tcp": n_tcp,
        "final_nodes": len(kept),
        "scores": [round(n.get("_score", 0), 1) for n in sorted(kept, key=lambda x: -x.get("_score", 0))[:20]],
        "error": None,
    }

    if len(kept) < MIN_FINAL_NODES:
        status["error"] = "insufficient valid proxies"
        _write_status(status)
        log.warning("Update skipped: insufficient valid proxies (kept=%d, min=%d)", len(kept), MIN_FINAL_NODES)
        return 0

    # 8. generate
    cfg = build_config(kept)
    if not write_clash_yaml(cfg, CLASH_OUT):
        status["error"] = "generator refused to write empty/broken config"
        _write_status(status)
        log.error("Update skipped: generator rejected config")
        return 0

    _write_status(status)
    log.info("=== clash-free-auto pipeline OK: %d proxies published ===", len(kept))
    return 0


def _write_status(status: dict) -> None:
    os.makedirs(os.path.dirname(STATUS_OUT), exist_ok=True)
    with open(STATUS_OUT, "w", encoding="utf-8") as f:
        json.dump(status, f, indent=2, ensure_ascii=False)
    log.info("status.json written (%d bytes)", os.path.getsize(STATUS_OUT))


if __name__ == "__main__":
    sys.exit(run())
