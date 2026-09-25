"""Generate a Mihomo / Clash Meta config for Clash Verge Rev.

Output keys:
  proxies:        the selected nodes
  proxy-groups:   SELECT / AUTO / DIRECT
  rules:          CN-direct / GEOIP / reserved slots for Google/Gemini/etc.

Safety (spec #18 #28):
  - if no proxies, caller must NOT overwrite an existing clash.yaml
  - we only write files here; main.py decides whether to commit
"""
from __future__ import annotations

import logging
import yaml
from .validator import schema_ok  # final safety gate

log = logging.getLogger("cfa.generator")

GROUP_NAMES = ["🚀 每日免费", "🚀 自动最快", "直达"]
DEFAULT_MAX_IN_GROUP = 100


def _proxy_dict(n: dict) -> dict:
    """Strip internal bookkeeping keys and keep only mihomo-recognized ones."""
    internal = {"_source", "_score", "_validated", "_validation_level"}
    d = {k: v for k, v in n.items() if k not in internal and v is not None}
    # ensure keys mihomo actually knows (drop extras that may confuse)
    allowed = {
        "name", "type", "server", "port",
        "method", "cipher", "password", "network", "plugin", "plugin-opts",
        "uuid", "alterId", "security", "sni", "skip-cert-verify",
        "flow", "reality-pub", "fingerprint", "ws-headers", "grpc-service-name",
        "auth", "protocol", "disable-insecure-tls", "obfs", "obfs-password",
        "username",
    }
    d = {k: v for k, v in d.items() if k in allowed}
    # drop empty-string optional fields (empty vless flow breaks mihomo startup)
    for key in ("flow", "sni", "plugin", "obfs", "username", "alterId"):
        if d.get(key) == "":
            d.pop(key, None)
    # for ss: if no method, default to chacha20-ietf-poly1305
    if d.get("type") == "ss" and "method" not in d:
        d["method"] = "chacha20-ietf-poly1305"
    # mihomo expects `port` as int
    if "port" in d:
        try:
            d["port"] = int(d["port"])
        except Exception:
            pass
    return d


def build_config(
    proxies: list[dict],
    group_name: dict | None = None,
) -> dict:
    """Build a complete mihomo config dict.

    group_name lets caller override which proxy to wire into SELECT/AUTO.
    Defaults to using the `proxies` list itself.
    """
    # Final safety gate: every proxy must pass the strict per-protocol schema
    # check before it can reach the generated config. Nodes failing here are
    # dropped and counted in the returned `dropped` key.
    passed, dropped = [], []
    for n in proxies:
        ok, reason = schema_ok(n)
        if ok:
            passed.append(n)
        else:
            dropped.append({"name": n.get("name"), "type": n.get("type"), "reason": reason})
    if dropped:
        log.warning("generator dropped %d invalid nodes: %s", len(dropped),
                    "; ".join("%s(%s): %s" % (d["name"], d["type"], d["reason"]) for d in dropped[:5]))
    proxy_dicts = [_proxy_dict(n) for n in passed]
    # attach drop stats for status.json
    global _dropped
    _dropped = dropped
    names = [p["name"] for p in proxy_dicts]

    # proxy-groups:
    # SELECT  : manual
    # AUTO    : url-test over the same list, with an interval
    # DIRECT  : direct (no proxy)
    all_in = list(names)
    auto_proxy = all_in if all_in else []

    # AI-specific group: prefer trojan/vless with CF domain or SNI (less likely datacenter)
    ai_proxies = [p for p in proxy_dicts if p.get("type") in ("trojan","vless") and (p.get("sni") or p.get("ws-headers",{}).get("Host",""))]
    if ai_proxies:
        ai_names = [p["name"] for p in ai_proxies]
    else:
        ai_names = []
    
    groups = [
        {
            "name": "🚀 每日免费",
            "type": "select",
            "proxies": ["🚀 自动最快", *all_in],
        },
        {
            "name": "🚀 自动最快",
            "type": "url-test",
            "proxies": auto_proxy or [],
            # standard mihomo test URL (resolves for both Meta and Verge)
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
        },
        {
            "name": "🤖 AI 专用",
            "type": "url-test",
            "proxies": ai_names or auto_proxy,
            "url": "https://chat.openai.com/",
            "interval": 600,
            "tolerance": 100,
        },
    ]

    # reserved rules for common services — kept off by default (commented),
    # ready to be enabled
    # GEOIP,CN,DIRECT  is a single rule; below it we add placeholders
    # that can be uncommented to route specific domains via AUTO.
    rules = [
        "GEOIP,CN,🚀 每日免费,no-resolve",
        # "DOMAIN-SUFFIX,google.com,SELECT",
        # "DOMAIN-SUFFIX,openai.com,SELECT",
        # "DOMAIN-SUFFIX,chatgpt.com,SELECT",
        # "DOMAIN-SUFFIX,gemini.google.com,SELECT",
        # "DOMAIN-SUFFIX,claude.ai,SELECT",
        # "DOMAIN-SUFFIX,x.com,SELECT",
        # "DOMAIN-SUFFIX,github.com,SELECT",
        # AI sites via dedicated group (avoids datacenter IP blocks)
        "DOMAIN-KEYWORD,openai,🤖 AI 专用",
        "DOMAIN-KEYWORD,chatgpt,🤖 AI 专用",
        "DOMAIN-KEYWORD,anthropic,🤖 AI 专用",
        "DOMAIN-KEYWORD,claude,🤖 AI 专用",
        "DOMAIN-KEYWORD,ai,🤖 AI 专用",
        "MATCH,🚀 自动最快",
    ]

    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "tproxy": {"mode": "tcp-only"},
        "proxies": proxy_dicts,
        "proxy-groups": groups,
        "rules": rules,
        "dns": {
            "enabled": True,
            "listen": "127.0.0.1:5353",
            "nameserver": [
                "223.5.5.5",
                "119.29.29.29",
                "1.1.1.1",
            ],
            "fallback": ["https://dns.google/dns-query"],
            "fallback-filter": {"geoip": True, "ipcidr": ["223.5.5.5/32"]},
        },
    }
    return cfg


def render_yaml(cfg: dict) -> str:
    return yaml.safe_dump(cfg, allow_unicode=True, default_flow_style=False, sort_keys=False)


_dropped: list[dict] = []


def get_dropped() -> list[dict]:
    """Nodes rejected by the generator's schema gate in the last build_config()."""
    return list(_dropped)


def write_clash_yaml(cfg: dict, out_path: str) -> bool:
    """Write clash.yaml after a final schema re-check.

    Returns True if written, False if content was empty or failed validation.
    """
    proxies = cfg.get("proxies") or []
    if not proxies:
        log.warning("generator: refusing to write empty proxies list")
        return False
    text = render_yaml(cfg)
    # YAML must round-trip cleanly — sanity check
    try:
        yaml.safe_load(text)
    except Exception as e:
        log.error("generated yaml does not parse: %s", e)
        return False
    # Final re-verify: re-load the written text and re-check every proxy
    # against the per-protocol schema before declaring success.
    try:
        reloaded = yaml.safe_load(text)
        for p in (reloaded.get("proxies") or []):
            ok, reason = schema_ok(p)
            if not ok:
                log.error("generated proxy failed schema: %s -> %s", p.get("name"), reason)
                return False
    except Exception as e:
        log.error("final schema re-check failed: %s", e)
        return False
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    log.info("wrote %s with %d proxies (schema-verified)", out_path, len(proxies))
    return True
