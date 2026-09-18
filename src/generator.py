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

log = logging.getLogger("cfa.generator")

GROUP_NAMES = ["SELECT", "AUTO", "DIRECT"]
DEFAULT_MAX_IN_GROUP = 100


def _proxy_dict(n: dict) -> dict:
    """Strip internal bookkeeping keys and keep only mihomo-recognized ones."""
    internal = {"_source", "_score", "_validated", "_validation_level"}
    d = {k: v for k, v in n.items() if k not in internal and v is not None}
    # ensure keys mihomo actually knows (drop extras that may confuse)
    allowed = {
        "name", "type", "server", "port",
        "method", "password", "network", "plugin", "plugin-opts",
        "uuid", "alterId", "security", "sni", "skip-cert-verify",
        "flow", "reality-pub", "fingerprint", "ws-headers", "grpc-service-name",
        "auth", "protocol", "disable-insecure-tls", "obfs", "obfs-password",
        "username",
    }
    d = {k: v for k, v in d.items() if k in allowed}
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
    proxy_dicts = [_proxy_dict(n) for n in proxies]
    names = [p["name"] for p in proxy_dicts]

    # proxy-groups:
    # SELECT  : manual
    # AUTO    : url-test over the same list, with an interval
    # DIRECT  : direct (no proxy)
    all_in = list(names)
    auto_proxy = all_in if all_in else []

    groups = [
        {
            "name": "SELECT",
            "type": "select",
            "proxies": ["AUTO", "DIRECT", *all_in],
            "url": "http://127.0.0.1:33000/generate",  # mihomo test endpoint
            "interval": 300,
        },
        {
            "name": "AUTO",
            "type": "url-test",
            "proxies": auto_proxy or [],
            "url": "http://127.0.0.1:33000/generate",
            "interval": 300,
            "tolerance": 50,
        },
        {
            "name": "DIRECT",
            "type": "direct",
        },
    ]

    # reserved rules for common services — kept off by default (commented),
    # ready to be enabled
    # GEOIP,CN,DIRECT  is a single rule; below it we add placeholders
    # that can be uncommented to route specific domains via AUTO.
    rules = [
        "GEOIP,CN,DIRECT,no-resolve",
        # "DOMAIN-SUFFIX,google.com,SELECT",
        # "DOMAIN-SUFFIX,openai.com,SELECT",
        # "DOMAIN-SUFFIX,chatgpt.com,SELECT",
        # "DOMAIN-SUFFIX,gemini.google.com,SELECT",
        # "DOMAIN-SUFFIX,claude.ai,SELECT",
        # "DOMAIN-SUFFIX,x.com,SELECT",
        # "DOMAIN-SUFFIX,github.com,SELECT",
        "MATCH,AUTO",
    ]

    cfg = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
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


def write_clash_yaml(cfg: dict, out_path: str) -> bool:
    """Write clash.yaml. Caller must have verified cfg is non-empty first.

    Returns True if written, False if content was empty.
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
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    log.info("wrote %s with %d proxies", out_path, len(proxies))
    return True
