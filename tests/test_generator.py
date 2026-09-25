"""Tests for the generator module.

Covers:
  - YAML round-trip parses cleanly
  - refuses to write when proxies list is empty
  - proxy-groups / rules / dns structure is present
  - internal bookkeeping keys are stripped
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.generator import build_config, render_yaml, write_clash_yaml  # noqa: E402


def _sample_nodes():
    return [
        {
            "name": "HK-ss",
            "type": "ss",
            "server": "1.1.1.1",
            "port": 10443,
            "method": "chacha20-ietf-poly1305",
            "cipher": "chacha20-ietf-poly1305",
            "password": "abc",
            "_source": "x",
            "_score": 80,
            "_validated": True,
            "_validation_level": "tcp",
        },
        {
            "name": "US-trojan",
            "type": "trojan",
            "server": "2.2.2.2",
            "port": 443,
            "password": "dead",
            "sni": "us.example.com",
            "_score": 70,
            "_validated": False,
            "_validation_level": "basic",
        },
    ]


def test_build_config_structure():
    cfg = build_config(_sample_nodes())
    assert "proxies" in cfg
    assert "proxy-groups" in cfg
    assert "rules" in cfg
    assert "dns" in cfg
    names = [g["name"] for g in cfg["proxy-groups"]]
    # group names are localized (每日免费 / 自动最快 / 直达 / AI专用) — assert all four present
    assert len(names) == 4
    assert any("每日免费" in n for n in names)
    assert any("自动最快" in n for n in names)
    assert any("直达" in n for n in names)
    assert any("AI" in n for n in names)


def test_internal_keys_stripped():
    cfg = build_config(_sample_nodes())
    for p in cfg["proxies"]:
        assert "_score" not in p
        assert "_validated" not in p
        assert "_validation_level" not in p
        assert "_source" not in p


def test_yaml_roundtrip_parses():
    import yaml as _yaml
    cfg = build_config(_sample_nodes())
    text = render_yaml(cfg)
    reparsed = _yaml.safe_load(text)
    assert reparsed["proxies"][0]["name"] == "HK-ss"
    assert reparsed["proxies"][1]["name"] == "US-trojan"


def test_refuses_empty(tmp_path):
    out = tmp_path / "empty.yaml"
    cfg = build_config([])
    assert not write_clash_yaml(cfg, str(out))
    assert not out.exists()


def test_writes_with_content(tmp_path):
    out = tmp_path / "ok.yaml"
    cfg = build_config(_sample_nodes())
    assert write_clash_yaml(cfg, str(out))
    assert out.exists()
    text = out.read_text()
    assert "HK-ss" in text


def test_gecip_cn_rule_present():
    cfg = build_config(_sample_nodes())
    assert any(r.startswith("GEOIP,CN") for r in cfg["rules"])
    assert any(r.startswith("MATCH") for r in cfg["rules"])
