"""Schema validation tests — per-protocol strict checks + generator gate.

Covers the "O:" incident: an ss node missing cipher must never reach clash.yaml.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.validator import schema_ok  # noqa: E402
from src.generator import build_config, render_yaml, write_clash_yaml, get_dropped  # noqa: E402


# ── schema_ok unit tests ─────────────────────────────────────────────────────

def test_invalid_ss_without_cipher():
    """An ss node with no cipher must FAIL validation."""
    ok, reason = schema_ok(
        {"name": "O:", "type": "ss", "server": "1.2.3.4", "port": 443, "password": "xxx"}
    )
    assert not ok
    assert "cipher" in reason.lower()


def test_invalid_ss_without_password():
    """An ss node with empty password must FAIL validation."""
    ok, reason = schema_ok(
        {
            "name": "test-ss",
            "type": "ss",
            "server": "1.2.3.4",
            "port": 443,
            "cipher": "chacha20-ietf-poly1305",
            "password": "",
        }
    )
    assert not ok
    assert "password" in reason.lower()


def test_valid_ss():
    """A complete ss node (cipher + password + server + port) must PASS."""
    ok, reason = schema_ok(
        {
            "name": "HK-ss",
            "type": "ss",
            "server": "1.1.1.1",
            "port": 443,
            "cipher": "chacha20-ietf-poly1305",
            "password": "secret",
        }
    )
    assert ok, reason


def test_valid_vless():
    ok, reason = schema_ok(
        {
            "name": "test-vless",
            "type": "vless",
            "server": "2.2.2.2",
            "port": 443,
            "uuid": "01234567-89ab-cdef-0123-456789abcdef",
        }
    )
    assert ok, reason


def test_invalid_vless_without_uuid():
    ok, reason = schema_ok(
        {"name": "test", "type": "vless", "server": "2.2.2.2", "port": 443}
    )
    assert not ok


def test_invalid_trojan_without_password():
    ok, reason = schema_ok(
        {"name": "test", "type": "trojan", "server": "3.3.3.3", "port": 443, "password": ""}
    )
    assert not ok


def test_bad_name_fallback():
    """Pure-punctuation names (":;", ",", etc.) must get a fallback."""
    node = {"name": "::", "type": "ss", "server": "5.6.7.8", "port": 443,
            "cipher": "chacha20-ietf-poly1305", "password": "pw"}
    ok, reason = schema_ok(node)
    assert ok
    assert node["name"] != "::"
    assert "ss" in node["name"]


def test_o_colon_name_passes_schema():
    """'O:' is an unusual but structurally valid ss node — schema gate passes.
    The O: incident was about missing cipher, not the name itself."""
    node = {"name": "O:", "type": "ss", "server": "5.6.7.8", "port": 443,
            "cipher": "chacha20-ietf-poly1305", "password": "pw"}
    ok, reason = schema_ok(node)
    assert ok, reason



# ── generator gate tests ─────────────────────────────────────────────────────

def test_final_config_contains_no_invalid_proxy(tmp_path):
    """Invalid nodes must NOT appear in the generated YAML; valid ones must."""
    import yaml as _yaml

    nodes = [
        # valid
        {"name": "good-ss", "type": "ss", "server": "9.9.9.9", "port": 443,
         "cipher": "chacha20-ietf-poly1305", "password": "pw"},
        # invalid: no cipher
        {"name": "bad-ss", "type": "ss", "server": "1.2.3.4", "port": 443, "password": "x"},
        # invalid: vless no uuid
        {"name": "bad-vless", "type": "vless", "server": "1.2.3.4", "port": 443},
        # valid
        {"name": "good-trojan", "type": "trojan", "server": "8.8.8.8", "port": 443,
         "password": "pw"},
    ]
    get_dropped()  # reset
    cfg = build_config(nodes)
    dropped = get_dropped()
    assert len(dropped) == 2, "expected exactly 2 invalid nodes dropped"

    text = render_yaml(cfg)
    data = _yaml.safe_load(text)
    proxy_names = [p["name"] for p in data["proxies"]]
    assert "good-ss" in proxy_names
    assert "good-trojan" in proxy_names
    assert "bad-ss" not in proxy_names
    assert "bad-vless" not in proxy_names


def test_write_clash_yaml_rejects_invalid(tmp_path):
    """write_clash_yaml must return False if a generated proxy fails schema."""
    import yaml as _yaml

    # Build a config that looks valid but has a bad ss proxy (bypass build_config gate
    # by constructing manually to test the write-time re-check).
    bad_cfg = {
        "mixed-port": 7890,
        "proxies": [
            {"name": "bad", "type": "ss", "server": "1.2.3.4", "port": 443,
             "password": "x"}  # no cipher — must fail
        ],
    }
    out = tmp_path / "clash.yaml"
    result = write_clash_yaml(bad_cfg, str(out))
    assert not result, "write_clash_yaml should refuse to write a schema-invalid config"
    assert not out.exists() or "bad" not in out.read_text()
