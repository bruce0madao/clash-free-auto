"""Tests for parser module.

Run with:  pytest tests/ -q
Imports use the package-qualified form (src.parser) so they work both
from the repo root and inside GitHub Actions.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.parser import parse_subscription  # noqa: E402


def test_parse_yaml_clash():
    yaml_text = """
proxies:
  - name: HK-1
    type: ss
    server: 1.2.3.4
    port: 10443
    cipher: chacha20-ietf-poly1305
    password: abc123
  - name: US-Trojan
    type: trojan
    server: 5.6.7.8
    port: 443
    sni: example.com
    password: deadbeef
"""
    nodes = parse_subscription(yaml_text, "test")
    assert len(nodes) == 2
    assert nodes[0]["type"] == "ss"
    assert nodes[0]["server"] == "1.2.3.4"
    assert nodes[0]["port"] == 10443


def test_parse_ss_link():
    import base64
    b64 = base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:secret@1.1.1.1:443").decode()
    # ss://b64info@server:port#tag  is non-standard; use the base64 userinfo form:
    line = f"ss://{b64}@2.2.2.2:443#SG"
    nodes = parse_subscription(line, "test")
    assert len(nodes) >= 1
    assert nodes[0]["type"] == "ss"
    assert nodes[0]["server"] == "2.2.2.2"


def test_parse_vless_link():
    line = "vless://uuid@8.8.8.8:443?encryption=none&security=reality&sni=gg.gg#Test"
    nodes = parse_subscription(line, "test")
    assert len(nodes) == 1
    assert nodes[0]["type"] == "vless"
    assert nodes[0]["server"] == "8.8.8.8"


def test_parse_base64_yaml():
    import base64
    raw = "proxies:\n  - name: X\n    type: vmess\n    server: 9.9.9.9\n    port: 1080\n    uuid: 123\n"
    b64 = base64.b64encode(raw.encode()).decode()
    nodes = parse_subscription(b64, "test")
    assert len(nodes) == 1
    assert nodes[0]["type"] == "vmess"


def test_garbage_does_not_crash():
    nodes = parse_subscription("not a real subscription !!! %%%", "test")
    assert isinstance(nodes, list)


def test_empty():
    assert parse_subscription("", "test") == []
    assert parse_subscription(None, "test") == []
