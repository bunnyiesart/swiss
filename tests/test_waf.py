import json
import subprocess
from unittest.mock import patch, MagicMock

from lib.waf import WAFDetector


def _run(stdout: str, returncode: int = 0) -> MagicMock:
    m = MagicMock()
    m.stdout = stdout
    m.stderr = ""
    m.returncode = returncode
    return m


_WAF_DETECTED = json.dumps([
    {"url": "https://example.com", "firewall": "Cloudflare", "manufacturer": "Cloudflare, Inc."}
])

_MULTI_WAF = json.dumps([
    {"url": "https://example.com", "firewall": "Cloudflare", "manufacturer": "Cloudflare, Inc."},
    {"url": "https://example.com", "firewall": "ModSecurity", "manufacturer": "Trustwave"},
])

_NONE_DETECTED = json.dumps([
    {"url": "https://example.com", "firewall": "None", "manufacturer": "None"}
])

_GENERIC_DETECTED = json.dumps([
    {"url": "https://example.com", "firewall": "Generic", "manufacturer": "unknown"}
])


def test_waf_detected():
    client = WAFDetector()
    with patch("lib.waf.subprocess.run", return_value=_run(_WAF_DETECTED)):
        result = client.detect("https://example.com")
    assert result["source"] == "waf"
    assert "Cloudflare" in result["detected"]
    assert result["generic_detected"] is False
    assert "error" not in result


def test_multiple_wafs_detected():
    client = WAFDetector()
    with patch("lib.waf.subprocess.run", return_value=_run(_MULTI_WAF)):
        result = client.detect("https://example.com")
    assert len(result["detected"]) == 2
    assert "Cloudflare" in result["detected"]
    assert "ModSecurity" in result["detected"]


def test_none_detected():
    client = WAFDetector()
    with patch("lib.waf.subprocess.run", return_value=_run(_NONE_DETECTED)):
        result = client.detect("https://example.com")
    assert result["source"] == "waf"
    assert result["detected"] == []
    assert result["generic_detected"] is False
    assert "error" not in result


def test_generic_detected():
    client = WAFDetector()
    with patch("lib.waf.subprocess.run", return_value=_run(_GENERIC_DETECTED)):
        result = client.detect("https://example.com")
    assert result["detected"] == []
    assert result["generic_detected"] is True


def test_timeout():
    client = WAFDetector()
    with patch("lib.waf.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="wafw00f", timeout=30)):
        result = client.detect("https://slow.example.com")
    assert result["source"] == "waf"
    assert result["error"] == "timeout"


def test_empty_output():
    client = WAFDetector()
    with patch("lib.waf.subprocess.run", return_value=_run("")):
        result = client.detect("https://example.com")
    assert result["detected"] == []
    assert "error" not in result


def test_non_zero_exit():
    client = WAFDetector()
    with patch("lib.waf.subprocess.run", return_value=_run("", returncode=2)):
        result = client.detect("https://example.com")
    assert result["source"] == "waf"
    assert "error" in result
