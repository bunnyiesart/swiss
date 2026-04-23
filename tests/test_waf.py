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
    {"detected": True, "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc.",
     "trigger_url": "https://example.com/?xss=<script>", "url": "https://example.com"}
])

_MULTI_WAF = json.dumps([
    {"detected": True, "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc.",
     "trigger_url": "https://example.com/?xss=<script>", "url": "https://example.com"},
    {"detected": True, "firewall": "ModSecurity", "manufacturer": "Trustwave",
     "trigger_url": "https://example.com/?sql=union", "url": "https://example.com"},
])

_NONE_DETECTED = json.dumps([
    {"detected": False, "firewall": "None", "manufacturer": "None",
     "trigger_url": None, "url": "https://example.com"}
])

_GENERIC_DETECTED = json.dumps([
    {"detected": True, "firewall": "Generic", "manufacturer": "Unknown",
     "trigger_url": "https://example.com/?xss=<script>", "url": "https://example.com"}
])

_MIXED = json.dumps([
    {"detected": True,  "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc.",
     "trigger_url": "https://example.com/?xss=<script>", "url": "https://example.com"},
    {"detected": True,  "firewall": "Generic",    "manufacturer": "Unknown",
     "trigger_url": "https://example.com/?xss=<script>", "url": "https://example.com"},
    {"detected": False, "firewall": "None",        "manufacturer": "None",
     "trigger_url": None, "url": "https://example.com"},
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
    assert result["generic_detected"] is False


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


def test_mixed_result():
    """Named WAF + generic flag + undetected entry all in one response."""
    client = WAFDetector()
    with patch("lib.waf.subprocess.run", return_value=_run(_MIXED)):
        result = client.detect("https://example.com")
    assert result["detected"] == ["Cloudflare"]
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


def test_binary_path_used():
    """Ensures the wafw00f binary (not python -m) is invoked."""
    client = WAFDetector()
    with patch("lib.waf.subprocess.run", return_value=_run(_WAF_DETECTED)) as mock_run:
        client.detect("https://example.com")
    cmd = mock_run.call_args[0][0]
    assert "wafw00f" in cmd[0]
    assert "-m" not in cmd
