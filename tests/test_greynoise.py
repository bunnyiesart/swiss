import responses as resp_lib
from lib.greynoise import GreyNoise

_COMMUNITY_BASE  = "https://api.greynoise.io/v3/community"
_ENTERPRISE_BASE = "https://api.greynoise.io/v3/noise/context"


@resp_lib.activate
def test_community_known_noise():
    resp_lib.add(resp_lib.GET, f"{_COMMUNITY_BASE}/1.2.3.4", json={
        "ip": "1.2.3.4", "noise": True, "riot": False,
        "classification": "malicious", "name": "MassScanner", "last_seen": "2024-01-01",
    }, status=200)
    client = GreyNoise()
    result = client.check_ip("1.2.3.4")
    assert result["source"] == "greynoise"
    assert result["noise"] is True
    assert result["classification"] == "malicious"
    assert "error" not in result


@resp_lib.activate
def test_community_not_found():
    resp_lib.add(resp_lib.GET, f"{_COMMUNITY_BASE}/1.2.3.4", status=404)
    client = GreyNoise()
    result = client.check_ip("1.2.3.4")
    assert result["noise"] is False
    assert result["found"] is False
    assert "error" not in result


@resp_lib.activate
def test_community_error():
    resp_lib.add(resp_lib.GET, f"{_COMMUNITY_BASE}/1.2.3.4", status=500)
    client = GreyNoise()
    result = client.check_ip("1.2.3.4")
    assert "error" in result


@resp_lib.activate
def test_enterprise_uses_context_endpoint():
    resp_lib.add(resp_lib.GET, f"{_ENTERPRISE_BASE}/1.2.3.4", json={
        "ip": "1.2.3.4", "noise": True, "riot": False,
        "classification": "malicious", "name": "MassScanner",
        "tags": ["scanner"], "metadata": {"country": "US"},
        "last_seen": "2024-01-01", "first_seen": "2023-01-01", "seen": True,
    }, status=200)
    client = GreyNoise("test-key")
    result = client.check_ip("1.2.3.4")
    assert result["source"] == "greynoise"
    assert result["noise"] is True
    assert "tags" in result
    assert "metadata" in result
    assert "error" not in result


@resp_lib.activate
def test_enterprise_not_found():
    resp_lib.add(resp_lib.GET, f"{_ENTERPRISE_BASE}/1.2.3.4", status=404)
    client = GreyNoise("test-key")
    result = client.check_ip("1.2.3.4")
    assert result["noise"] is False
    assert result["found"] is False
    assert "error" not in result
