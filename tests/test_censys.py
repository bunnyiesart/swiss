import responses as resp_lib

from lib.censys import CensysClient

BASE = "https://search.censys.io/api/v2"

_CENSYS_RESPONSE = {
    "result": {
        "ip": "8.8.8.8",
        "services": [
            {"port": 53, "transport_protocol": "UDP", "service_name": "DNS"},
            {"port": 443, "transport_protocol": "TCP", "service_name": "HTTPS"},
        ],
        "labels": ["cdn"],
        "autonomous_system": {
            "asn": 15169,
            "description": "Google LLC",
            "bgp_prefix": "8.8.8.0/24",
        },
        "location": {"country_code": "US"},
    }
}


@resp_lib.activate
def test_check_ip_happy_path():
    resp_lib.add(resp_lib.GET, f"{BASE}/hosts/8.8.8.8", json=_CENSYS_RESPONSE, status=200)
    client = CensysClient("test-id", "test-secret")
    result = client.check_ip("8.8.8.8")
    assert result["source"] == "censys"
    assert result["found"] is True
    assert len(result["services"]) == 2
    assert result["services"][0]["port"] == 53
    assert result["asn"] == 15169
    assert result["org"] == "Google LLC"
    assert result["country"] == "US"
    assert result["bgp_prefix"] == "8.8.8.0/24"
    assert "error" not in result


@resp_lib.activate
def test_check_ip_not_found():
    resp_lib.add(resp_lib.GET, f"{BASE}/hosts/192.0.2.1", status=404)
    client = CensysClient("test-id", "test-secret")
    result = client.check_ip("192.0.2.1")
    assert result["source"] == "censys"
    assert result["found"] is False
    assert "error" not in result


@resp_lib.activate
def test_check_ip_auth_error():
    resp_lib.add(resp_lib.GET, f"{BASE}/hosts/1.2.3.4", status=401)
    client = CensysClient("bad-id", "bad-secret")
    result = client.check_ip("1.2.3.4")
    assert result["source"] == "censys"
    assert "error" in result


def test_not_configured():
    from lib.config import _unconfigured
    client = _unconfigured("censys")
    result = client.check_ip("1.2.3.4")
    assert result["error"] == "not_configured"
