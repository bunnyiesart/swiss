import responses as resp_lib
from lib.shodan import Shodan

BASE = "https://api.shodan.io/shodan/host"


@resp_lib.activate
def test_check_ip_happy_path():
    resp_lib.add(resp_lib.GET, f"{BASE}/1.2.3.4", json={
        "ip_str": "1.2.3.4", "org": "Example Org", "isp": "Example ISP",
        "country_name": "United States", "country_code": "US",
        "ports": [22, 80, 443], "vulns": {"CVE-2021-44228": {}},
        "tags": ["cdn"], "last_update": "2024-01-01T00:00:00",
        "hostnames": ["example.com"],
    }, status=200)
    client = Shodan("test-key")
    result = client.check_ip("1.2.3.4")
    assert result["source"] == "shodan"
    assert result["found"] is True
    assert 80 in result["open_ports"]
    assert "CVE-2021-44228" in result["vulns"]
    assert "error" not in result


@resp_lib.activate
def test_check_ip_not_found():
    resp_lib.add(resp_lib.GET, f"{BASE}/1.2.3.4", status=404)
    client = Shodan("test-key")
    result = client.check_ip("1.2.3.4")
    assert result["source"] == "shodan"
    assert result["found"] is False
    assert "error" not in result
