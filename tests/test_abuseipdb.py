import responses as resp_lib
from lib.abuseipdb import AbuseIPDB

BASE = "https://api.abuseipdb.com/api/v2"

_RESPONSE = {
    "data": {
        "ipAddress": "1.2.3.4",
        "abuseConfidenceScore": 87,
        "totalReports": 42,
        "numDistinctUsers": 15,
        "lastReportedAt": "2024-01-01T00:00:00+00:00",
        "isp": "Example ISP",
        "domain": "example.com",
        "countryCode": "US",
        "usageType": "Data Center/Web Hosting/Transit",
        "isTor": False,
        "isWhitelisted": False,
    }
}


@resp_lib.activate
def test_check_ip_happy_path():
    resp_lib.add(resp_lib.GET, f"{BASE}/check", json=_RESPONSE, status=200)
    client = AbuseIPDB("test-key")
    result = client.check_ip("1.2.3.4")
    assert result["source"] == "abuseipdb"
    assert result["abuse_confidence_score"] == 87
    assert result["total_reports"] == 42
    assert "error" not in result


@resp_lib.activate
def test_check_ip_error():
    resp_lib.add(resp_lib.GET, f"{BASE}/check", status=401)
    client = AbuseIPDB("bad-key")
    result = client.check_ip("1.2.3.4")
    assert result["source"] == "abuseipdb"
    assert "error" in result
