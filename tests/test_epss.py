import responses as resp_lib
from lib.epss import EPSSClient, BASE

_HIT = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 1,
    "offset": 0,
    "limit": 100,
    "data": [{"cve": "CVE-2021-44228", "epss": "0.97566", "percentile": "0.99997", "date": "2026-07-01"}],
}

_MISS = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 0,
    "offset": 0,
    "limit": 100,
    "data": [],
}


@resp_lib.activate
def test_lookup_found():
    resp_lib.add(resp_lib.GET, BASE, json=_HIT, status=200)
    client = EPSSClient()
    result = client.lookup("CVE-2021-44228")
    assert result["source"] == "epss"
    assert result["found"] is True
    assert result["cve_id"] == "CVE-2021-44228"
    assert result["epss_score"] == 0.97566
    assert result["percentile"] == 0.99997
    assert result["date"] == "2026-07-01"
    assert "error" not in result


@resp_lib.activate
def test_lookup_not_found():
    resp_lib.add(resp_lib.GET, BASE, json=_MISS, status=200)
    client = EPSSClient()
    result = client.lookup("CVE-2099-9999")
    assert result["source"] == "epss"
    assert result["found"] is False
    assert "error" not in result


@resp_lib.activate
def test_lookup_uppercases_cve():
    resp_lib.add(resp_lib.GET, BASE, json=_HIT, status=200)
    client = EPSSClient()
    client.lookup("cve-2021-44228")
    assert "CVE-2021-44228" in resp_lib.calls[0].request.url


@resp_lib.activate
def test_network_error():
    resp_lib.add(resp_lib.GET, BASE, body=Exception("timeout"))
    client = EPSSClient()
    result = client.lookup("CVE-2021-44228")
    assert result["source"] == "epss"
    assert "error" in result
