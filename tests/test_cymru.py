from unittest.mock import patch

from lib.cymru import Cymru


def _txt(data: str) -> dict:
    return {
        "source": "dns_doh", "status_code": 0, "status": "NOERROR",
        "answers": [{"name": ".", "type": 16, "data": f'"{data}"', "ttl": 300}],
    }


def _nxdomain() -> dict:
    return {"source": "dns_doh", "status_code": 3, "status": "NXDOMAIN", "answers": []}


def _doh_error() -> dict:
    return {"source": "dns_doh", "error": "connection refused"}


def test_lookup_asn_happy_path():
    client = Cymru()
    origin = _txt("15169 | 8.8.8.0/24 | US | arin | 1992-12-01")
    org = _txt("15169 | 2010-06-04 | ARIN | arin | Google LLC")

    with patch.object(client._doh, "resolve", side_effect=[origin, org]):
        result = client.lookup_asn("8.8.8.8")

    assert result["source"] == "cymru"
    assert result["found"] is True
    assert result["asn"] == "15169"
    assert result["prefix"] == "8.8.8.0/24"
    assert result["country"] == "US"
    assert result["registry"] == "arin"
    assert result["allocated"] == "1992-12-01"
    assert result["org"] == "Google LLC"
    assert "error" not in result


def test_lookup_asn_nxdomain():
    client = Cymru()
    with patch.object(client._doh, "resolve", return_value=_nxdomain()):
        result = client.lookup_asn("192.0.2.1")
    assert result["source"] == "cymru"
    assert result["found"] is False
    assert "error" not in result


def test_lookup_asn_invalid_ip():
    client = Cymru()
    result = client.lookup_asn("not-an-ip")
    assert result["source"] == "cymru"
    assert result["error"] == "invalid_ip"


def test_lookup_asn_doh_error():
    client = Cymru()
    with patch.object(client._doh, "resolve", return_value=_doh_error()):
        result = client.lookup_asn("1.2.3.4")
    assert result["source"] == "cymru"
    assert "error" in result


def test_lookup_asn_ipv6():
    client = Cymru()
    origin = _txt("15169 | 2001:db8::/32 | US | arin | 2002-01-01")
    org = _txt("15169 | 2010-06-04 | ARIN | arin | Google LLC")

    with patch.object(client._doh, "resolve", side_effect=[origin, org]) as mock_resolve:
        result = client.lookup_asn("2001:db8::1")

    assert result["source"] == "cymru"
    assert result["found"] is True
    # IPv6 uses origin6.asn.cymru.com
    first_call_host = mock_resolve.call_args_list[0][0][0]
    assert "origin6.asn.cymru.com" in first_call_host


def test_check_hash_found():
    client = Cymru()
    md5 = "a" * 32
    with patch.object(client._doh, "resolve", return_value=_txt("1430276220 | 100")):
        result = client.check_hash(md5)
    assert result["source"] == "cymru"
    assert result["found"] is True
    assert result["detection_pct"] == 100
    assert result["last_seen"].startswith("2015-04-29T")
    assert result["last_seen"].endswith("Z")
    assert "error" not in result


def test_check_hash_not_found():
    client = Cymru()
    md5 = "b" * 32
    with patch.object(client._doh, "resolve", return_value=_nxdomain()):
        result = client.check_hash(md5)
    assert result["source"] == "cymru"
    assert result["found"] is False
    assert "error" not in result


def test_check_hash_non_md5_sha1():
    client = Cymru()
    result = client.check_hash("a" * 40)
    assert result["source"] == "cymru"
    assert result["error"] == "md5_only"


def test_check_hash_non_md5_sha256():
    client = Cymru()
    result = client.check_hash("a" * 64)
    assert result["source"] == "cymru"
    assert result["error"] == "md5_only"
