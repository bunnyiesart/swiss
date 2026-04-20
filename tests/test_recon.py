from unittest.mock import patch, MagicMock

import responses as resp_lib

from lib.recon import BGPViewClient, CRTShClient, DNSRecords

_CRTSH_RESPONSE = [
    {"name_value": "example.com\nwww.example.com\nmail.example.com", "issuer_name": "Let's Encrypt"},
    {"name_value": "*.example.com", "issuer_name": "DigiCert"},
]

_BGPVIEW_RESPONSE = {
    "status": "ok",
    "data": {
        "ip": "8.8.8.8",
        "prefixes": [
            {
                "prefix": "8.8.8.0/24",
                "asn": {"asn": 15169, "description": "Google LLC", "country_code": "US"},
                "country_code": "US",
            }
        ],
        "rir_allocation": {"rir_name": "ARIN", "date_allocated": "1992-12-01"},
    },
}


# ── CRTShClient ────────────────────────────────────────────────────────────────

@resp_lib.activate
def test_crtsh_lookup_found():
    resp_lib.add(resp_lib.GET, "https://crt.sh/", json=_CRTSH_RESPONSE, status=200)
    client = CRTShClient()
    result = client.lookup("example.com")
    assert result["source"] == "crt_sh"
    assert result["found"] is True
    assert result["cert_count"] == 2
    assert "example.com" in result["subdomains"]
    assert "www.example.com" in result["subdomains"]
    assert "mail.example.com" in result["subdomains"]
    assert "error" not in result


@resp_lib.activate
def test_crtsh_lookup_empty():
    resp_lib.add(resp_lib.GET, "https://crt.sh/", json=[], status=200)
    client = CRTShClient()
    result = client.lookup("notfound.example")
    assert result["source"] == "crt_sh"
    assert result["found"] is False
    assert result["cert_count"] == 0
    assert "error" not in result


@resp_lib.activate
def test_crtsh_lookup_error():
    resp_lib.add(resp_lib.GET, "https://crt.sh/", status=503)
    client = CRTShClient()
    result = client.lookup("example.com")
    assert result["source"] == "crt_sh"
    assert "error" in result


def test_crtsh_wildcard_stripped():
    with resp_lib.RequestsMock() as rsps:
        rsps.add(resp_lib.GET, "https://crt.sh/", json=[{"name_value": "*.example.com"}], status=200)
        client = CRTShClient()
        result = client.lookup("example.com")
    assert "example.com" in result["subdomains"]
    assert not any(s.startswith("*.") for s in result["subdomains"])


# ── BGPViewClient ──────────────────────────────────────────────────────────────

@resp_lib.activate
def test_bgpview_lookup_ip_found():
    resp_lib.add(resp_lib.GET, "https://api.bgpview.io/ip/8.8.8.8", json=_BGPVIEW_RESPONSE, status=200)
    client = BGPViewClient()
    result = client.lookup_ip("8.8.8.8")
    assert result["source"] == "bgpview"
    assert result["found"] is True
    assert len(result["prefixes"]) == 1
    assert result["prefixes"][0]["asn"] == 15169
    assert result["prefixes"][0]["org"] == "Google LLC"
    assert result["rir"] == "ARIN"
    assert result["allocated"] == "1992-12-01"
    assert "error" not in result


@resp_lib.activate
def test_bgpview_lookup_ip_not_found():
    resp_lib.add(resp_lib.GET, "https://api.bgpview.io/ip/192.0.2.1", status=404)
    client = BGPViewClient()
    result = client.lookup_ip("192.0.2.1")
    assert result["source"] == "bgpview"
    assert result["found"] is False
    assert "error" not in result


@resp_lib.activate
def test_bgpview_lookup_error():
    resp_lib.add(resp_lib.GET, "https://api.bgpview.io/ip/1.2.3.4", status=500)
    client = BGPViewClient()
    result = client.lookup_ip("1.2.3.4")
    assert result["source"] == "bgpview"
    assert "error" in result


# ── DNSRecords ─────────────────────────────────────────────────────────────────

def _doh_answer(data: str, record_type: str = "A") -> dict:
    return {
        "source": "dns_doh", "status_code": 0, "status": "NOERROR",
        "answers": [{"name": ".", "type": 1, "data": data, "ttl": 300}],
    }


def _doh_empty() -> dict:
    return {"source": "dns_doh", "status_code": 3, "status": "NXDOMAIN", "answers": []}


def test_dns_records_lookup():
    client = DNSRecords()

    def resolve_side_effect(domain, rt):
        if rt == "A":
            return _doh_answer("1.2.3.4")
        if rt == "MX":
            return _doh_answer("10 mail.example.com.")
        return _doh_empty()

    with patch.object(client._doh, "resolve", side_effect=resolve_side_effect):
        result = client.lookup("example.com")

    assert result["source"] == "dns"
    assert "A" in result["records"]
    assert "MX" in result["records"]
    assert "AAAA" not in result["records"]
    assert "error" not in result


def test_dns_ptr_lookup():
    client = DNSRecords()
    with patch.object(client._doh, "resolve", return_value=_doh_answer("dns.google.")):
        result = client.lookup_ptr("8.8.8.8")
    assert result["source"] == "dns"
    assert result["ip"] == "8.8.8.8"
    assert "dns.google." in result["ptr"]
    assert "error" not in result


def test_dns_ptr_no_record():
    client = DNSRecords()
    with patch.object(client._doh, "resolve", return_value=_doh_empty()):
        result = client.lookup_ptr("192.0.2.1")
    assert result["source"] == "dns"
    assert result["ptr"] == []
    assert "error" not in result
