import responses as resp_lib
from lib.cisa_kev import CISAKEVClient, _URL, _cache

_FEED = {
    "title": "CISA KEV",
    "catalogVersion": "2026.07.01",
    "dateReleased": "2026-07-01T00:00:00Z",
    "count": 1,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 contains a remote code execution vulnerability.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        }
    ],
}


def setup_function():
    _cache._store.clear()


@resp_lib.activate
def test_lookup_found():
    resp_lib.add(resp_lib.GET, _URL, json=_FEED, status=200)
    client = CISAKEVClient()
    result = client.lookup("CVE-2021-44228")
    assert result["source"] == "cisa_kev"
    assert result["found"] is True
    assert result["cve_id"] == "CVE-2021-44228"
    assert result["vendor_project"] == "Apache"
    assert result["product"] == "Log4j2"
    assert result["known_ransomware_use"] == "Known"
    assert "error" not in result


@resp_lib.activate
def test_lookup_not_found():
    resp_lib.add(resp_lib.GET, _URL, json=_FEED, status=200)
    client = CISAKEVClient()
    result = client.lookup("CVE-2099-9999")
    assert result["source"] == "cisa_kev"
    assert result["found"] is False
    assert "error" not in result


@resp_lib.activate
def test_lookup_case_insensitive():
    resp_lib.add(resp_lib.GET, _URL, json=_FEED, status=200)
    client = CISAKEVClient()
    result = client.lookup("cve-2021-44228")
    assert result["found"] is True


@resp_lib.activate
def test_cache_prevents_second_request():
    resp_lib.add(resp_lib.GET, _URL, json=_FEED, status=200)
    client = CISAKEVClient()
    client.lookup("CVE-2021-44228")
    client.lookup("CVE-2021-44228")
    assert len(resp_lib.calls) == 1


@resp_lib.activate
def test_network_error():
    resp_lib.add(resp_lib.GET, _URL, body=Exception("timeout"))
    client = CISAKEVClient()
    result = client.lookup("CVE-2021-44228")
    assert result["source"] == "cisa_kev"
    assert "error" in result
