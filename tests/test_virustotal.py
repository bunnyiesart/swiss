import responses as resp_lib
from lib.virustotal import VirusTotal

BASE = "https://www.virustotal.com/api/v3"

_IP_RESPONSE = {
    "data": {"attributes": {
        "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 10},
        "country": "US", "asn": 12345, "as_owner": "Example ISP", "reputation": -10, "tags": ["scanner"],
    }}
}

_DOMAIN_RESPONSE = {
    "data": {"attributes": {
        "last_analysis_stats": {"malicious": 3, "suspicious": 0, "harmless": 70, "undetected": 5},
        "registrar": "Example Registrar", "reputation": -5, "categories": {}, "tags": [],
    }}
}

_HASH_RESPONSE = {
    "data": {"attributes": {
        "last_analysis_stats": {"malicious": 20, "suspicious": 2, "harmless": 0, "undetected": 5},
        "meaningful_name": "malware.exe", "type_description": "Win32 EXE", "size": 12345,
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "first_submission_date": 1704067200,
        "last_submission_date":  1704153600,
        "tags": ["trojan"],
    }}
}


@resp_lib.activate
def test_check_ip_happy_path():
    resp_lib.add(resp_lib.GET, f"{BASE}/ip_addresses/1.2.3.4", json=_IP_RESPONSE, status=200)
    vt = VirusTotal("test-key")
    result = vt.check_ip("1.2.3.4")
    assert result["source"] == "virustotal"
    assert result["malicious"] == 5
    assert result["country"] == "US"
    assert "error" not in result


@resp_lib.activate
def test_check_ip_error():
    resp_lib.add(resp_lib.GET, f"{BASE}/ip_addresses/1.2.3.4", status=403)
    vt = VirusTotal("bad-key")
    result = vt.check_ip("1.2.3.4")
    assert result["source"] == "virustotal"
    assert "error" in result


@resp_lib.activate
def test_check_domain_happy_path():
    resp_lib.add(resp_lib.GET, f"{BASE}/domains/evil.com", json=_DOMAIN_RESPONSE, status=200)
    vt = VirusTotal("test-key")
    result = vt.check_domain("evil.com")
    assert result["source"] == "virustotal"
    assert result["malicious"] == 3
    assert "error" not in result


@resp_lib.activate
def test_check_hash_happy_path():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    resp_lib.add(resp_lib.GET, f"{BASE}/files/{h}", json=_HASH_RESPONSE, status=200)
    vt = VirusTotal("test-key")
    result = vt.check_hash(h)
    assert result["source"] == "virustotal"
    assert result["malicious"] == 20
    assert result["name"] == "malware.exe"
    assert result["first_seen"] == 1704067200
    assert result["last_seen"]  == 1704153600
    assert "error" not in result


@resp_lib.activate
def test_check_url_happy_path():
    import base64
    url = "https://evil.com/path"
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    resp_lib.add(resp_lib.GET, f"{BASE}/urls/{url_id}", json={
        "data": {"attributes": {
            "last_analysis_stats": {"malicious": 2, "suspicious": 0, "harmless": 50, "undetected": 5},
            "url": url, "title": "Evil Site", "last_final_url": "https://evil.com/redirect",
            "tags": [],
        }}
    }, status=200)
    vt = VirusTotal("test-key")
    result = vt.check_url(url)
    assert result["source"] == "virustotal"
    assert result["malicious"] == 2
    assert result["title"] == "Evil Site"
    assert result["final_url"] == "https://evil.com/redirect"
    assert "error" not in result
