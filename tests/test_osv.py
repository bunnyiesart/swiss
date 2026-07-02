import responses as resp_lib
from lib.osv import OSVClient, BASE

_HIT = {
    "vulns": [
        {
            "id": "GHSA-jfh8-c2jp-hdp9",
            "summary": "Remote code execution in Log4j2",
            "affected": [
                {
                    "package": {"name": "log4j-core", "ecosystem": "Maven"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}],
                },
                {
                    "package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]}],
                },
            ],
        }
    ]
}

_MISS = {"vulns": []}


@resp_lib.activate
def test_lookup_found():
    resp_lib.add(resp_lib.POST, BASE, json=_HIT, status=200)
    client = OSVClient()
    result = client.lookup("CVE-2021-44228")
    assert result["source"] == "osv"
    assert result["found"] is True
    assert "GHSA-jfh8-c2jp-hdp9" in result["osv_ids"]
    assert result["summary"] == "Remote code execution in Log4j2"
    assert len(result["packages"]) == 2
    assert result["packages"][0]["name"] == "log4j-core"
    assert result["packages"][0]["ecosystem"] == "Maven"
    assert result["packages"][0]["fixed"] == "2.15.0"
    assert "error" not in result


@resp_lib.activate
def test_lookup_not_found():
    resp_lib.add(resp_lib.POST, BASE, json=_MISS, status=200)
    client = OSVClient()
    result = client.lookup("CVE-2099-9999")
    assert result["source"] == "osv"
    assert result["found"] is False
    assert "error" not in result


@resp_lib.activate
def test_lookup_uppercases_cve():
    resp_lib.add(resp_lib.POST, BASE, json=_HIT, status=200)
    client = OSVClient()
    client.lookup("cve-2021-44228")
    import json
    body = json.loads(resp_lib.calls[0].request.body)
    assert body["cve_id"] == "CVE-2021-44228"


@resp_lib.activate
def test_network_error():
    resp_lib.add(resp_lib.POST, BASE, body=Exception("timeout"))
    client = OSVClient()
    result = client.lookup("CVE-2021-44228")
    assert result["source"] == "osv"
    assert "error" in result
