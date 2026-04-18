import responses as resp_lib
from lib.feodo import FeodoTracker, _cache

_BLOCKLIST = [
    {"ip_address": "1.2.3.4", "port": 443, "malware": "Dridex", "status": "online"},
    {"ip_address": "5.6.7.8", "port": 80,  "malware": "Trickbot", "status": "offline"},
]


@resp_lib.activate
def test_ip_listed():
    _cache.set("list", None)  # clear cache
    resp_lib.add(resp_lib.GET, "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                 json=_BLOCKLIST, status=200)
    client = FeodoTracker()
    result = client.check_ip("1.2.3.4")
    assert result["source"] == "feodo"
    assert result["listed"] is True
    assert result["malware"] == "Dridex"


@resp_lib.activate
def test_ip_not_listed():
    _cache.set("list", _BLOCKLIST)
    client = FeodoTracker()
    result = client.check_ip("9.9.9.9")
    assert result["listed"] is False


@resp_lib.activate
def test_fetch_error():
    _cache.set("list", None)
    resp_lib.add(resp_lib.GET, "https://feodotracker.abuse.ch/downloads/ipblocklist.json", status=503)
    client = FeodoTracker()
    result = client.check_ip("1.2.3.4")
    assert "error" in result
