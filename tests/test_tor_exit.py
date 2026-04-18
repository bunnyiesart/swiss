import responses as resp_lib
from lib.tor_exit import TorExitNodes, _cache

_LIST = "# Tor exit nodes\n1.2.3.4\n5.6.7.8\n"


@resp_lib.activate
def test_ip_is_exit_node():
    _cache.set("list", None)
    resp_lib.add(resp_lib.GET, "https://check.torproject.org/torbulkexitlist",
                 body=_LIST, status=200)
    client = TorExitNodes()
    result = client.check_ip("1.2.3.4")
    assert result["source"] == "tor_exit"
    assert result["is_exit_node"] is True


@resp_lib.activate
def test_ip_not_exit_node():
    _cache.set("list", {"1.2.3.4", "5.6.7.8"})
    client = TorExitNodes()
    result = client.check_ip("9.9.9.9")
    assert result["is_exit_node"] is False
