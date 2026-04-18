from lib.eventid import EventIDClient


def test_lookup_known_windows_event():
    client = EventIDClient()
    result = client.lookup("4624", "windows")
    assert result["source"] == "eventid"
    assert result["found"] is True
    assert result["event_id"] == "4624"
    assert result["platform"] == "windows"
    assert "logged on" in result["name"].lower()
    assert "error" not in result


def test_lookup_known_sysmon_event():
    client = EventIDClient()
    result = client.lookup(1, "sysmon")
    assert result["found"] is True
    assert "Process Create" in result["name"]


def test_lookup_not_found():
    client = EventIDClient()
    result = client.lookup("99999", "windows")
    assert result["found"] is False
    assert "error" not in result


def test_lookup_unknown_platform():
    client = EventIDClient()
    result = client.lookup("4624", "unknown_platform")
    assert result["found"] is False


def test_lookup_string_or_int_id():
    client = EventIDClient()
    r1 = client.lookup("4624")
    r2 = client.lookup(4624)
    assert r1["name"] == r2["name"]
