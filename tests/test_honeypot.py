from unittest.mock import patch
import socket

from lib.honeypot import ProjectHoneypot


def test_check_ip_not_listed():
    client = ProjectHoneypot("abcdefghijkl")
    with patch("lib.honeypot.socket.gethostbyname", side_effect=socket.gaierror):
        result = client.check_ip("1.2.3.4")
    assert result["source"] == "honeypot"
    assert result["listed"] is False
    assert "error" not in result


def test_check_ip_listed():
    client = ProjectHoneypot("abcdefghijkl")
    with patch("lib.honeypot.socket.gethostbyname", return_value="127.10.50.4"):
        result = client.check_ip("1.2.3.4")
    assert result["source"] == "honeypot"
    assert result["listed"] is True
    assert result["days_since_last"] == 10
    assert result["threat_score"] == 50
    assert "comment_spammer" in result["visitor_types"]


def test_invalid_key_format():
    client = ProjectHoneypot("BADKEY123")
    result = client.check_ip("1.2.3.4")
    assert result["source"] == "honeypot"
    assert result["error"] == "invalid_api_key_format"


def test_ipv6_not_supported():
    client = ProjectHoneypot("abcdefghijkl")
    result = client.check_ip("2001:db8::1")
    assert result["error"] == "ipv6_not_supported"


def test_empty_key():
    client = ProjectHoneypot("")
    result = client.check_ip("1.2.3.4")
    assert result["error"] == "not_configured"
