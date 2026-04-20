import socket
from unittest.mock import MagicMock, patch

from lib.exposure import ExposureChecker


def _mock_socket(banner: bytes = b""):
    sock = MagicMock()
    sock.__enter__ = lambda s: s
    sock.__exit__ = MagicMock(return_value=False)
    sock.recv.return_value = banner
    return sock


def test_probe_reachable_no_banner():
    client = ExposureChecker()
    with patch("lib.exposure.socket.create_connection", return_value=_mock_socket()):
        result = client.probe("example.com", 443)
    assert result["source"] == "exposure"
    assert result["reachable"] is True
    assert result["port"] == 443
    assert result["banner"] == ""
    assert "latency_ms" in result
    assert "error" not in result


def test_probe_reachable_with_banner():
    client = ExposureChecker()
    with patch("lib.exposure.socket.create_connection", return_value=_mock_socket(b"SSH-2.0-OpenSSH_8.9")):
        result = client.probe("1.2.3.4", 22)
    assert result["reachable"] is True
    assert result["banner"] == "SSH-2.0-OpenSSH_8.9"


def test_probe_connection_refused():
    client = ExposureChecker()
    with patch("lib.exposure.socket.create_connection", side_effect=ConnectionRefusedError("refused")):
        result = client.probe("1.2.3.4", 9999)
    assert result["source"] == "exposure"
    assert result["reachable"] is False
    assert "error" in result


def test_probe_timeout():
    client = ExposureChecker()
    with patch("lib.exposure.socket.create_connection", side_effect=socket.timeout("timed out")):
        result = client.probe("10.0.0.1", 80)
    assert result["reachable"] is False
    assert "error" in result


def test_probe_banner_timeout_is_ok():
    sock = _mock_socket()
    sock.recv.side_effect = socket.timeout
    client = ExposureChecker()
    with patch("lib.exposure.socket.create_connection", return_value=sock):
        result = client.probe("example.com", 80)
    assert result["reachable"] is True
    assert result["banner"] == ""
