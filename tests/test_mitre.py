import json
from unittest.mock import patch, MagicMock

import responses as resp_lib

from lib.mitre import MITREClient, _build_index, _cache

_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--1",
            "name": "PowerShell",
            "description": "Adversaries may abuse PowerShell commands.",
            "x_mitre_platforms": ["Windows"],
            "x_mitre_detection": "Monitor process execution of PowerShell.",
            "x_mitre_is_subtechnique": True,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1059.001",
                 "url": "https://attack.mitre.org/techniques/T1059/001/"}
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--2",
            "name": "Phishing",
            "description": "Adversaries may send phishing messages.",
            "x_mitre_platforms": ["Windows", "macOS", "Linux"],
            "x_mitre_detection": "Monitor for suspicious emails.",
            "x_mitre_is_subtechnique": False,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566",
                 "url": "https://attack.mitre.org/techniques/T1566/"}
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--revoked",
            "name": "OldTechnique",
            "description": "This was revoked.",
            "revoked": True,
            "kill_chain_phases": [],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T9999"}
            ],
        },
        {
            "type": "course-of-action",
            "id": "course-of-action--1",
            "name": "Disable PowerShell",
        },
        {
            "type": "relationship",
            "relationship_type": "mitigates",
            "source_ref": "course-of-action--1",
            "target_ref": "attack-pattern--1",
        },
    ],
}


def _patched_index():
    """Return a fresh index from the fake bundle, bypassing the TTL cache."""
    _cache._store.clear()
    with patch("lib.mitre.requests.Session") as mock_session_cls:
        mock_resp = MagicMock()
        mock_resp.json.return_value = _BUNDLE
        mock_resp.raise_for_status.return_value = None
        mock_session_cls.return_value.get.return_value = mock_resp
        return MITREClient()


def test_lookup_by_technique_id():
    _cache._store.clear()
    with patch("lib.mitre.requests.Session") as mock_session_cls:
        mock_resp = MagicMock()
        mock_resp.json.return_value = _BUNDLE
        mock_resp.raise_for_status.return_value = None
        mock_session_cls.return_value.get.return_value = mock_resp

        client = MITREClient()
        result = client.lookup("T1059.001")

    assert result["source"] == "mitre"
    assert result["found"] is True
    assert result["id"] == "T1059.001"
    assert result["name"] == "PowerShell"
    assert "execution" in result["tactics"]
    assert "Windows" in result["platforms"]
    assert "Disable PowerShell" in result["mitigations"]
    assert result["url"] == "https://attack.mitre.org/techniques/T1059/001/"
    assert "error" not in result


def test_lookup_by_name():
    _cache._store.clear()
    with patch("lib.mitre.requests.Session") as mock_session_cls:
        mock_resp = MagicMock()
        mock_resp.json.return_value = _BUNDLE
        mock_resp.raise_for_status.return_value = None
        mock_session_cls.return_value.get.return_value = mock_resp

        client = MITREClient()
        result = client.lookup("powershell")

    assert result["source"] == "mitre"
    assert result["found"] is True
    assert result["id"] == "T1059.001"


def test_lookup_case_insensitive_id():
    _cache._store.clear()
    with patch("lib.mitre.requests.Session") as mock_session_cls:
        mock_resp = MagicMock()
        mock_resp.json.return_value = _BUNDLE
        mock_resp.raise_for_status.return_value = None
        mock_session_cls.return_value.get.return_value = mock_resp

        client = MITREClient()
        result = client.lookup("t1566")

    assert result["found"] is True
    assert result["id"] == "T1566"
    assert result["name"] == "Phishing"


def test_lookup_not_found():
    _cache._store.clear()
    with patch("lib.mitre.requests.Session") as mock_session_cls:
        mock_resp = MagicMock()
        mock_resp.json.return_value = _BUNDLE
        mock_resp.raise_for_status.return_value = None
        mock_session_cls.return_value.get.return_value = mock_resp

        client = MITREClient()
        result = client.lookup("T9999")

    assert result["source"] == "mitre"
    assert result["found"] is False
    assert "error" not in result


def test_revoked_technique_excluded():
    _cache._store.clear()
    with patch("lib.mitre.requests.Session") as mock_session_cls:
        mock_resp = MagicMock()
        mock_resp.json.return_value = _BUNDLE
        mock_resp.raise_for_status.return_value = None
        mock_session_cls.return_value.get.return_value = mock_resp

        client = MITREClient()
        result = client.lookup("OldTechnique")

    assert result["found"] is False


def test_fetch_error():
    _cache._store.clear()
    with patch("lib.mitre.requests.Session") as mock_session_cls:
        mock_session_cls.return_value.get.side_effect = Exception("network error")
        client = MITREClient()
        result = client.lookup("T1059.001")

    assert result["source"] == "mitre"
    assert "error" in result


def test_build_index_structure():
    idx = _build_index(_BUNDLE)
    assert "T1059.001" in idx
    assert "powershell" in idx
    assert "T1566" in idx
    assert "phishing" in idx
    assert "T9999" not in idx  # revoked
    obj, mitigations = idx["T1059.001"]
    assert obj["name"] == "PowerShell"
    assert "Disable PowerShell" in mitigations
