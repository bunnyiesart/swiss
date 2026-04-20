import pytest
from lib.config import _key, _key_pair, _private_cfg, _unconfigured, _blacklist_configs


def test_key_returns_value_when_enabled(mock_config):
    assert _key("virustotal") == "vt-test-key"


def test_key_returns_none_when_disabled(mock_config, monkeypatch):
    import lib.config as cfg_mod
    cfg = {**cfg_mod._CFG, "virustotal": {"enabled": False}}
    monkeypatch.setattr(cfg_mod, "_CFG", cfg)
    assert _key("virustotal") is None


def test_key_returns_none_when_env_var_absent(mock_config, monkeypatch):
    monkeypatch.delenv("SWISS_VIRUSTOTAL_API_KEY")
    assert _key("virustotal") is None


def test_key_returns_none_for_missing_service(mock_config, monkeypatch):
    monkeypatch.delenv("SWISS_VIRUSTOTAL_API_KEY", raising=False)
    assert _key("nonexistent") is None


def test_key_pair_returns_tuple(mock_config):
    pair = _key_pair("ibm_xforce")
    assert pair == ("xf-key", "xf-pass")


def test_key_pair_returns_none_when_disabled(mock_config, monkeypatch):
    import lib.config as cfg_mod
    cfg = {**cfg_mod._CFG, "ibm_xforce": {"enabled": False}}
    monkeypatch.setattr(cfg_mod, "_CFG", cfg)
    assert _key_pair("ibm_xforce") is None


def test_private_cfg_returns_none_when_disabled(mock_config):
    assert _private_cfg("misp") is None


def test_private_cfg_returns_dict_when_enabled(mock_config, monkeypatch):
    import lib.config as cfg_mod
    cfg = {**cfg_mod._CFG, "misp": {"url": "https://misp.test", "enabled": True, "verify_ssl": False}}
    monkeypatch.setattr(cfg_mod, "_CFG", cfg)
    result = _private_cfg("misp")
    assert result is not None
    assert result["url"] == "https://misp.test"
    assert result["api_key"] == "misp-key"
    assert result["verify_ssl"] is False


def test_secrets_not_read_from_config_file(mock_config, monkeypatch):
    import lib.config as cfg_mod
    cfg = {**cfg_mod._CFG, "virustotal": {"enabled": True, "api_key": "should-be-ignored"}}
    monkeypatch.setattr(cfg_mod, "_CFG", cfg)
    assert _key("virustotal") == "vt-test-key"


def test_key_from_env_var_is_sole_source(mock_config, monkeypatch):
    monkeypatch.setenv("SWISS_VIRUSTOTAL_API_KEY", "override-key")
    assert _key("virustotal") == "override-key"


def test_unconfigured_returns_error_dict():
    sentinel = _unconfigured("virustotal")
    result = sentinel.check_ip("1.2.3.4")
    assert result == {"source": "virustotal", "error": "not_configured"}


def test_unconfigured_any_method():
    sentinel = _unconfigured("foo")
    assert sentinel.check_domain("evil.com") == {"source": "foo", "error": "not_configured"}
    assert sentinel.check_hash("abc") == {"source": "foo", "error": "not_configured"}


def test_blacklist_configs_returns_enabled(mock_config):
    bl = _blacklist_configs()
    assert len(bl) == 1
    assert bl[0]["url"] == "https://bl.test/list.txt"
