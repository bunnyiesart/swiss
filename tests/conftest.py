import pytest


TEST_CONFIG = {
    "virustotal":        {"api_key": "vt-test-key",    "enabled": True,  "favorite": True},
    "abuseipdb":         {"api_key": "abuse-test-key", "enabled": True,  "favorite": True},
    "greynoise":         {"api_key": "gn-test-key",    "enabled": True,  "favorite": True},
    "shodan":            {"api_key": "shodan-test-key","enabled": True,  "favorite": True},
    "ipinfo":            {"api_key": "ipinfo-test-key","enabled": True,  "favorite": False},
    "ibm_xforce":        {"api_key": "xf-key", "api_password": "xf-pass", "enabled": True, "favorite": False},
    "alienvault":        {"api_key": "av-key",         "enabled": True,  "favorite": False},
    "urlscan":           {"api_key": "us-key",         "enabled": True,  "favorite": True},
    "honeypot":          {"api_key": "abcdefghijkl",   "enabled": True,  "favorite": False},
    "malwarebazaar":     {"api_key": "",               "enabled": True,  "favorite": True},
    "threatfox":         {"api_key": "",               "enabled": True,  "favorite": False},
    "urlhaus":           {"api_key": "",               "enabled": True,  "favorite": False},
    "misp":              {"url": "https://misp.test", "api_key": "misp-key", "enabled": False, "favorite": True, "verify_ssl": False},
    "graylog":           {"url": "https://graylog.test", "username": "admin", "password": "pass", "enabled": False, "favorite": False, "verify_ssl": False},
    "dfir_iris":         {"url": "https://iris.test", "api_key": "iris-key", "enabled": False, "favorite": False, "verify_ssl": False},
    "wazuh":             {"url": "https://wazuh.test", "username": "admin", "password": "pass", "enabled": False, "favorite": False, "verify_ssl": False},
    "custom_blacklists": [{"name": "test-bl", "url": "https://bl.test/list.txt", "enabled": True, "favorite": False}],
}


@pytest.fixture(autouse=False)
def mock_config(monkeypatch):
    import lib.config as cfg_mod
    import os
    monkeypatch.setattr(cfg_mod, "_CFG", TEST_CONFIG)
    for key in list(os.environ):
        if key.startswith("SWISS_"):
            monkeypatch.delenv(key)
    return TEST_CONFIG
