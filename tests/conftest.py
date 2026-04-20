import pytest


TEST_CONFIG = {
    "virustotal":        {"enabled": True,  "favorite": True},
    "abuseipdb":         {"enabled": True,  "favorite": True},
    "greynoise":         {"enabled": True,  "favorite": True},
    "shodan":            {"enabled": True,  "favorite": True},
    "ipinfo":            {"enabled": True,  "favorite": False},
    "ibm_xforce":        {"enabled": True,  "favorite": False},
    "alienvault":        {"enabled": True,  "favorite": False},
    "urlscan":           {"enabled": True,  "favorite": True},
    "honeypot":          {"enabled": True,  "favorite": False},
    "malwarebazaar":     {"enabled": True,  "favorite": True},
    "threatfox":         {"enabled": True,  "favorite": False},
    "urlhaus":           {"enabled": True,  "favorite": False},
    "misp":              {"url": "https://misp.test",    "enabled": False, "favorite": True,  "verify_ssl": False},
    "graylog":           {"url": "https://graylog.test", "enabled": False, "favorite": False, "verify_ssl": False},
    "dfir_iris":         {"url": "https://iris.test",    "enabled": False, "favorite": False, "verify_ssl": False},
    "wazuh":             {"url": "https://wazuh.test",   "enabled": False, "favorite": False, "verify_ssl": False},
    "custom_blacklists": [{"name": "test-bl", "url": "https://bl.test/list.txt", "enabled": True, "favorite": False}],
}

TEST_SECRETS = {
    "SWISS_VIRUSTOTAL_API_KEY":    "vt-test-key",
    "SWISS_ABUSEIPDB_API_KEY":     "abuse-test-key",
    "SWISS_GREYNOISE_API_KEY":     "gn-test-key",
    "SWISS_SHODAN_API_KEY":        "shodan-test-key",
    "SWISS_IPINFO_API_KEY":        "ipinfo-test-key",
    "SWISS_IBM_XFORCE_API_KEY":    "xf-key",
    "SWISS_IBM_XFORCE_API_PASSWORD": "xf-pass",
    "SWISS_ALIENVAULT_API_KEY":    "av-key",
    "SWISS_URLSCAN_API_KEY":       "us-key",
    "SWISS_HONEYPOT_API_KEY":      "abcdefghijkl",
    "SWISS_MISP_API_KEY":          "misp-key",
    "SWISS_GRAYLOG_USERNAME":      "admin",
    "SWISS_GRAYLOG_PASSWORD":      "pass",
    "SWISS_DFIR_IRIS_API_KEY":     "iris-key",
    "SWISS_WAZUH_USERNAME":        "admin",
    "SWISS_WAZUH_PASSWORD":        "pass",
}


@pytest.fixture(autouse=False)
def mock_config(monkeypatch):
    import lib.config as cfg_mod
    import os
    monkeypatch.setattr(cfg_mod, "_CFG", TEST_CONFIG)
    for key in list(os.environ):
        if key.startswith("SWISS_"):
            monkeypatch.delenv(key)
    for key, val in TEST_SECRETS.items():
        monkeypatch.setenv(key, val)
    return TEST_CONFIG
