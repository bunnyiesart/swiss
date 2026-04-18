from lib.ioc import _normalize_ioc, detect_ioc_type


def test_detect_ipv4():
    assert detect_ioc_type("1.2.3.4") == "ip"


def test_detect_ipv6():
    assert detect_ioc_type("2001:db8::1") == "ip"


def test_detect_md5():
    assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"


def test_detect_sha1():
    assert detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"


def test_detect_sha256():
    assert detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"


def test_detect_cve():
    assert detect_ioc_type("CVE-2024-12345") == "cve"
    assert detect_ioc_type("cve-2021-44228") == "cve"


def test_detect_mac():
    assert detect_ioc_type("AA:BB:CC:DD:EE:FF") == "mac"
    assert detect_ioc_type("AA-BB-CC-DD-EE-FF") == "mac"


def test_detect_email():
    assert detect_ioc_type("user@evil.com") == "email"


def test_detect_url():
    assert detect_ioc_type("https://evil.com/path") == "url"
    assert detect_ioc_type("http://1.2.3.4/payload") == "url"


def test_detect_domain():
    assert detect_ioc_type("evil.com") == "domain"
    assert detect_ioc_type("sub.evil.co.uk") == "domain"


def test_detect_unknown():
    assert detect_ioc_type("notanindicator") == "unknown"
    assert detect_ioc_type("") == "unknown"


def test_cve_before_sha1():
    # CVE-2024-12345 should be detected as CVE, not as unknown or domain
    assert detect_ioc_type("CVE-2024-12345") == "cve"


def test_normalize_hxxps():
    assert _normalize_ioc("hxxps://evil[.]com") == "https://evil.com"


def test_normalize_hxxp():
    assert _normalize_ioc("hxxp://evil[.]com/path") == "http://evil.com/path"


def test_normalize_dot_brackets():
    assert _normalize_ioc("evil[.]com") == "evil.com"


def test_normalize_at_brackets():
    assert _normalize_ioc("user[@]evil.com") == "user@evil.com"


def test_normalize_dot_parens():
    assert _normalize_ioc("evil(.)com") == "evil.com"


def test_normalize_passthrough():
    assert _normalize_ioc("1.2.3.4") == "1.2.3.4"
