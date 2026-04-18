import ipaddress
import re

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:\-.]){5}[0-9a-fA-F]{2}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_URL_SCHEMES = ("http://", "https://", "ftp://")


def detect_ioc_type(value: str) -> str:
    """Detect the type of an IOC string.

    Detection order is most-specific first to avoid false matches.

    Returns one of: ip, domain, url, md5, sha1, sha256, cve, mac, email, unknown.
    """
    v = value.strip()

    if _CVE_RE.match(v):
        return "cve"
    if _MD5_RE.match(v):
        return "md5"
    if _SHA1_RE.match(v):
        return "sha1"
    if _SHA256_RE.match(v):
        return "sha256"
    if _MAC_RE.match(v):
        return "mac"

    try:
        addr = ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass

    if _EMAIL_RE.match(v):
        return "email"

    if any(v.lower().startswith(s) for s in _URL_SCHEMES):
        return "url"

    if _DOMAIN_RE.match(v):
        return "domain"

    return "unknown"


def _normalize_ioc(value: str) -> str:
    """Re-fang a defanged IOC for processing.

    Examples:
        hxxps://evil[.]com  ->  https://evil.com
        evil[.]com          ->  evil.com
        user[@]evil.com     ->  user@evil.com
    """
    v = value.strip()
    v = re.sub(r"hxxps", "https", v, flags=re.IGNORECASE)
    v = re.sub(r"hxxp", "http", v, flags=re.IGNORECASE)
    v = v.replace("[.]", ".")
    v = v.replace("(.)", ".")
    v = v.replace("[dot]", ".")
    v = v.replace("(dot)", ".")
    v = v.replace("[at]", "@")
    v = v.replace("[@]", "@")
    return v
