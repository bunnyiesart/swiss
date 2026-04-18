from concurrent.futures import ThreadPoolExecutor, as_completed

from fastmcp import FastMCP

from lib.abuseipdb import AbuseIPDB
from lib.alienvault import AlienVault
from lib.blockchain import BlockchainClient
from lib.cache import TTLCache
from lib.config import (
    _cfg_raw,
    _key,
    _key_pair,
    _private_cfg,
    _unconfigured,
)
from lib.cve import CVEClient
from lib.custom_blacklists import CustomBlacklists
from lib.decode import Decoder
from lib.dfir_iris import DFIRIrisClient
from lib.dns_doh import DNSDoH
from lib.eventid import EventIDClient
from lib.feodo import FeodoTracker
from lib.graylog import GraylogClient
from lib.greynoise import GreyNoise
from lib.honeypot import ProjectHoneypot
from lib.ibm_xforce import IBMXForce
from lib.ioc import _normalize_ioc, detect_ioc_type
from lib.ipinfo import IPInfo
from lib.lolbas import LOLBas
from lib.maclookup import MACLookup
from lib.malwarebazaar import MalwareBazaar
from lib.misp import MISPClient
from lib.shodan import Shodan
from lib.threatfox import ThreatFox
from lib.tor_exit import TorExitNodes
from lib.urlhaus import URLhaus
from lib.urlscan import URLScan
from lib.useragent import UserAgentParser
from lib.virustotal import VirusTotal
from lib.wazuh import WazuhClient
from lib.whois import WHOISClient

mcp = FastMCP("swiss")


# ── Parallel execution ─────────────────────────────────────────────────────────

def _parallel(tasks: dict[str, tuple]) -> dict:
    """Fan out tasks in parallel; silently drop not_configured results."""
    if not tasks:
        return {}
    results = {}
    with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        futures = {executor.submit(fn, *args): name for name, (fn, *args) in tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {"source": name, "error": str(exc)}
            if result.get("error") != "not_configured":
                results[name] = result
    return results


# ── Lazy singletons ────────────────────────────────────────────────────────────

_vt = _abuse = _gn = _shodan = _ipinfo = _xforce = _av = _urlscan = _honeypot = None
_mb = _tf = _uh = None
_misp = _graylog = _iris = _wazuh = None
_blacklists = _whois_c = _cve_c = _mac_c = _ua_c = _evid_c = _lolbas_c = None
_blockchain_c = _decoder = _doh = _feodo = _tor = None


def get_vt():
    global _vt
    if _vt is None:
        k = _key("virustotal")
        _vt = VirusTotal(k) if k else _unconfigured("virustotal")
    return _vt


def get_abuse():
    global _abuse
    if _abuse is None:
        k = _key("abuseipdb")
        _abuse = AbuseIPDB(k) if k else _unconfigured("abuseipdb")
    return _abuse


def get_gn():
    global _gn
    if _gn is None:
        _gn = GreyNoise(_key("greynoise"))  # None = community tier, key = enterprise
    return _gn


def get_shodan():
    global _shodan
    if _shodan is None:
        k = _key("shodan")
        _shodan = Shodan(k) if k else _unconfigured("shodan")
    return _shodan


def get_ipinfo():
    global _ipinfo
    if _ipinfo is None:
        k = _key("ipinfo")
        _ipinfo = IPInfo(k) if k else _unconfigured("ipinfo")
    return _ipinfo


def get_xforce():
    global _xforce
    if _xforce is None:
        pair = _key_pair("ibm_xforce")
        _xforce = IBMXForce(*pair) if pair else _unconfigured("ibm_xforce")
    return _xforce


def get_av():
    global _av
    if _av is None:
        k = _key("alienvault")
        _av = AlienVault(k) if k else _unconfigured("alienvault")
    return _av


def get_urlscan():
    global _urlscan
    if _urlscan is None:
        k = _key("urlscan")
        _urlscan = URLScan(k) if k else _unconfigured("urlscan")
    return _urlscan


def get_honeypot():
    global _honeypot
    if _honeypot is None:
        k = _key("honeypot")
        _honeypot = ProjectHoneypot(k) if k else _unconfigured("honeypot")
    return _honeypot


def get_mb():
    global _mb
    if _mb is None:
        _mb = MalwareBazaar(_key("malwarebazaar"))
    return _mb


def get_tf():
    global _tf
    if _tf is None:
        _tf = ThreatFox(_key("threatfox"))
    return _tf


def get_uh():
    global _uh
    if _uh is None:
        _uh = URLhaus(_key("urlhaus"))
    return _uh


def get_feodo():
    global _feodo
    if _feodo is None:
        _feodo = FeodoTracker()
    return _feodo


def get_tor():
    global _tor
    if _tor is None:
        _tor = TorExitNodes()
    return _tor


def get_misp():
    global _misp
    if _misp is None:
        cfg = _private_cfg("misp")
        _misp = MISPClient(**{k: v for k, v in cfg.items() if k in ("url", "api_key", "verify_ssl")}) \
            if cfg else _unconfigured("misp")
    return _misp


def get_graylog():
    global _graylog
    if _graylog is None:
        cfg = _private_cfg("graylog")
        _graylog = GraylogClient(
            url=cfg["url"], username=cfg["username"], password=cfg["password"], verify_ssl=cfg["verify_ssl"]
        ) if cfg else _unconfigured("graylog")
    return _graylog


def get_iris():
    global _iris
    if _iris is None:
        cfg = _private_cfg("dfir_iris")
        _iris = DFIRIrisClient(url=cfg["url"], api_key=cfg["api_key"], verify_ssl=cfg["verify_ssl"]) \
            if cfg else _unconfigured("dfir_iris")
    return _iris


def get_wazuh():
    global _wazuh
    if _wazuh is None:
        cfg = _private_cfg("wazuh")
        _wazuh = WazuhClient(
            url=cfg["url"], username=cfg["username"], password=cfg["password"], verify_ssl=cfg["verify_ssl"]
        ) if cfg else _unconfigured("wazuh")
    return _wazuh


def get_blacklists():
    global _blacklists
    if _blacklists is None:
        _blacklists = CustomBlacklists()
    return _blacklists


def get_whois():
    global _whois_c
    if _whois_c is None:
        _whois_c = WHOISClient()
    return _whois_c


def get_cve():
    global _cve_c
    if _cve_c is None:
        _cve_c = CVEClient()
    return _cve_c


def get_mac():
    global _mac_c
    if _mac_c is None:
        _mac_c = MACLookup()
    return _mac_c


def get_ua():
    global _ua_c
    if _ua_c is None:
        _ua_c = UserAgentParser()
    return _ua_c


def get_evid():
    global _evid_c
    if _evid_c is None:
        _evid_c = EventIDClient()
    return _evid_c


def get_lolbas():
    global _lolbas_c
    if _lolbas_c is None:
        _lolbas_c = LOLBas()
    return _lolbas_c


def get_blockchain():
    global _blockchain_c
    if _blockchain_c is None:
        _blockchain_c = BlockchainClient()
    return _blockchain_c


def get_decoder():
    global _decoder
    if _decoder is None:
        _decoder = Decoder()
    return _decoder


def get_doh():
    global _doh
    if _doh is None:
        _doh = DNSDoH()
    return _doh


# ── Favorites — dynamic tool registration ─────────────────────────────────────

def _register_favorites():
    if _cfg_raw("virustotal").get("favorite") and _cfg_raw("virustotal").get("enabled", True):
        def virustotal(ioc: str) -> dict:
            """Check any IOC against VirusTotal.

            Args:
                ioc: IP address, domain, hash (MD5/SHA1/SHA256), or URL.

            Returns:
                VirusTotal analysis results including engine detection counts.
            """
            ioc_type = detect_ioc_type(_normalize_ioc(ioc.strip()))
            vt = get_vt()
            dispatch = {
                "ip": vt.check_ip, "domain": vt.check_domain,
                "md5": vt.check_hash, "sha1": vt.check_hash, "sha256": vt.check_hash,
                "url": vt.check_url,
            }
            fn = dispatch.get(ioc_type)
            return fn(ioc) if fn else {"source": "virustotal", "error": f"unsupported ioc type: {ioc_type}"}
        mcp.add_tool(virustotal)

    if _cfg_raw("abuseipdb").get("favorite") and _cfg_raw("abuseipdb").get("enabled", True):
        def abuseipdb(ip: str) -> dict:
            """Check an IP against AbuseIPDB.

            Args:
                ip: IPv4 address to check.

            Returns:
                Abuse confidence score, report count, ISP, usage type, and last report date.
            """
            return get_abuse().check_ip(ip)
        mcp.add_tool(abuseipdb)

    if _cfg_raw("greynoise").get("favorite") and _cfg_raw("greynoise").get("enabled", True):
        def greynoise(ip: str) -> dict:
            """Check whether an IP is internet background noise using GreyNoise.

            Args:
                ip: IPv4 address to check.

            Returns:
                Noise/RIOT classification, scanner name, and last seen date.
            """
            return get_gn().check_ip(ip)
        mcp.add_tool(greynoise)

    if _cfg_raw("shodan").get("favorite") and _cfg_raw("shodan").get("enabled", True):
        def shodan(ip: str) -> dict:
            """Look up an IP in Shodan for open ports, services, and vulnerabilities.

            Args:
                ip: IPv4 address to investigate.

            Returns:
                Open ports, banners, CVEs, tags, org, and last scan time.
            """
            return get_shodan().check_ip(ip)
        mcp.add_tool(shodan)

    if _cfg_raw("urlscan").get("favorite") and _cfg_raw("urlscan").get("enabled", True):
        def urlscan(target: str) -> dict:
            """Scan or retrieve a urlscan.io report for a URL or domain.

            Searches recent scans first; submits a new scan only if no result
            exists within the last 7 days.

            Args:
                target: URL or domain to scan.

            Returns:
                Page title, IP, country, malicious verdict, screenshot URL, and report link.
            """
            ioc_type = detect_ioc_type(_normalize_ioc(target.strip()))
            us = get_urlscan()
            if ioc_type == "url":
                return us.check_url(target)
            return us.check_domain(target)
        mcp.add_tool(urlscan)

    if _cfg_raw("malwarebazaar").get("favorite") and _cfg_raw("malwarebazaar").get("enabled", True):
        def malwarebazaar(hash: str) -> dict:
            """Look up a file hash on MalwareBazaar.

            Args:
                hash: MD5, SHA1, or SHA256 hash.

            Returns:
                File name, type, size, signature, tags, first/last seen dates.
            """
            return get_mb().check_hash(hash)
        mcp.add_tool(malwarebazaar)

    if _cfg_raw("misp").get("favorite") and _cfg_raw("misp").get("enabled", False):
        def misp(ioc: str) -> dict:
            """Search your MISP instance for an IOC.

            Args:
                ioc: IP address, domain, hash, or URL.

            Returns:
                Matching MISP attributes with event IDs and tags.
            """
            normalized = _normalize_ioc(ioc.strip())
            ioc_type = detect_ioc_type(normalized)
            m = get_misp()
            dispatch = {
                "ip": m.check_ip, "domain": m.check_domain,
                "md5": m.check_hash, "sha1": m.check_hash, "sha256": m.check_hash,
                "url": m.check_url,
            }
            fn = dispatch.get(ioc_type, m.check_ip)
            return fn(normalized)
        mcp.add_tool(misp)


_register_favorites()


# ── Aggregated enrichment tools ────────────────────────────────────────────────

@mcp.tool()
def lookup_ip(ip: str) -> dict:
    """Look up an IP address across all enabled threat intelligence sources.

    Sources: VirusTotal, AbuseIPDB, GreyNoise, Shodan, IPInfo, IBM X-Force,
    AlienVault OTX, Project Honeypot, Feodo Tracker (botnet C2), Tor exit check.
    Private sources (MISP, Graylog, DFIR-IRIS, Wazuh) included when enabled.
    Custom blacklists checked when configured.

    Args:
        ip: IPv4 or IPv6 address to investigate.

    Returns:
        Dict keyed by source name. Not-configured sources are omitted.
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        is_ipv4 = addr.version == 4
    except ValueError:
        is_ipv4 = True

    tasks = {
        "virustotal": (get_vt().check_ip, ip),
        "abuseipdb":  (get_abuse().check_ip, ip),
        "greynoise":  (get_gn().check_ip, ip),
        "shodan":     (get_shodan().check_ip, ip),
        "ipinfo":     (get_ipinfo().check_ip, ip),
        "ibm_xforce": (get_xforce().check_ip, ip),
        "alienvault": (get_av().check_ip, ip),
        "feodo":      (get_feodo().check_ip, ip),
        "tor_exit":   (get_tor().check_ip, ip),
        "misp":       (get_misp().check_ip, ip),
        "graylog":    (get_graylog().top_events, ip),
        "dfir_iris":  (get_iris().related_cases, ip),
        "wazuh":      (get_wazuh().recent_alerts, ip),
    }
    if is_ipv4:
        tasks["honeypot"] = (get_honeypot().check_ip, ip)

    results = _parallel(tasks)
    bl = get_blacklists().check(ip)
    if bl:
        results["custom_blacklists"] = bl
    return results


@mcp.tool()
def lookup_domain(domain: str) -> dict:
    """Look up a domain across all enabled threat intelligence sources.

    Sources: VirusTotal, AlienVault OTX, WHOIS, urlscan.io, IBM X-Force.
    Private sources (MISP, Graylog, DFIR-IRIS) included when enabled.
    Custom blacklists checked when configured.

    Args:
        domain: Domain name to investigate (e.g. evil.com).

    Returns:
        Dict keyed by source name. Not-configured sources are omitted.
    """
    tasks = {
        "virustotal": (get_vt().check_domain, domain),
        "alienvault": (get_av().check_domain, domain),
        "whois":      (get_whois().lookup, domain),
        "urlscan":    (get_urlscan().check_domain, domain),
        "ibm_xforce": (get_xforce().check_domain, domain),
        "misp":       (get_misp().check_domain, domain),
        "graylog":    (get_graylog().top_events, domain),
        "dfir_iris":  (get_iris().related_cases, domain),
    }
    results = _parallel(tasks)
    bl = get_blacklists().check(domain)
    if bl:
        results["custom_blacklists"] = bl
    return results


@mcp.tool()
def lookup_hash(hash: str) -> dict:
    """Look up a file hash across all enabled threat intelligence sources.

    Sources: VirusTotal, MalwareBazaar, ThreatFox, IBM X-Force, AlienVault OTX.
    Private sources (MISP) included when enabled.
    Custom blacklists checked when configured.

    Args:
        hash: MD5, SHA1, or SHA256 file hash.

    Returns:
        Dict keyed by source name. Not-configured sources are omitted.
    """
    tasks = {
        "virustotal":    (get_vt().check_hash, hash),
        "malwarebazaar": (get_mb().check_hash, hash),
        "threatfox":     (get_tf().check_hash, hash),
        "ibm_xforce":    (get_xforce().check_hash, hash),
        "alienvault":    (get_av().check_hash, hash),
        "misp":          (get_misp().check_hash, hash),
        "dfir_iris":     (get_iris().related_cases, hash),
    }
    results = _parallel(tasks)
    bl = get_blacklists().check(hash)
    if bl:
        results["custom_blacklists"] = bl
    return results


@mcp.tool()
def lookup_url(url: str) -> dict:
    """Look up a URL across all enabled threat intelligence sources.

    Sources: VirusTotal, urlscan.io, URLhaus, IBM X-Force.
    Private sources (MISP) included when enabled.
    Custom blacklists checked when configured.

    Args:
        url: Full URL to investigate (e.g. https://evil.com/payload.exe).

    Returns:
        Dict keyed by source name. Not-configured sources are omitted.
    """
    tasks = {
        "virustotal": (get_vt().check_url, url),
        "urlscan":    (get_urlscan().check_url, url),
        "urlhaus":    (get_uh().check_url, url),
        "ibm_xforce": (get_xforce().check_url, url),
        "misp":       (get_misp().check_url, url),
    }
    results = _parallel(tasks)
    bl = get_blacklists().check(url)
    if bl:
        results["custom_blacklists"] = bl
    return results


@mcp.tool()
def enrich(ioc: str) -> dict:
    """Auto-detect the IOC type and enrich across all relevant sources.

    Handles defanged IOCs (e.g. hxxps://evil[.]com/path, 1.1.1[.]1).

    Args:
        ioc: Any indicator — IP, domain, URL, hash, CVE, MAC, email, or defanged variant.

    Returns:
        {"ioc_type": str, "results": {...}} or {"ioc_type": "unknown", "error": "..."}.
    """
    normalized = _normalize_ioc(ioc.strip())
    ioc_type = detect_ioc_type(normalized)

    dispatch = {
        "ip":     lookup_ip,
        "domain": lookup_domain,
        "url":    lookup_url,
        "md5":    lookup_hash,
        "sha1":   lookup_hash,
        "sha256": lookup_hash,
        "cve":    lookup_cve,
        "mac":    lookup_mac,
    }

    fn = dispatch.get(ioc_type)
    if fn is None:
        return {"ioc_type": ioc_type, "error": f"No lookup available for type: {ioc_type}"}

    return {"ioc_type": ioc_type, "results": fn(normalized)}


# ── Utility tools ──────────────────────────────────────────────────────────────

@mcp.tool()
def lookup_cve(cve_id: str) -> dict:
    """Look up a CVE in the NVD database.

    Args:
        cve_id: CVE identifier (e.g. CVE-2024-1234).

    Returns:
        Description, CVSS score and severity, published date, CWEs, and references.
    """
    return get_cve().lookup(cve_id.strip())


@mcp.tool()
def lookup_mac(mac: str) -> dict:
    """Look up the manufacturer for a MAC address.

    Args:
        mac: MAC address in any common format (AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF).

    Returns:
        Vendor company name, country, and OUI type.
    """
    return get_mac().lookup(mac.strip())


@mcp.tool()
def lookup_useragent(ua: str) -> dict:
    """Parse a User-Agent string into browser, OS, and device components.

    Fully offline — uses the ua-parser library.

    Args:
        ua: Raw User-Agent string.

    Returns:
        Browser family/version, OS family/version, device family, is_mobile, is_bot.
    """
    return get_ua().parse(ua)


@mcp.tool()
def lookup_eventid(event_id: str, platform: str = "windows") -> dict:
    """Look up a Windows/Sysmon/Exchange/SQL event ID.

    Args:
        event_id: Event ID number as a string (e.g. "4624").
        platform: One of windows, sysmon, exchange, sharepoint, sql. Default: windows.

    Returns:
        Event name, description, MITRE ATT&CK techniques, and category.
    """
    return get_evid().lookup(event_id.strip(), platform.strip().lower())


@mcp.tool()
def lookup_lolbas(name: str) -> dict:
    """Search the LOLBas database for a living-off-the-land binary.

    Args:
        name: Binary name to search (e.g. certutil, mshta, rundll32).

    Returns:
        Description, known commands, use cases, detection hints, and references.
    """
    return get_lolbas().lookup(name.strip())


@mcp.tool()
def lookup_blockchain(address: str) -> dict:
    """Look up a Bitcoin address or transaction hash on blockchain.com.

    Args:
        address: Bitcoin address or 64-character transaction hash.

    Returns:
        Balance, transaction count, recent transactions (for addresses) or
        block height and fee (for transactions).
    """
    return get_blockchain().lookup(address.strip())


@mcp.tool()
def decode(value: str, encoding: str = "magic") -> dict:
    """Decode or transform an encoded string.

    Fully offline — no network calls.

    Args:
        value: The encoded string to decode.
        encoding: One of base64, base64url, hex, url, rot13, defang, magic.
                  Use magic to auto-detect the encoding. Default: magic.

    Returns:
        Decoded output and detected encoding. Magic mode returns all successful decodings.
    """
    return get_decoder().decode(value, encoding)


@mcp.tool()
def resolve_domain(domain: str, record_type: str = "A") -> dict:
    """Resolve a domain using DNS-over-HTTPS (Google DNS).

    Args:
        domain: Domain name to resolve.
        record_type: DNS record type — A, AAAA, MX, NS, TXT, CNAME, SOA. Default: A.

    Returns:
        DNS answers with record data and TTL, plus status code.
    """
    return get_doh().resolve(domain.strip(), record_type.strip().upper())


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
