from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from lib.dns_doh import DNSDoH

_DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def _session() -> requests.Session:
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


class CRTShClient:
    def __init__(self):
        self._session = _session()

    def lookup(self, domain: str) -> dict:
        try:
            r = self._session.get(
                "https://crt.sh/",
                params={"q": domain, "output": "json"},
                timeout=15,
            )
            r.raise_for_status()
            entries = r.json()
            if not entries:
                return {"source": "crt_sh", "domain": domain, "found": False, "cert_count": 0, "subdomains": []}

            subdomains = set()
            for e in entries:
                for name in e.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name:
                        subdomains.add(name.lower())

            return {
                "source":     "crt_sh",
                "domain":     domain,
                "found":      True,
                "cert_count": len(entries),
                "subdomains": sorted(subdomains)[:50],
            }
        except Exception as e:
            return {"source": "crt_sh", "error": str(e)}


class BGPViewClient:
    def __init__(self):
        self._session = _session()

    def lookup_ip(self, ip: str) -> dict:
        try:
            r = self._session.get(
                f"https://api.bgpview.io/ip/{ip}",
                timeout=10,
            )
            if r.status_code == 404:
                return {"source": "bgpview", "ip": ip, "found": False}
            r.raise_for_status()
            d = r.json().get("data", {})
            prefixes = d.get("prefixes", [])
            result: dict = {
                "source":   "bgpview",
                "ip":       ip,
                "found":    bool(prefixes),
                "prefixes": [],
            }
            for p in prefixes[:5]:
                asn_info = p.get("asn", {})
                result["prefixes"].append({
                    "prefix":  p.get("prefix"),
                    "asn":     asn_info.get("asn"),
                    "org":     asn_info.get("description"),
                    "country": asn_info.get("country_code") or p.get("country_code"),
                })
            rir = d.get("rir_allocation") or {}
            if rir:
                result["rir"] = rir.get("rir_name")
                result["allocated"] = rir.get("date_allocated")
            return result
        except Exception as e:
            return {"source": "bgpview", "error": str(e)}


class DNSRecords:
    def __init__(self):
        self._doh = DNSDoH()

    def lookup(self, domain: str) -> dict:
        try:
            records: dict = {}
            with ThreadPoolExecutor(max_workers=len(_DNS_RECORD_TYPES)) as ex:
                futures = {
                    ex.submit(self._doh.resolve, domain, rt): rt
                    for rt in _DNS_RECORD_TYPES
                }
                for future in as_completed(futures):
                    rt = futures[future]
                    r = future.result()
                    if not r.get("error") and r.get("answers"):
                        records[rt] = [a["data"] for a in r["answers"]]
            return {"source": "dns", "domain": domain, "records": records}
        except Exception as e:
            return {"source": "dns", "error": str(e)}

    def lookup_ptr(self, ip: str) -> dict:
        try:
            parts = ip.split(".")
            arpa = ".".join(reversed(parts)) + ".in-addr.arpa"
            r = self._doh.resolve(arpa, "PTR")
            if r.get("error") or not r.get("answers"):
                return {"source": "dns", "ip": ip, "ptr": []}
            return {"source": "dns", "ip": ip, "ptr": [a["data"] for a in r["answers"]]}
        except Exception as e:
            return {"source": "dns", "error": str(e)}
