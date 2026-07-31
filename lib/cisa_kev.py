import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from lib.cache import TTLCache

_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_cache = TTLCache(ttl=21600)  # 6 hours


def _fetch_index() -> dict:
    cached = _cache.get("index")
    if cached is not None:
        return cached
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    r = s.get(_URL, timeout=30)
    r.raise_for_status()
    data = r.json()
    idx = {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}
    _cache.set("index", idx)
    return idx


class CISAKEVClient:
    def lookup(self, cve_id: str) -> dict:
        try:
            idx = _fetch_index()
            entry = idx.get(cve_id.upper())
            if not entry:
                return {"source": "cisa_kev", "found": False, "cve_id": cve_id}
            return {
                "source":                    "cisa_kev",
                "found":                     True,
                "cve_id":                    entry.get("cveID"),
                "vendor_project":            entry.get("vendorProject"),
                "product":                   entry.get("product"),
                "vulnerability_name":        entry.get("vulnerabilityName"),
                "date_added":                entry.get("dateAdded"),
                "short_description":         entry.get("shortDescription"),
                "required_action":           entry.get("requiredAction"),
                "due_date":                  entry.get("dueDate"),
                "known_ransomware_use":      entry.get("knownRansomwareCampaignUse", "Unknown"),
            }
        except Exception as e:
            return {"source": "cisa_kev", "error": str(e)}
