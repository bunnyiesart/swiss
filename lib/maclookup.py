import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://api.maclookup.app/v2/macs"


class MACLookup:
    def __init__(self):
        self._session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def lookup(self, mac: str) -> dict:
        try:
            r = self._session.get(f"{BASE}/{mac}", timeout=10)
            r.raise_for_status()
            d = r.json()
            return {
                "source":   "maclookup",
                "mac":      mac,
                "found":    d.get("found", False),
                "company":  d.get("company"),
                "country":  d.get("country"),
                "type":     d.get("type"),
                "updated":  d.get("updated"),
            }
        except Exception as e:
            return {"source": "maclookup", "error": str(e)}
