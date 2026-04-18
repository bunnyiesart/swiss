import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_COMMUNITY_BASE  = "https://api.greynoise.io/v3/community"
_ENTERPRISE_BASE = "https://api.greynoise.io/v3/noise/context"


class GreyNoise:
    def __init__(self, api_key: str | None = None):
        self._key = api_key
        self._session = requests.Session()
        if api_key:
            self._session.headers["key"] = api_key
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def check_ip(self, ip: str) -> dict:
        if self._key:
            return self._check_enterprise(ip)
        return self._check_community(ip)

    def _check_community(self, ip: str) -> dict:
        try:
            r = self._session.get(f"{_COMMUNITY_BASE}/{ip}", timeout=10)
            if r.status_code == 404:
                return {"source": "greynoise", "ip": ip, "noise": False, "riot": False, "found": False}
            r.raise_for_status()
            d = r.json()
            return {
                "source":         "greynoise",
                "ip":             d.get("ip"),
                "noise":          d.get("noise"),
                "riot":           d.get("riot"),
                "classification": d.get("classification"),
                "name":           d.get("name"),
                "link":           d.get("link"),
                "last_seen":      d.get("last_seen"),
                "message":        d.get("message"),
            }
        except Exception as e:
            return {"source": "greynoise", "error": str(e)}

    def _check_enterprise(self, ip: str) -> dict:
        try:
            r = self._session.get(f"{_ENTERPRISE_BASE}/{ip}", timeout=10)
            if r.status_code == 404:
                return {"source": "greynoise", "ip": ip, "noise": False, "riot": False, "found": False}
            r.raise_for_status()
            d = r.json()
            return {
                "source":         "greynoise",
                "ip":             d.get("ip"),
                "noise":          d.get("noise"),
                "riot":           d.get("riot"),
                "classification": d.get("classification"),
                "name":           d.get("name"),
                "tags":           d.get("tags", []),
                "metadata":       d.get("metadata", {}),
                "raw_data":       d.get("raw_data", {}),
                "last_seen":      d.get("last_seen"),
                "first_seen":     d.get("first_seen"),
                "seen":           d.get("seen"),
            }
        except Exception as e:
            return {"source": "greynoise", "error": str(e)}
