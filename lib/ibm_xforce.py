import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://api.xforce.ibmcloud.com"


class IBMXForce:
    def __init__(self, api_key: str, api_password: str):
        self._session = requests.Session()
        self._session.auth = (api_key, api_password)
        self._session.headers["Accept"] = "application/json"
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def _get(self, path: str) -> dict:
        r = self._session.get(f"{BASE}{path}", timeout=10)
        r.raise_for_status()
        return r.json()

    def check_ip(self, ip: str) -> dict:
        try:
            d = self._get(f"/ipr/{ip}")
            return {
                "source":  "ibm_xforce",
                "ip":      ip,
                "score":   d.get("score"),
                "reason":  d.get("reason"),
                "cats":    d.get("cats", {}),
                "subnets": [s.get("subnet") for s in d.get("subnets", [])],
            }
        except Exception as e:
            return {"source": "ibm_xforce", "error": str(e)}

    def check_domain(self, domain: str) -> dict:
        try:
            d = self._get(f"/url/{domain}")
            result = d.get("result", {})
            return {
                "source":     "ibm_xforce",
                "domain":     domain,
                "score":      result.get("score"),
                "cats":       result.get("cats", {}),
                "malware":    d.get("associated", {}).get("malware", {}).get("count", 0),
            }
        except Exception as e:
            return {"source": "ibm_xforce", "error": str(e)}

    def check_hash(self, h: str) -> dict:
        try:
            d = self._get(f"/malware/{h}")
            mal = d.get("malware", {})
            return {
                "source":   "ibm_xforce",
                "hash":     h,
                "risk":     mal.get("risk"),
                "family":   mal.get("family", []),
                "type":     mal.get("type"),
                "created":  mal.get("created"),
            }
        except Exception as e:
            return {"source": "ibm_xforce", "error": str(e)}

    def check_url(self, url: str) -> dict:
        try:
            d = self._get(f"/url/{url}")
            result = d.get("result", {})
            return {
                "source": "ibm_xforce",
                "url":    url,
                "score":  result.get("score"),
                "cats":   result.get("cats", {}),
            }
        except Exception as e:
            return {"source": "ibm_xforce", "error": str(e)}
