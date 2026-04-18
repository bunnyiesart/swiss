import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from lib.ioc import detect_ioc_type

_HASH_TYPES = {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}


class MISPClient:
    def __init__(self, url: str, api_key: str, verify_ssl: bool = True):
        self._url = url.rstrip("/")
        self._verify = verify_ssl
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    def _search(self, value: str, type_attribute: str) -> dict:
        r = self._session.post(
            f"{self._url}/attributes/restSearch",
            json={"value": value, "type": type_attribute, "returnFormat": "json", "limit": 10},
            timeout=15,
            verify=self._verify,
        )
        r.raise_for_status()
        attrs = r.json().get("response", {}).get("Attribute", [])
        return {
            "source": "misp",
            "found": len(attrs) > 0,
            "count": len(attrs),
            "attributes": [
                {
                    "type":     a.get("type"),
                    "value":    a.get("value"),
                    "event_id": a.get("event_id"),
                    "tags":     [t.get("name") for t in a.get("Tag", [])],
                    "comment":  a.get("comment"),
                }
                for a in attrs[:10]
            ],
        }

    def check_ip(self, ip: str) -> dict:
        try:
            return self._search(ip, "ip-dst")
        except Exception as e:
            return {"source": "misp", "error": str(e)}

    def check_domain(self, domain: str) -> dict:
        try:
            return self._search(domain, "domain")
        except Exception as e:
            return {"source": "misp", "error": str(e)}

    def check_hash(self, h: str) -> dict:
        ioc_type = detect_ioc_type(h)
        attr_type = _HASH_TYPES.get(ioc_type, "sha256")
        try:
            return self._search(h, attr_type)
        except Exception as e:
            return {"source": "misp", "error": str(e)}

    def check_url(self, url: str) -> dict:
        try:
            return self._search(url, "url")
        except Exception as e:
            return {"source": "misp", "error": str(e)}
