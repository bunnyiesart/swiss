import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFox:
    def __init__(self, api_key: str | None = None):
        self._session = requests.Session()
        self._session.headers["Content-Type"] = "application/json"
        if api_key:
            self._session.headers["Auth-Key"] = api_key
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def check_hash(self, h: str) -> dict:
        try:
            r = self._session.post(BASE, json={"query": "search_ioc", "search_term": h}, timeout=10)
            r.raise_for_status()
            body = r.json()
            if body.get("query_status") != "ok":
                return {"source": "threatfox", "found": False, "status": body.get("query_status")}
            iocs = body.get("data", [])[:10]
            return {
                "source": "threatfox",
                "found":  True,
                "count":  len(iocs),
                "iocs": [
                    {
                        "ioc":              i.get("ioc"),
                        "ioc_type":         i.get("ioc_type"),
                        "threat_type":      i.get("threat_type"),
                        "malware":          i.get("malware"),
                        "confidence_level": i.get("confidence_level"),
                        "first_seen":       i.get("first_seen"),
                        "tags":             i.get("tags", []),
                    }
                    for i in iocs
                ],
            }
        except Exception as e:
            return {"source": "threatfox", "error": str(e)}
