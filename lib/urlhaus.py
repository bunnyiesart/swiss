import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://urlhaus-api.abuse.ch/v1"


class URLhaus:
    def __init__(self, api_key: str | None = None):
        self._session = requests.Session()
        if api_key:
            self._session.headers["Auth-Key"] = api_key
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def check_url(self, url: str) -> dict:
        try:
            r = self._session.post(f"{BASE}/url/", data={"url": url}, timeout=10)
            r.raise_for_status()
            d = r.json()
            if d.get("query_status") == "no_results":
                return {"source": "urlhaus", "found": False}
            return {
                "source":     "urlhaus",
                "found":      True,
                "url_status": d.get("url_status"),
                "threat":     d.get("threat"),
                "tags":       d.get("tags", []),
                "date_added": d.get("date_added"),
                "reporter":   d.get("reporter"),
                "urls_count": d.get("urls_count"),
            }
        except Exception as e:
            return {"source": "urlhaus", "error": str(e)}

    def check_host(self, host: str) -> dict:
        try:
            r = self._session.post(f"{BASE}/host/", data={"host": host}, timeout=10)
            r.raise_for_status()
            d = r.json()
            if d.get("query_status") == "no_results":
                return {"source": "urlhaus", "found": False}
            urls = d.get("urls", [])
            return {
                "source":      "urlhaus",
                "found":       True,
                "urls_count":  d.get("urls_count"),
                "blacklists":  d.get("blacklists", {}),
                "recent_urls": [
                    {"url": u.get("url"), "status": u.get("url_status"), "threat": u.get("threat")}
                    for u in urls[:10]
                ],
            }
        except Exception as e:
            return {"source": "urlhaus", "error": str(e)}
