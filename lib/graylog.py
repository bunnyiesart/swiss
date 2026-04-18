import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_RANGE_SECONDS = 86400  # 24 hours
_LIMIT = 10


class GraylogClient:
    def __init__(self, url: str, username: str, password: str, verify_ssl: bool = True):
        self._url = url.rstrip("/")
        self._verify = verify_ssl
        self._session = requests.Session()
        self._session.auth = (username, password)
        self._session.headers["Accept"] = "application/json"
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    def top_events(self, ioc: str) -> dict:
        try:
            r = self._session.get(
                f"{self._url}/api/search/universal/relative",
                params={"query": ioc, "range": _RANGE_SECONDS, "limit": _LIMIT, "decorate": False},
                timeout=15,
                verify=self._verify,
            )
            r.raise_for_status()
            d = r.json()
            messages = d.get("messages", [])
            return {
                "source":      "graylog",
                "total_count": d.get("total_results", 0),
                "recent_hits": [m.get("message", {}) for m in messages[:_LIMIT]],
            }
        except Exception as e:
            return {"source": "graylog", "error": str(e)}
