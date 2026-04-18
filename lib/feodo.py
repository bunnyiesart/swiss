import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from lib.cache import TTLCache

_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
_cache = TTLCache(ttl=300)


def _fetch() -> list[dict]:
    cached = _cache.get("list")
    if cached is not None:
        return cached
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    r = s.get(_URL, timeout=15)
    r.raise_for_status()
    try:
        data = r.json()
    except Exception:
        data = []
    _cache.set("list", data)
    return data


class FeodoTracker:
    def check_ip(self, ip: str) -> dict:
        try:
            entries = _fetch()
            for entry in entries:
                if entry.get("ip_address") == ip:
                    return {
                        "source":  "feodo",
                        "ip":      ip,
                        "listed":  True,
                        "malware": entry.get("malware"),
                        "port":    entry.get("port"),
                        "status":  entry.get("status"),
                    }
            return {"source": "feodo", "ip": ip, "listed": False}
        except Exception as e:
            return {"source": "feodo", "error": str(e)}
