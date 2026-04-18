import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from lib.cache import TTLCache

_URL = "https://check.torproject.org/torbulkexitlist"
_cache = TTLCache(ttl=300)


def _fetch() -> set[str]:
    cached = _cache.get("list")
    if cached is not None:
        return cached
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    r = s.get(_URL, timeout=15)
    r.raise_for_status()
    ips = {line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith("#")}
    _cache.set("list", ips)
    return ips


class TorExitNodes:
    def check_ip(self, ip: str) -> dict:
        try:
            exit_nodes = _fetch()
            return {"source": "tor_exit", "ip": ip, "is_exit_node": ip in exit_nodes}
        except Exception as e:
            return {"source": "tor_exit", "error": str(e)}
