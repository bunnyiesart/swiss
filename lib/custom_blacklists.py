import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from lib.cache import TTLCache
from lib.config import _blacklist_configs

_cache = TTLCache(ttl=300)


def _fetch_lines(url: str) -> set[str]:
    cached = _cache.get(url)
    if cached is not None:
        return cached
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    r = s.get(url, timeout=15)
    r.raise_for_status()
    lines = {line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith("#")}
    _cache.set(url, lines)
    return lines


class CustomBlacklists:
    def check(self, ioc: str) -> list[dict]:
        """Check IOC against all enabled custom blacklists.

        Returns a list of matches (one dict per matching blacklist).
        Empty list means no matches.
        """
        matches = []
        for entry in _blacklist_configs():
            name = entry.get("name", entry["url"])
            try:
                lines = _fetch_lines(entry["url"])
                if ioc in lines:
                    matches.append({"source": name, "listed": True, "url": entry["url"]})
            except Exception as e:
                matches.append({"source": name, "error": str(e)})
        return matches
