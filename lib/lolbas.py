import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from lib.cache import TTLCache

_URL = "https://lolbas-project.github.io/api/lolbas.json"
_cache = TTLCache(ttl=1800)


def _fetch() -> list[dict]:
    cached = _cache.get("data")
    if cached is not None:
        return cached
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    r = s.get(_URL, timeout=15)
    r.raise_for_status()
    data = r.json()
    _cache.set("data", data)
    return data


class LOLBas:
    def lookup(self, name: str) -> dict:
        try:
            entries = _fetch()
            name_lower = name.lower()
            matches = [e for e in entries if e.get("Name", "").lower() == name_lower]
            if not matches:
                partial = [e for e in entries if name_lower in e.get("Name", "").lower()]
                matches = partial[:5]
            if not matches:
                return {"source": "lolbas", "found": False, "name": name}
            results = []
            for e in matches:
                results.append({
                    "name":        e.get("Name"),
                    "description": e.get("Description"),
                    "author":      e.get("Author"),
                    "created":     e.get("Created"),
                    "commands": [
                        {
                            "command":     c.get("Command"),
                            "description": c.get("Description"),
                            "usecase":     c.get("Usecase"),
                            "category":    c.get("Category"),
                        }
                        for c in e.get("Commands", [])[:5]
                    ],
                    "detection": e.get("Detection", []),
                    "resources": [r.get("Link") for r in e.get("Resources", [])[:3]],
                })
            return {"source": "lolbas", "found": True, "count": len(results), "results": results}
        except Exception as e:
            return {"source": "lolbas", "error": str(e)}
