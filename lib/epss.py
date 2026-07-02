import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://api.first.org/data/v1/epss"


class EPSSClient:
    def __init__(self):
        self._session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def lookup(self, cve_id: str) -> dict:
        try:
            r = self._session.get(BASE, params={"cve": cve_id.upper()}, timeout=10)
            r.raise_for_status()
            body = r.json()
            data = body.get("data", [])
            if not data:
                return {"source": "epss", "found": False, "cve_id": cve_id}
            entry = data[0]
            return {
                "source":     "epss",
                "found":      True,
                "cve_id":     entry.get("cve"),
                "epss_score": float(entry.get("epss", 0)),
                "percentile": float(entry.get("percentile", 0)),
                "date":       entry.get("date"),
            }
        except Exception as e:
            return {"source": "epss", "error": str(e)}
