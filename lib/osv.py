import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://api.osv.dev/v1/query"


class OSVClient:
    def __init__(self):
        self._session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def lookup(self, cve_id: str) -> dict:
        try:
            r = self._session.post(BASE, json={"cve_id": cve_id.upper()}, timeout=10)
            r.raise_for_status()
            vulns = r.json().get("vulns", [])
            if not vulns:
                return {"source": "osv", "found": False, "cve_id": cve_id}

            packages = []
            for v in vulns:
                for affected in v.get("affected", []):
                    pkg = affected.get("package", {})
                    name = pkg.get("name")
                    ecosystem = pkg.get("ecosystem")
                    if not name:
                        continue
                    ranges = affected.get("ranges", [])
                    fixed = None
                    for r_entry in ranges:
                        for event in r_entry.get("events", []):
                            if "fixed" in event:
                                fixed = event["fixed"]
                                break
                    packages.append({
                        "name":      name,
                        "ecosystem": ecosystem,
                        "fixed":     fixed,
                    })

            return {
                "source":    "osv",
                "found":     True,
                "cve_id":    cve_id.upper(),
                "osv_ids":   [v.get("id") for v in vulns],
                "summary":   vulns[0].get("summary") if vulns else None,
                "packages":  packages[:20],
            }
        except Exception as e:
            return {"source": "osv", "error": str(e)}
