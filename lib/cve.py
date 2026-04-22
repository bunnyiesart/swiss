import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVEClient:
    def __init__(self):
        self._session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def lookup(self, cve_id: str) -> dict:
        try:
            r = self._session.get(BASE, params={"cveId": cve_id.upper()}, timeout=15)
            r.raise_for_status()
            vulns = r.json().get("vulnerabilities", [])
            if not vulns:
                return {"source": "cve", "found": False, "cve_id": cve_id}
            cve = vulns[0].get("cve", {})

            descriptions = cve.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)

            metrics = cve.get("metrics", {})
            cvss_score = None
            cvss_severity = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                    break

            weaknesses = [
                w.get("description", [{}])[0].get("value")
                for w in cve.get("weaknesses", [])
                if w.get("description")
            ]

            references = [r.get("url") for r in cve.get("references", [])[:5]]

            return {
                "source":        "cve",
                "found":         True,
                "cve_id":        cve.get("id"),
                "published":     cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "description":   description,
                "cvss_score":    cvss_score,
                "cvss_severity": cvss_severity,
                "weaknesses":    [w for w in weaknesses if w],
                "references":    references,
            }
        except Exception as e:
            return {"source": "cve", "error": str(e)}
