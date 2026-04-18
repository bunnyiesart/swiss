import time
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://urlscan.io/api/v1"
_RECENT_DAYS = 7
_POLL_INTERVAL = 3
_POLL_MAX = 10


class URLScan:
    def __init__(self, api_key: str):
        self._session = requests.Session()
        self._session.headers.update({"API-Key": api_key, "Content-Type": "application/json"})
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def _search(self, query: str) -> dict | None:
        """Return the most recent scan result matching query, if within _RECENT_DAYS."""
        try:
            r = self._session.get(f"{BASE}/search/", params={"q": query, "size": 1}, timeout=10)
            r.raise_for_status()
            results = r.json().get("results", [])
            if not results:
                return None
            task_time = results[0].get("task", {}).get("time", "")
            if task_time:
                scanned_at = datetime.fromisoformat(task_time.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - scanned_at).days
                if age_days <= _RECENT_DAYS:
                    return self._flatten(results[0])
        except Exception:
            pass
        return None

    def _submit(self, url: str) -> str | None:
        """Submit a new scan and return the result UUID."""
        try:
            r = self._session.post(f"{BASE}/scan/", json={"url": url}, timeout=10)
            r.raise_for_status()
            return r.json().get("uuid")
        except Exception:
            return None

    def _poll(self, uuid: str) -> dict:
        """Poll for scan result; return pending dict if timeout."""
        for _ in range(_POLL_MAX):
            time.sleep(_POLL_INTERVAL)
            try:
                r = self._session.get(f"{BASE}/result/{uuid}/", timeout=10)
                if r.status_code == 200:
                    return self._flatten(r.json())
                if r.status_code not in (404, 422):
                    r.raise_for_status()
            except Exception:
                pass
        return {"source": "urlscan", "pending": True, "uuid": uuid}

    def _flatten(self, data: dict) -> dict:
        page = data.get("page", {})
        stats = data.get("stats", {})
        task = data.get("task", {})
        return {
            "source":        "urlscan",
            "url":           page.get("url"),
            "domain":        page.get("domain"),
            "ip":            page.get("ip"),
            "country":       page.get("country"),
            "title":         page.get("title"),
            "status":        page.get("status"),
            "malicious":     data.get("verdicts", {}).get("overall", {}).get("malicious", False),
            "score":         data.get("verdicts", {}).get("overall", {}).get("score", 0),
            "tags":          data.get("verdicts", {}).get("overall", {}).get("tags", []),
            "screenshot":    data.get("screenshot"),
            "report_url":    f"https://urlscan.io/result/{data.get('task', {}).get('uuid', '')}/",
            "scanned_at":    task.get("time"),
            "requests_total": stats.get("requests", {}).get("total", 0),
        }

    def check_domain(self, domain: str) -> dict:
        try:
            cached = self._search(f"domain:{domain}")
            if cached:
                return cached
            uuid = self._submit(f"https://{domain}")
            if not uuid:
                return {"source": "urlscan", "error": "submission_failed"}
            return self._poll(uuid)
        except Exception as e:
            return {"source": "urlscan", "error": str(e)}

    def check_url(self, url: str) -> dict:
        try:
            cached = self._search(f"page.url:{url}")
            if cached:
                return cached
            uuid = self._submit(url)
            if not uuid:
                return {"source": "urlscan", "error": "submission_failed"}
            return self._poll(uuid)
        except Exception as e:
            return {"source": "urlscan", "error": str(e)}
