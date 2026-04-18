import base64

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://www.virustotal.com/api/v3"


def _build_session(api_key: str) -> requests.Session:
    s = requests.Session()
    s.headers["x-apikey"] = api_key
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


class VirusTotal:
    def __init__(self, api_key: str):
        self._session = _build_session(api_key)

    def _get(self, path: str) -> dict:
        r = self._session.get(f"{BASE}{path}", timeout=10)
        r.raise_for_status()
        return r.json().get("data", {}).get("attributes", {})

    def _stats(self, attrs: dict) -> dict:
        s = attrs.get("last_analysis_stats", {})
        return {
            "malicious":  s.get("malicious", 0),
            "suspicious": s.get("suspicious", 0),
            "harmless":   s.get("harmless", 0),
            "undetected": s.get("undetected", 0),
        }

    def check_ip(self, ip: str) -> dict:
        try:
            a = self._get(f"/ip_addresses/{ip}")
            return {
                "source":     "virustotal",
                **self._stats(a),
                "country":    a.get("country"),
                "asn":        a.get("asn"),
                "as_owner":   a.get("as_owner"),
                "reputation": a.get("reputation"),
                "tags":       a.get("tags", []),
            }
        except Exception as e:
            return {"source": "virustotal", "error": str(e)}

    def check_domain(self, domain: str) -> dict:
        try:
            a = self._get(f"/domains/{domain}")
            return {
                "source":      "virustotal",
                **self._stats(a),
                "registrar":   a.get("registrar"),
                "creation_date": a.get("creation_date"),
                "reputation":  a.get("reputation"),
                "categories":  a.get("categories", {}),
                "tags":        a.get("tags", []),
            }
        except Exception as e:
            return {"source": "virustotal", "error": str(e)}

    def check_hash(self, h: str) -> dict:
        try:
            a = self._get(f"/files/{h}")
            return {
                "source":           "virustotal",
                **self._stats(a),
                "name":             a.get("meaningful_name"),
                "type_description": a.get("type_description"),
                "size":             a.get("size"),
                "md5":              a.get("md5"),
                "sha1":             a.get("sha1"),
                "sha256":           a.get("sha256"),
                "first_seen":       a.get("first_submission_date"),
                "last_seen":        a.get("last_submission_date"),
                "tags":             a.get("tags", []),
            }
        except Exception as e:
            return {"source": "virustotal", "error": str(e)}

    def check_url(self, url: str) -> dict:
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
            a = self._get(f"/urls/{url_id}")
            return {
                "source":   "virustotal",
                **self._stats(a),
                "url":      a.get("url"),
                "title":    a.get("title"),
                "final_url": a.get("last_final_url"),
                "tags":     a.get("tags", []),
            }
        except Exception as e:
            return {"source": "virustotal", "error": str(e)}
