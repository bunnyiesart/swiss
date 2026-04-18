import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://otx.alienvault.com/api/v1/indicators"


class AlienVault:
    def __init__(self, api_key: str):
        self._session = requests.Session()
        self._session.headers["X-OTX-API-KEY"] = api_key
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def _get(self, path: str) -> dict:
        r = self._session.get(f"{BASE}{path}", timeout=10)
        r.raise_for_status()
        return r.json()

    @staticmethod
    def _str(v) -> str | None:
        if isinstance(v, dict):
            return v.get("display_name") or v.get("id") or None
        return str(v) if v else None

    def _pulse_summary(self, d: dict) -> dict:
        pi = d.get("pulse_info", {})
        pulses = pi.get("pulses", [])
        families = list({s for p in pulses for t in p.get("malware_families", []) if (s := self._str(t))})
        industries = list({s for p in pulses for t in p.get("industries", []) if (s := self._str(t))})
        return {
            "pulse_count":      pi.get("count", 0),
            "malware_families": families[:10],
            "industries":       industries[:10],
        }

    def check_ip(self, ip: str) -> dict:
        try:
            d = self._get(f"/IPv4/{ip}/general")
            return {
                "source":  "alienvault",
                "ip":      ip,
                "country": d.get("country_name"),
                "asn":     d.get("asn"),
                **self._pulse_summary(d),
            }
        except Exception as e:
            return {"source": "alienvault", "error": str(e)}

    def check_domain(self, domain: str) -> dict:
        try:
            d = self._get(f"/domain/{domain}/general")
            return {
                "source": "alienvault",
                "domain": domain,
                **self._pulse_summary(d),
            }
        except Exception as e:
            return {"source": "alienvault", "error": str(e)}

    def check_hash(self, h: str) -> dict:
        try:
            d = self._get(f"/file/{h}/general")
            return {
                "source": "alienvault",
                "hash":   h,
                **self._pulse_summary(d),
            }
        except Exception as e:
            return {"source": "alienvault", "error": str(e)}
