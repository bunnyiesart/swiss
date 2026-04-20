import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://search.censys.io/api/v2"


class CensysClient:
    def __init__(self, api_id: str, api_secret: str):
        self._session = requests.Session()
        self._session.auth = (api_id, api_secret)
        self._session.headers["Accept"] = "application/json"
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def check_ip(self, ip: str) -> dict:
        try:
            r = self._session.get(f"{BASE}/hosts/{ip}", timeout=10)
            if r.status_code == 404:
                return {"source": "censys", "ip": ip, "found": False}
            r.raise_for_status()
            d = r.json().get("result", {})
            services = [
                {
                    "port":      svc.get("port"),
                    "protocol":  svc.get("transport_protocol"),
                    "service":   svc.get("service_name"),
                }
                for svc in d.get("services", [])[:20]
            ]
            asn = d.get("autonomous_system", {})
            loc = d.get("location", {})
            return {
                "source":   "censys",
                "ip":       ip,
                "found":    True,
                "services": services,
                "labels":   d.get("labels", []),
                "asn":      asn.get("asn"),
                "org":      asn.get("description"),
                "country":  loc.get("country_code"),
                "bgp_prefix": asn.get("bgp_prefix"),
            }
        except Exception as e:
            return {"source": "censys", "error": str(e)}
