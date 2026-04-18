import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://api.shodan.io"


class Shodan:
    def __init__(self, api_key: str):
        self._key = api_key
        self._session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def check_ip(self, ip: str) -> dict:
        try:
            r = self._session.get(
                f"{BASE}/shodan/host/{ip}",
                params={"key": self._key},
                timeout=10,
            )
            if r.status_code == 404:
                return {"source": "shodan", "ip": ip, "found": False}
            r.raise_for_status()
            d = r.json()
            return {
                "source":       "shodan",
                "ip":           d.get("ip_str"),
                "found":        True,
                "org":          d.get("org"),
                "isp":          d.get("isp"),
                "country_name": d.get("country_name"),
                "country_code": d.get("country_code"),
                "city":         d.get("city"),
                "os":           d.get("os"),
                "hostnames":    d.get("hostnames", []),
                "open_ports":   d.get("ports", []),
                "vulns":        list(d.get("vulns", {}).keys()),
                "tags":         d.get("tags", []),
                "last_update":  d.get("last_update"),
            }
        except Exception as e:
            return {"source": "shodan", "error": str(e)}
