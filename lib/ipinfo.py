import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://ipinfo.io"


class IPInfo:
    def __init__(self, api_key: str):
        self._token = api_key
        self._session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def check_ip(self, ip: str) -> dict:
        try:
            r = self._session.get(
                f"{BASE}/{ip}/json",
                params={"token": self._token} if self._token else {},
                timeout=10,
            )
            r.raise_for_status()
            d = r.json()
            privacy = d.get("privacy", {})
            return {
                "source":   "ipinfo",
                "ip":       d.get("ip"),
                "hostname": d.get("hostname"),
                "city":     d.get("city"),
                "region":   d.get("region"),
                "country":  d.get("country"),
                "org":      d.get("org"),
                "asn":      d.get("asn"),
                "timezone": d.get("timezone"),
                "is_vpn":   privacy.get("vpn"),
                "is_proxy": privacy.get("proxy"),
                "is_tor":   privacy.get("tor"),
                "is_hosting": privacy.get("hosting"),
            }
        except Exception as e:
            return {"source": "ipinfo", "error": str(e)}
