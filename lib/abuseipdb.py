import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDB:
    def __init__(self, api_key: str):
        self._session = requests.Session()
        self._session.headers.update({"Key": api_key, "Accept": "application/json"})
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        try:
            r = self._session.get(
                f"{BASE}/check",
                params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": True},
                timeout=10,
            )
            r.raise_for_status()
            d = r.json().get("data", {})
            return {
                "source":                "abuseipdb",
                "ip":                    d.get("ipAddress"),
                "abuse_confidence_score": d.get("abuseConfidenceScore"),
                "total_reports":         d.get("totalReports"),
                "num_distinct_users":    d.get("numDistinctUsers"),
                "last_reported_at":      d.get("lastReportedAt"),
                "isp":                   d.get("isp"),
                "domain":                d.get("domain"),
                "country_code":          d.get("countryCode"),
                "usage_type":            d.get("usageType"),
                "is_tor":                d.get("isTor"),
                "is_whitelisted":        d.get("isWhitelisted"),
            }
        except Exception as e:
            return {"source": "abuseipdb", "error": str(e)}
