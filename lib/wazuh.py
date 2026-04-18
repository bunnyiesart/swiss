import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_LIMIT = 10
_TIMEFRAME = "24h"


class WazuhClient:
    def __init__(self, url: str, username: str, password: str, verify_ssl: bool = True):
        self._url = url.rstrip("/")
        self._verify = verify_ssl
        self._session = requests.Session()
        self._session.auth = (username, password)
        self._session.headers["Accept"] = "application/json"
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)
        self._token: str | None = None

    def _get_token(self) -> str | None:
        try:
            r = self._session.get(
                f"{self._url}/security/user/authenticate",
                timeout=10,
                verify=self._verify,
            )
            r.raise_for_status()
            self._token = r.json().get("data", {}).get("token")
            if self._token:
                self._session.headers["Authorization"] = f"Bearer {self._token}"
            return self._token
        except Exception:
            return None

    def recent_alerts(self, ioc: str) -> dict:
        try:
            if not self._token:
                self._get_token()
            r = self._session.get(
                f"{self._url}/alerts",
                params={"q": ioc, "limit": _LIMIT, "timeframe": _TIMEFRAME},
                timeout=15,
                verify=self._verify,
            )
            r.raise_for_status()
            d = r.json().get("data", {})
            affected = d.get("affected_items", [])
            return {
                "source":      "wazuh",
                "alert_count": d.get("total_affected_items", 0),
                "alerts": [
                    {
                        "id":          a.get("id"),
                        "rule_desc":   a.get("rule", {}).get("description"),
                        "rule_level":  a.get("rule", {}).get("level"),
                        "agent_name":  a.get("agent", {}).get("name"),
                        "timestamp":   a.get("timestamp"),
                    }
                    for a in affected[:_LIMIT]
                ],
            }
        except Exception as e:
            return {"source": "wazuh", "error": str(e)}
