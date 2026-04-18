import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://dns.google/resolve"
_STATUS_CODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 8: "NOTZONE",
}


class DNSDoH:
    def __init__(self):
        self._session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def resolve(self, domain: str, record_type: str = "A") -> dict:
        try:
            r = self._session.get(
                BASE,
                params={"name": domain, "type": record_type.upper()},
                timeout=10,
            )
            r.raise_for_status()
            d = r.json()
            status_code = d.get("Status", 0)
            answers = d.get("Answer", [])
            return {
                "source":      "dns_doh",
                "domain":      domain,
                "type":        record_type.upper(),
                "status_code": status_code,
                "status":      _STATUS_CODES.get(status_code, str(status_code)),
                "answers": [
                    {"name": a.get("name"), "type": a.get("type"), "data": a.get("data"), "ttl": a.get("TTL")}
                    for a in answers
                ],
                "truncated":   d.get("TC", False),
                "recursive":   d.get("RD", False),
            }
        except Exception as e:
            return {"source": "dns_doh", "error": str(e)}
