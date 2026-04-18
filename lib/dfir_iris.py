import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class DFIRIrisClient:
    def __init__(self, url: str, api_key: str, verify_ssl: bool = True):
        self._url = url.rstrip("/")
        self._verify = verify_ssl
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        })
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    def related_cases(self, ioc: str) -> dict:
        try:
            r = self._session.get(
                f"{self._url}/case/ioc/list",
                params={"search": ioc},
                timeout=15,
                verify=self._verify,
            )
            r.raise_for_status()
            data = r.json().get("data", {})
            iocs = data.get("ioc", []) if isinstance(data, dict) else []
            cases = [
                {"case_id": i.get("ioc_case_id"), "value": i.get("ioc_value"), "type": i.get("ioc_type")}
                for i in iocs[:5]
            ]
            return {
                "source":     "dfir_iris",
                "case_count": len(iocs),
                "cases":      cases,
            }
        except Exception as e:
            return {"source": "dfir_iris", "error": str(e)}
