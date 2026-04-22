import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from lib.cache import TTLCache

_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
_cache = TTLCache(ttl=86400)


def _build_index(bundle: dict) -> dict:
    techniques = {}
    mitigations = {}

    for obj in bundle.get("objects", []):
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        t = obj.get("type")
        if t == "attack-pattern":
            techniques[obj["id"]] = obj
        elif t == "course-of-action":
            mitigations[obj["id"]] = obj

    mitigation_map: dict[str, list[str]] = {}
    for obj in bundle.get("objects", []):
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "mitigates"
        ):
            target = obj.get("target_ref", "")
            source = obj.get("source_ref", "")
            if target in techniques and source in mitigations:
                mitigation_map.setdefault(target, []).append(
                    mitigations[source].get("name", "")
                )

    idx: dict[str, tuple] = {}
    for stix_id, obj in techniques.items():
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref["external_id"].upper()
                entry = (obj, mitigation_map.get(stix_id, []))
                idx[ext_id] = entry
                idx[obj["name"].lower()] = entry
                break

    return idx


def _fetch_index() -> dict:
    cached = _cache.get("index")
    if cached is not None:
        return cached
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    r = s.get(_URL, timeout=60)
    r.raise_for_status()
    idx = _build_index(r.json())
    _cache.set("index", idx)
    return idx


class MITREClient:
    def lookup(self, query: str) -> dict:
        try:
            idx = _fetch_index()
            key = query.strip().upper()
            entry = idx.get(key) or idx.get(query.strip().lower())
            if not entry:
                return {"source": "mitre", "found": False, "query": query}

            obj, technique_mitigations = entry
            ext_id = ""
            url = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id", "")
                    url = ref.get("url", "")
                    break

            tactics = [
                p["phase_name"]
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]

            return {
                "source":      "mitre",
                "found":       True,
                "id":          ext_id,
                "name":        obj.get("name", ""),
                "tactics":     tactics,
                "platforms":   obj.get("x_mitre_platforms", []),
                "description": obj.get("description", ""),
                "detection":   obj.get("x_mitre_detection", ""),
                "mitigations": technique_mitigations[:10],
                "url":         url,
            }
        except Exception as e:
            return {"source": "mitre", "error": str(e)}
