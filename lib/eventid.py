import json
import os

_DATA_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "eventids.json"))
_DB: dict | None = None


def _load() -> dict:
    global _DB
    if _DB is None:
        with open(_DATA_PATH) as f:
            _DB = json.load(f)
    return _DB


class EventIDClient:
    def lookup(self, event_id: int | str, platform: str = "windows") -> dict:
        try:
            db = _load()
            platform_key = platform.lower()
            section = db.get(platform_key, {})
            entry = section.get(str(event_id))
            if not entry:
                return {"source": "eventid", "found": False, "event_id": str(event_id), "platform": platform_key}
            return {
                "source":      "eventid",
                "found":       True,
                "event_id":    str(event_id),
                "platform":    platform_key,
                "name":        entry.get("name"),
                "description": entry.get("description"),
                "category":    entry.get("category"),
                "mitre":       entry.get("mitre", []),
            }
        except Exception as e:
            return {"source": "eventid", "error": str(e)}
