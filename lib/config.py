import json
import os
from pathlib import Path

_cfg_env = os.environ.get("SWISS_CONFIG_PATH")
CONFIG_PATH = Path(_cfg_env) if _cfg_env else Path(__file__).parent.parent / "config.json"

_CFG: dict | None = None

# Fields that are secrets — sourced exclusively from env vars, never from config.json.
_SECRET_FIELDS = ("api_key", "api_password", "username", "password")
# All credential fields that may appear as SWISS_<SERVICE>_<FIELD> env vars.
_ENV_FIELDS = ("api_key", "api_password", "url", "username", "password")

_DEFAULTS: dict[str, dict] = {
    "virustotal":    {"enabled": True,  "favorite": True},
    "abuseipdb":     {"enabled": True,  "favorite": True},
    "greynoise":     {"enabled": True,  "favorite": True},
    "shodan":        {"enabled": True,  "favorite": True},
    "ipinfo":        {"enabled": True,  "favorite": False},
    "ibm_xforce":    {"enabled": True,  "favorite": False},
    "alienvault":    {"enabled": True,  "favorite": False},
    "urlscan":       {"enabled": True,  "favorite": True},
    "honeypot":      {"enabled": True,  "favorite": False},
    "malwarebazaar": {"enabled": True,  "favorite": True,  "api_key": ""},
    "threatfox":     {"enabled": True,  "favorite": False, "api_key": ""},
    "urlhaus":       {"enabled": True,  "favorite": False, "api_key": ""},
    "misp":          {"enabled": False, "favorite": True},
    "graylog":       {"enabled": False, "favorite": False},
    "dfir_iris":     {"enabled": False, "favorite": False},
    "wazuh":         {"enabled": False, "favorite": False},
    "cymru":         {"enabled": True,  "favorite": True},
    "censys":        {"enabled": True,  "favorite": False},
}


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    with CONFIG_PATH.open() as f:
        return json.load(f)


def _get_cfg() -> dict:
    global _CFG
    if _CFG is None:
        _CFG = _load_config()
    return _CFG


def _cfg_raw(service: str) -> dict:
    """Return config dict for a service, merged with defaults then env vars.

    Secrets (api_key, api_password, username, password) are sourced exclusively
    from env vars — never read from config.json.
    """
    defaults = _DEFAULTS.get(service, {})
    user_cfg = _get_cfg().get(service, {})
    # Strip any secrets that may exist in the file — they are not authoritative.
    filtered_cfg = {k: v for k, v in user_cfg.items() if k not in _SECRET_FIELDS}
    merged = {**defaults, **filtered_cfg}
    prefix = f"SWISS_{service.upper()}_"
    for field in _ENV_FIELDS:
        val = os.environ.get(f"{prefix}{field.upper()}", "").strip()
        if val:
            merged[field] = val
    return merged


def _key(service: str) -> str | None:
    """Return api_key if service is enabled and key is non-empty, else None."""
    cfg = _cfg_raw(service)
    if not cfg.get("enabled", True):
        return None
    key = cfg.get("api_key", "").strip()
    return key if key else None


def _key_pair(service: str) -> tuple[str, str] | None:
    """Return (api_key, api_password) for Basic Auth services (e.g. IBM X-Force)."""
    cfg = _cfg_raw(service)
    if not cfg.get("enabled", True):
        return None
    k = cfg.get("api_key", "").strip()
    p = cfg.get("api_password", "").strip()
    return (k, p) if (k and p) else None


def _private_cfg(service: str) -> dict | None:
    """Return private integration config or None if disabled/unconfigured."""
    cfg = _cfg_raw(service)
    if not cfg.get("enabled", False):
        return None
    url = cfg.get("url", "").strip()
    if not url:
        return None
    return {
        "url": url,
        "api_key": cfg.get("api_key", "").strip(),
        "username": cfg.get("username", "").strip(),
        "password": cfg.get("password", "").strip(),
        "verify_ssl": cfg.get("verify_ssl", True),
    }


def _blacklist_configs() -> list[dict]:
    """Return enabled custom blacklist entries."""
    entries = _get_cfg().get("custom_blacklists", [])
    return [e for e in entries if e.get("enabled") and e.get("url", "").strip()]


class _Unconfigured:
    """Sentinel returned when a service is disabled or missing credentials.

    Any method call returns {"source": "<name>", "error": "not_configured"}.
    """

    def __init__(self, source: str):
        self._source = source

    def __getattr__(self, name: str):
        src = self._source

        def _stub(*args, **kwargs):
            return {"source": src, "error": "not_configured"}

        return _stub


def _unconfigured(source: str) -> _Unconfigured:
    return _Unconfigured(source)
