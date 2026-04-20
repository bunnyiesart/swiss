# Architecture

## Project structure

```
server.py                  # FastMCP entry point — lazy singletons, _parallel(), tool registration
requirements.txt
config.example.json
data/
  eventids.json            # Bundled event ID table — no network call
lib/
  __init__.py
  config.py                # Config loading, mode-600 enforcement, credential accessors
  ioc.py                   # IOC type detection and defang normalization
  cache.py                 # Thread-safe TTL cache used by list-based sources

  # Public enrichment wrappers
  virustotal.py            # check_ip / check_domain / check_hash / check_url
  abuseipdb.py             # check_ip
  greynoise.py             # check_ip (community or enterprise depending on key)
  shodan.py                # check_ip
  ipinfo.py                # check_ip
  ibm_xforce.py            # check_ip / check_domain / check_hash / check_url
  alienvault.py            # check_ip / check_domain / check_hash
  urlscan.py               # check_domain / check_url (history-first, async poll)
  honeypot.py              # check_ip — DNS-based, socket only
  feodo.py                 # check_ip — JSON blocklist + TTL cache
  tor_exit.py              # check_ip — bulk list + TTL cache
  malwarebazaar.py         # check_hash
  threatfox.py             # check_hash
  urlhaus.py               # check_url / check_host

  # Threat intelligence & recon
  cymru.py                 # lookup_asn(ip) / check_hash(md5) — Team Cymru DNS services, no key
  mitre.py                 # lookup(technique_id_or_name) — ATT&CK STIX bundle, TTL cache 24h
  recon.py                 # CRTShClient / BGPViewClient / DNSRecords — passive recon sources
  censys.py                # check_ip — Censys v2 API (api_id + api_secret)
  exposure.py              # probe(host, port) — active TCP probe + banner grab
  waf.py                   # detect(url) — wafw00f subprocess wrapper

  # Private infrastructure wrappers
  misp.py                  # check_ip / check_domain / check_hash / check_url
  graylog.py               # top_events(ioc)
  dfir_iris.py             # related_cases(ioc)
  wazuh.py                 # recent_alerts(ioc)
  custom_blacklists.py     # check(ioc) — per-URL TTL cache, exact line match

  # Utility wrappers
  whois.py                 # lookup(domain) — python-whois
  cve.py                   # lookup(cve_id) — NVD 2.0 API
  maclookup.py             # lookup(mac)
  useragent.py             # parse(ua) — ua-parser, offline
  eventid.py               # lookup(event_id, platform) — reads data/eventids.json
  lolbas.py                # lookup(name) — LOLBas GitHub feed + TTL cache
  blockchain.py            # lookup(address) — blockchain.com
  decode.py                # decode(value, encoding) — fully offline
  dns_doh.py               # resolve(domain, type) — DNS-over-HTTPS
tests/
  conftest.py              # mock_config fixture; clears SWISS_* env vars
  test_*.py
```

---

## Key patterns

### Service wrapper contract

Every `lib/*.py` wrapper follows the same shape:

```python
class VirusTotal:
    def __init__(self, api_key: str):
        self._session = requests.Session()
        self._session.headers["x-apikey"] = api_key
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def check_ip(self, ip: str) -> dict:
        try:
            r = self._session.get(f"{BASE}/ip_addresses/{ip}", timeout=10)
            r.raise_for_status()
            a = r.json()["data"]["attributes"]
            return {"source": "virustotal", "malicious": a["last_analysis_stats"]["malicious"], ...}
        except Exception as e:
            return {"source": "virustotal", "error": str(e)}
```

Rules:
- Constructor stores credentials and builds a `requests.Session` with retry adapter
- Every method returns a flat dict with `"source"` always present
- Errors are caught and returned as `{"source": "...", "error": "..."}` — never raised
- All requests use `timeout=10`
- Retry on 502/503/504 only (not on 4xx — those are real errors)

### Private wrapper contract

Private wrappers (MISP, Graylog, DFIR-IRIS, Wazuh) extend the pattern with:
- `url` parameter (internal servers may not have DNS)
- `verify_ssl` parameter (internal servers often use self-signed certs)
- Mount both `https://` and `http://` adapters

```python
class MISPClient:
    def __init__(self, url: str, api_key: str, verify_ssl: bool = True):
        self._url = url.rstrip("/")
        self._verify = verify_ssl
        self._session = requests.Session()
        self._session.headers["Authorization"] = api_key
        adapter = HTTPAdapter(max_retries=Retry(total=3, backoff_factor=1, status_forcelist=[502,503,504]))
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)
```

### `_unconfigured` sentinel

Instead of `if client is None` guards everywhere, unconfigured services return an `_Unconfigured` sentinel. Every method call on it returns `{"source": "<name>", "error": "not_configured"}`.

```python
class _Unconfigured:
    def __init__(self, source: str):
        self._source = source
    def __getattr__(self, name):
        src = self._source
        def _stub(*args, **kwargs):
            return {"source": src, "error": "not_configured"}
        return _stub
```

`_parallel()` silently drops `not_configured` results, so misconfigured services are invisible in output.

### Lazy singletons

Service clients are created once on first use:

```python
_vt = None
def get_vt():
    global _vt
    if _vt is None:
        k = _key("virustotal")
        _vt = VirusTotal(k) if k else _unconfigured("virustotal")
    return _vt
```

Services that work without a key pass `None` instead of returning `_unconfigured`:

```python
_gn = None
def get_gn():
    global _gn
    if _gn is None:
        _gn = GreyNoise(_key("greynoise"))  # None = community tier
    return _gn
```

### Parallel execution

`_parallel()` fans out all tasks using `ThreadPoolExecutor`, silently drops `not_configured` results, and keeps real API errors:

```python
def _parallel(tasks: dict[str, tuple]) -> dict:
    if not tasks:
        return {}
    results = {}
    with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        futures = {executor.submit(fn, *args): name for name, (fn, *args) in tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {"source": name, "error": str(exc)}
            if result.get("error") != "not_configured":
                results[name] = result
    return results
```

`max_workers=len(tasks)` is intentional — all work is I/O-bound (network calls).

### Config loading

`lib/config.py` merges three layers in order of precedence (highest last):

1. **Built-in defaults** (`_DEFAULTS` dict) — so the server works with no config file
2. **Config file** (`~/.config/swiss/config.json`) — user overrides
3. **Environment variables** (`SWISS_<SERVICE>_<FIELD>`) — deployment overrides

```python
def _cfg_raw(service: str) -> dict:
    defaults = _DEFAULTS.get(service, {})
    user_cfg = _get_cfg().get(service, {})
    merged = {**defaults, **user_cfg}
    prefix = f"SWISS_{service.upper()}_"
    for field in _ENV_FIELDS:
        val = os.environ.get(f"{prefix}{field.upper()}", "").strip()
        if val:
            merged[field] = val
    return merged
```

Mode-600 enforcement runs before loading:
```python
mode = CONFIG_PATH.stat().st_mode & 0o177
if mode != 0:
    raise SystemExit(f"[swiss] Config file has unsafe permissions ...")
```

### Favorites — dynamic tool registration

At startup, `_register_favorites()` reads config and calls `mcp.add_tool()` for each enabled+favorited service. Each service has an explicit `def` block — **never a loop** (late-binding closure bug).

```python
def _register_favorites():
    if _cfg_raw("abuseipdb").get("favorite") and _cfg_raw("abuseipdb").get("enabled", True):
        def abuseipdb(ip: str) -> dict:
            """Check an IP against AbuseIPDB. ..."""
            return get_abuse().check_ip(ip)
        mcp.add_tool(abuseipdb)
    # ... one block per service
```

FastMCP uses `fn.__name__` as the tool name — the `def abuseipdb(...)` identifier becomes the registered tool name automatically.

### TTL cache

List-based sources (Feodo, Tor, LOLBas, custom blacklists) use a module-level `TTLCache` to avoid fetching on every IOC lookup:

```python
_cache = TTLCache(ttl=300)  # 5 minutes

def check_ip(self, ip: str) -> dict:
    blocklist = _cache.get("list")
    if blocklist is None:
        blocklist = self._fetch()
        _cache.set("list", blocklist)
    ...
```

---

## Adding a new integration

1. **Create `lib/<service>.py`** following the wrapper contract above.

2. **Add defaults to `lib/config.py`** in `_DEFAULTS`:
   ```python
   "myservice": {"enabled": True, "favorite": False, "api_key": ""},
   ```

3. **Add to `config.example.json`**.

4. **Add a lazy singleton in `server.py`**:
   ```python
   _mysvc = None
   def get_mysvc():
       global _mysvc
       if _mysvc is None:
           k = _key("myservice")
           _mysvc = MyService(k) if k else _unconfigured("myservice")
       return _mysvc
   ```

5. **Add to the relevant `lookup_*` task dict** in `server.py`.

6. **Optionally add to `_register_favorites()`** with an explicit `def` block.

7. **Write `tests/test_<service>.py`** covering happy path, not-found, and error responses using the `responses` library.

---

## Testing

All HTTP is mocked using the `responses` library. Tests never make real network calls.

```python
import responses as resp_lib
from lib.virustotal import VirusTotal

@resp_lib.activate
def test_check_ip():
    resp_lib.add(resp_lib.GET, "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4",
                 json={...}, status=200)
    result = VirusTotal("test-key").check_ip("1.2.3.4")
    assert result["source"] == "virustotal"
    assert "error" not in result
```

The `mock_config` fixture in `conftest.py` bypasses file loading and clears all `SWISS_*` env vars:

```python
@pytest.fixture
def mock_config(monkeypatch):
    import lib.config as cfg_mod
    monkeypatch.setattr(cfg_mod, "_CFG", TEST_CONFIG)
    for key in list(os.environ):
        if key.startswith("SWISS_"):
            monkeypatch.delenv(key)
    return TEST_CONFIG
```

Run tests:
```bash
.venv/bin/pytest
.venv/bin/pytest tests/test_virustotal.py -v
.venv/bin/pytest -k "test_check_ip" -v
```
