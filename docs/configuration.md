# Configuration

## Config file

Config lives at `~/.config/swiss/config.json`. The file **must be mode 600** — the server will refuse to start if it is group- or world-readable.

```bash
mkdir -p ~/.config/swiss
cp config.example.json ~/.config/swiss/config.json
chmod 600 ~/.config/swiss/config.json
```

## Environment variables

Every credential field can be set via environment variable instead of (or in addition to) the config file. Environment variables take precedence over the config file.

Naming convention: `SWISS_<SERVICE>_<FIELD>` — all uppercase, underscores preserved.

```bash
# Public integrations
export SWISS_VIRUSTOTAL_API_KEY="..."
export SWISS_ABUSEIPDB_API_KEY="..."
export SWISS_GREYNOISE_API_KEY="..."       # optional — omit for community tier
export SWISS_SHODAN_API_KEY="..."
export SWISS_IPINFO_API_KEY="..."
export SWISS_ALIENVAULT_API_KEY="..."
export SWISS_URLSCAN_API_KEY="..."
export SWISS_HONEYPOT_API_KEY="..."
export SWISS_IBM_XFORCE_API_KEY="..."
export SWISS_IBM_XFORCE_API_PASSWORD="..."

# Censys (api_key = API ID, api_password = API Secret)
export SWISS_CENSYS_API_KEY="..."
export SWISS_CENSYS_API_PASSWORD="..."

# abuse.ch (one key covers all three — obtained from auth.abuse.ch)
export SWISS_MALWAREBAZAAR_API_KEY="..."
export SWISS_THREATFOX_API_KEY="..."
export SWISS_URLHAUS_API_KEY="..."

# Private integrations
export SWISS_MISP_URL="https://misp.internal"
export SWISS_MISP_API_KEY="..."
export SWISS_GRAYLOG_URL="https://graylog.internal"
export SWISS_GRAYLOG_USERNAME="..."
export SWISS_GRAYLOG_PASSWORD="..."
export SWISS_DFIR_IRIS_URL="https://iris.internal"
export SWISS_DFIR_IRIS_API_KEY="..."
export SWISS_WAZUH_URL="https://wazuh.internal"
export SWISS_WAZUH_USERNAME="..."
export SWISS_WAZUH_PASSWORD="..."
```

## Full schema

```json
{
  "virustotal":        {"api_key": "",  "enabled": true,  "favorite": true},
  "abuseipdb":         {"api_key": "",  "enabled": true,  "favorite": true},
  "greynoise":         {"api_key": "",  "enabled": true,  "favorite": true},
  "shodan":            {"api_key": "",  "enabled": true,  "favorite": true},
  "ipinfo":            {"api_key": "",  "enabled": true,  "favorite": false},
  "ibm_xforce":        {"api_key": "",  "api_password": "", "enabled": true, "favorite": false},
  "alienvault":        {"api_key": "",  "enabled": true,  "favorite": false},
  "urlscan":           {"api_key": "",  "enabled": true,  "favorite": true},
  "honeypot":          {"api_key": "",  "enabled": true,  "favorite": false},
  "malwarebazaar":     {"api_key": "",  "enabled": true,  "favorite": true},
  "threatfox":         {"api_key": "",  "enabled": true,  "favorite": false},
  "urlhaus":           {"api_key": "",  "enabled": true,  "favorite": false},
  "misp":              {"url": "", "api_key": "",   "enabled": false, "favorite": true,  "verify_ssl": true},
  "graylog":           {"url": "", "username": "", "password": "", "enabled": false, "favorite": false, "verify_ssl": true},
  "dfir_iris":         {"url": "", "api_key": "",   "enabled": false, "favorite": false, "verify_ssl": true},
  "wazuh":             {"url": "", "username": "", "password": "", "enabled": false, "favorite": false, "verify_ssl": true},
  "censys":            {"api_key": "", "api_password": "", "enabled": true, "favorite": false},
  "custom_blacklists": [
    {"name": "My Blocklist", "url": "https://example.com/blocklist.txt", "enabled": false, "favorite": false}
  ]
}
```

## Per-field reference

### `enabled`

Controls whether the integration participates in aggregated `lookup_*` tools.

- All public integrations default to `true` — they run even without an API key, returning `{"error": "not_configured"}` which is silently dropped from output.
- All private integrations default to `false` — set to `true` once you have the URL and credentials.

### `favorite`

When `true`, the integration gets its own dedicated MCP tool registered at startup (e.g. `abuseipdb(ip)`). This lets you call a single source directly without the full fan-out overhead.

Changing `favorite` requires restarting the MCP server.

### `api_key`

Empty string means unconfigured. The tool gracefully returns `{"error": "not_configured"}` and is silently omitted from aggregated results. No exceptions are raised.

### `verify_ssl`

Private integrations only. Set to `false` if your internal server uses a self-signed certificate. Defaults to `true`.

---

## Favorites

Any integration can be promoted to a dedicated tool by setting `"favorite": true`. The tool name matches the service key exactly.

**Default favorites:**

| Tool registered | Service key |
|---|---|
| `virustotal(ioc)` | virustotal |
| `abuseipdb(ip)` | abuseipdb |
| `greynoise(ip)` | greynoise |
| `shodan(ip)` | shodan |
| `urlscan(target)` | urlscan |
| `malwarebazaar(hash)` | malwarebazaar |
| `cymru(ioc)` | cymru |
| `misp(ioc)` | misp (when `enabled: true`) |

> Graylog, DFIR-IRIS, and Wazuh are intentionally not favorited. Each has its own dedicated MCP server. The swiss integrations are thin supplementary wrappers.

---

## Custom blacklists

swiss can check any IOC against custom blocklists you host. Each entry is a URL pointing to a plain-text file with one entry per line.

```json
"custom_blacklists": [
  {"name": "Internal C2 IPs",  "url": "https://threat.internal/c2-ips.txt",     "enabled": true,  "favorite": false},
  {"name": "Phishing Domains", "url": "https://threat.internal/phishing.txt",   "enabled": true,  "favorite": false},
  {"name": "Malware Hashes",   "url": "https://threat.internal/hashes.txt",     "enabled": false, "favorite": false}
]
```

Lists are fetched once and cached for 5 minutes (TTL). Matching uses exact line comparison — not substring — to avoid false positives on short IOCs.

Results appear under `"custom_blacklists"` in the aggregated tool output. The value is a list of matching entries (one per matching blacklist), not a single dict.

---

## Private integrations

Private integrations (MISP, Graylog, DFIR-IRIS, Wazuh) are disabled by default. Enable them by setting `enabled: true` and providing the `url` and credentials.

The swiss wrappers for these are intentionally thin — they provide supplementary context (related cases, recent alerts, top events) rather than deep investigation, since each service has its own dedicated MCP server for that.

```json
"misp": {
  "url": "https://misp.yourdomain.internal",
  "api_key": "your-misp-authkey",
  "enabled": true,
  "favorite": true,
  "verify_ssl": true
}
```
