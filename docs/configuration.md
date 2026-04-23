# Configuration

## Config file

Config lives at `~/.config/swiss/config.json`. The file **must be mode 600** — the server will refuse to start if it is group- or world-readable.

```bash
mkdir -p ~/.config/swiss
cp config.example.json ~/.config/swiss/config.json
chmod 600 ~/.config/swiss/config.json
```

## Start here

Not all integrations need an API key. The table below shows what you get for free, what needs a quick sign-up, and what is optional.

| Tier | Services | What to do |
|---|---|---|
| **No key required** | GreyNoise (community), Feodo Tracker, Tor exit, Team Cymru, MITRE ATT&CK, crt.sh, BGPView, WHOIS, NVD, LOLBas, decode, DNS-over-HTTPS | Nothing — these activate automatically |
| **Free key, ~2 min** | VirusTotal, AbuseIPDB, AlienVault OTX, urlscan.io | Sign up at each site, copy the API key |
| **Free key, shared** | MalwareBazaar + ThreatFox + URLhaus | One registration at [auth.abuse.ch](https://auth.abuse.ch/) — same key for all three |
| **Free key, ~5 min** | Shodan, Project Honeypot, IBM X-Force | Sign up; IBM X-Force requires a free IBM ID (no credit card) |
| **Optional / tiered** | GreyNoise (enterprise), IPInfo, Censys | Work without a key; adding one unlocks more data or higher rate limits |
| **Self-hosted** | MISP, Graylog, DFIR-IRIS, Wazuh | Disabled by default — enable once you have the URL and credentials |

## Environment variables

Every credential is set via environment variable. Environment variables take precedence over the config file and are the **only** authoritative source for API keys and passwords — secrets written directly into `config.json` are stripped at load time.

Naming convention: `SWISS_<SERVICE>_<FIELD>` — all uppercase, underscores preserved.

```bash
export SWISS_CONFIG_PATH="$HOME/.config/swiss/config.json"   # required for venv setup

# ── Free keys — register once, use forever ────────────────────────────────────
export SWISS_VIRUSTOTAL_API_KEY="..."        # virustotal.com → sign in → profile → API key
export SWISS_ABUSEIPDB_API_KEY="..."         # abuseipdb.com → sign in → API
export SWISS_ALIENVAULT_API_KEY="..."        # otx.alienvault.com → sign up → settings → API key
export SWISS_URLSCAN_API_KEY="..."           # urlscan.io → sign up → settings → API key

# MalwareBazaar, ThreatFox, and URLhaus share ONE key — register once at auth.abuse.ch:
export SWISS_MALWAREBAZAAR_API_KEY="..."     # auth.abuse.ch → sign up → copy key
export SWISS_THREATFOX_API_KEY="..."         # same key as above
export SWISS_URLHAUS_API_KEY="..."           # same key as above

# ── Free with registration ────────────────────────────────────────────────────
export SWISS_SHODAN_API_KEY="..."            # shodan.io → sign up → account overview
export SWISS_HONEYPOT_API_KEY="..."          # projecthoneypot.org → My Account → HTTP:BL
                                             # must be exactly 12 lowercase letters
export SWISS_IBM_XFORCE_API_KEY="..."        # exchange.xforce.ibmcloud.com → Settings → API access
export SWISS_IBM_XFORCE_API_PASSWORD="..."   # API secret (not your login password) — generated alongside the key above
                                             # requires a free IBM ID — no credit card needed

# ── Optional / tiered ─────────────────────────────────────────────────────────
export SWISS_GREYNOISE_API_KEY="..."         # greynoise.io — omit to use the free community tier
export SWISS_IPINFO_API_KEY="..."            # ipinfo.io — omit for 50k req/month keyless tier
export SWISS_CENSYS_API_KEY="..."            # search.censys.io → account → API  (API ID)
export SWISS_CENSYS_API_PASSWORD="..."       # API Secret — generated alongside the API ID above
                                             # 250 queries/month on the free tier

# ── Private / self-hosted ─────────────────────────────────────────────────────
export SWISS_MISP_URL="https://misp.internal"
export SWISS_MISP_API_KEY="..."              # MISP → Administration → Auth Keys
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

> **Secrets are env-var only.** Fields named `api_key`, `api_password`, `username`, and `password` are stripped from the config file at load time and ignored — set them exclusively via `SWISS_<SERVICE>_<FIELD>` environment variables. Only `enabled`, `favorite`, `url`, and `verify_ssl` are read from the file.

```json
{
  "virustotal":        {"enabled": true,  "favorite": true},
  "abuseipdb":         {"enabled": true,  "favorite": true},
  "greynoise":         {"enabled": true,  "favorite": true},
  "shodan":            {"enabled": true,  "favorite": true},
  "ipinfo":            {"enabled": true,  "favorite": false},
  "ibm_xforce":        {"enabled": true,  "favorite": false},
  "alienvault":        {"enabled": true,  "favorite": false},
  "urlscan":           {"enabled": true,  "favorite": true},
  "honeypot":          {"enabled": true,  "favorite": false},
  "malwarebazaar":     {"enabled": true,  "favorite": true},
  "threatfox":         {"enabled": true,  "favorite": false},
  "urlhaus":           {"enabled": true,  "favorite": false},
  "cymru":             {"enabled": true,  "favorite": true},
  "censys":            {"enabled": true,  "favorite": false},
  "misp":              {"url": "", "enabled": false, "favorite": true,  "verify_ssl": true},
  "graylog":           {"url": "", "enabled": false, "favorite": false, "verify_ssl": true},
  "dfir_iris":         {"url": "", "enabled": false, "favorite": false, "verify_ssl": true},
  "wazuh":             {"url": "", "enabled": false, "favorite": false, "verify_ssl": true},
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
