# swiss

[![CI](https://github.com/bunnyiesart/swiss/actions/workflows/ci.yml/badge.svg)](https://github.com/bunnyiesart/swiss/actions/workflows/ci.yml)
[![ghcr.io](https://img.shields.io/badge/ghcr.io-bunnyiesart%2Fswiss-blue)](https://github.com/bunnyiesart/swiss/pkgs/container/swiss)

A [FastMCP](https://github.com/jlowin/fastmcp) server that exposes Blue Team / SOC analyst tools as MCP tools — replacing browser-based lookups with secure, token-efficient MCP calls directly inside Claude.

API keys never pass through Claude. Credentials are set as environment variables on your machine; the config file controls which integrations are active.

---

## What it does

Instead of opening VirusTotal, AbuseIPDB, Shodan, and four other tabs every time you investigate an IP, you call one tool:

```
lookup_ip("185.220.101.47")
```

swiss fans out to all configured sources in parallel and returns a single structured result.

---

## Quick start (Docker)

> **No API keys needed to start.** GreyNoise, Feodo Tracker, Tor exit, Team Cymru, MITRE ATT&CK, WHOIS, and several other sources work out of the box. Add keys incrementally — each one unlocks more sources.

Pull the pre-built image from GitHub Container Registry:

```bash
docker pull ghcr.io/bunnyiesart/swiss:latest
```

Create your config file:

```bash
mkdir -p ~/.config/swiss
curl -sL https://raw.githubusercontent.com/bunnyiesart/swiss/main/config.example.json \
  > ~/.config/swiss/config.json
chmod 600 ~/.config/swiss/config.json
```

Set your API keys as environment variables, then register with Claude Code by adding this to `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "swiss": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/home/you/.config/swiss/config.json:/config/swiss.json:ro",
        "-e", "SWISS_CONFIG_PATH=/config/swiss.json",
        "-e", "SWISS_VIRUSTOTAL_API_KEY=your-key",
        "-e", "SWISS_ABUSEIPDB_API_KEY=your-key",
        "-e", "SWISS_GREYNOISE_API_KEY=your-key",
        "-e", "SWISS_SHODAN_API_KEY=your-key",
        "ghcr.io/bunnyiesart/swiss:latest"
      ]
    }
  }
}
```

Add one `-e` line per API key you want to use. **API keys must be passed as `-e` flags** — they are intentionally stripped from the config file and only read from environment variables. Replace `/home/you/...` with the absolute path to your config file. `-i` (not `-t`) is required for stdio MCP transport. Restart Claude Code after updating `mcp.json`, then call `lookup_ip("8.8.8.8")` to verify.

---

## Quick start (local venv)

> **No API keys needed to start.** Same as above — add keys incrementally as you need each source.

```bash
git clone https://github.com/bunnyiesart/swiss
cd swiss
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Create your config file:

```bash
mkdir -p ~/.config/swiss
curl -sL https://raw.githubusercontent.com/bunnyiesart/swiss/main/config.example.json \
  > ~/.config/swiss/config.json
chmod 600 ~/.config/swiss/config.json
```

Set your API keys and config path as environment variables — add these to your shell profile (`.bashrc` / `.zshrc`):

```bash
export SWISS_CONFIG_PATH="$HOME/.config/swiss/config.json"
export SWISS_VIRUSTOTAL_API_KEY="..."
export SWISS_ABUSEIPDB_API_KEY="..."
# ... other keys
```

Then register with Claude Code:

```json
{
  "mcpServers": {
    "swiss": {
      "command": "/home/you/swiss/.venv/bin/python3",
      "args": ["/home/you/swiss/server.py"]
    }
  }
}
```

> `SWISS_CONFIG_PATH` is required for the venv setup — without it the server looks for `config.json` in the project root, not in `~/.config/swiss/`.

---

## Tools

### Aggregated enrichment

Fan out to all enabled sources in parallel. Sources that aren't configured are silently omitted.

| Tool | What it does |
|---|---|
| `lookup_ip(ip)` | VirusTotal · AbuseIPDB · GreyNoise · Shodan · IPInfo · IBM X-Force · AlienVault OTX · Project Honeypot · Feodo Tracker · Tor exit · Team Cymru · MISP* · Graylog* · DFIR-IRIS* · Wazuh* · custom blacklists* |
| `lookup_domain(domain)` | VirusTotal · AlienVault OTX · WHOIS · urlscan.io · IBM X-Force · MISP* · Graylog* · DFIR-IRIS* · custom blacklists* |
| `lookup_hash(hash)` | VirusTotal · MalwareBazaar · ThreatFox · IBM X-Force · AlienVault OTX · Team Cymru (MHR, MD5 only) · MISP* · custom blacklists* |
| `lookup_url(url)` | VirusTotal · urlscan.io · URLhaus · IBM X-Force · MISP* · custom blacklists* |
| `enrich(ioc)` | Auto-detects type, re-fangs defanged input, dispatches to the right lookup |

*private — only included when `enabled: true` in config*

### Dedicated tools (favorites)

Each favorited integration also gets its own dedicated tool. Calling `abuseipdb("1.2.3.4")` hits only AbuseIPDB — no fan-out overhead.

Default favorites: `virustotal` · `abuseipdb` · `greynoise` · `shodan` · `urlscan` · `malwarebazaar` · `cymru` · `misp` (when enabled)

Any integration can be favorited in config. See [Favorites](docs/configuration.md#favorites).

### Utility tools

| Tool | What it does |
|---|---|
| `detect_waf(url)` | WAF fingerprinting via wafw00f — identifies vendor or flags generic WAF |
| `check_exposure(host, port)` | TCP probe + Shodan + Censys — is this service reachable from the internet? |
| `recon(target)` | Passive recon — crt.sh · BGPView · DNS records · WHOIS (domain) or Shodan · PTR (IP) |
| `lookup_technique(id)` | MITRE ATT&CK technique — tactics, platforms, detection, mitigations |
| `lookup_cve(cve_id)` | NVD/MITRE lookup — CVSS score, description, CWEs, references |
| `lookup_mac(mac)` | MAC address manufacturer (maclookup.app) |
| `lookup_useragent(ua)` | Parse a User-Agent string — offline, ua-parser library |
| `lookup_eventid(event_id, platform)` | Windows / Sysmon / Exchange / SharePoint / SQL event ID — bundled JSON, no network |
| `lookup_lolbas(name)` | LOLBas living-off-the-land binary lookup |
| `lookup_blockchain(address)` | Bitcoin address or transaction — blockchain.com |
| `decode(value, encoding)` | base64 · hex · URL · ROT13 · defang · magic — fully offline |
| `resolve_domain(domain, record_type)` | DNS-over-HTTPS via Google DNS |

---

## Configuration

Full reference: [docs/configuration.md](docs/configuration.md)

The config file (`~/.config/swiss/config.json`) controls non-secret settings — `enabled`, `favorite`, `url` for private integrations, `verify_ssl`. API keys and passwords are **only** read from environment variables; they are stripped if present in the config file.

Env var format: `SWISS_<SERVICE>_<FIELD>` (all caps). **Secrets set in `config.json` are stripped and ignored** — environment variables are the only authoritative source for API keys and passwords.

```bash
export SWISS_CONFIG_PATH="$HOME/.config/swiss/config.json"   # required for venv setup

# ── Works with no key ─────────────────────────────────────────────────────────
# GreyNoise (community tier), Feodo Tracker, Tor exit check, Team Cymru,
# MITRE ATT&CK, crt.sh, BGPView, WHOIS, NVD, LOLBas, decode, DNS-over-HTTPS
# activate automatically — no registration needed.

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
export SWISS_CENSYS_API_KEY="..."            # search.censys.io → account → API (250 queries/month free)
export SWISS_CENSYS_API_PASSWORD="..."       # API Secret — generated alongside the API ID above

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

---

## Integrations

Detailed per-integration docs including where to get API keys, tier differences, and returned fields: [docs/integrations.md](docs/integrations.md)

**Free keys required:** VirusTotal · AbuseIPDB · GreyNoise · Shodan · AlienVault OTX · urlscan.io · Project Honeypot · MalwareBazaar · ThreatFox · URLhaus (last three share one key from [auth.abuse.ch](https://auth.abuse.ch/))

**Works without any key:** GreyNoise (community tier) · Feodo Tracker · Tor exit check · Team Cymru · MITRE ATT&CK · crt.sh · BGPView · WHOIS · NVD · maclookup · LOLBas · blockchain · event IDs · decode · DNS-over-HTTPS · wafw00f

**Free tier, registration required:** IBM X-Force Exchange (IBM ID required; free community tier, no credit card needed) · IPInfo (50,000 req/month keyless; key increases limits)

**Optional (paid/free tier):** Censys (250 queries/month free)

**Self-hosted (optional):** MISP · Graylog · DFIR-IRIS · Wazuh

---

## Development

```bash
# Run tests (Docker — recommended)
make test

# Run tests (local venv)
.venv/bin/pytest

# Run a single test file
.venv/bin/pytest tests/test_virustotal.py -v
```

Step-by-step investigation workflows: [docs/usage-guide.md](docs/usage-guide.md)

Architecture and contribution guide: [docs/architecture.md](docs/architecture.md)
