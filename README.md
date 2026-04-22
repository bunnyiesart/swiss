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

Set your API keys as environment variables (e.g. `SWISS_VIRUSTOTAL_API_KEY=...`), then register with Claude Code by adding this to `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "swiss": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/home/you/.config/swiss/config.json:/config/swiss.json:ro",
        "-e", "SWISS_CONFIG_PATH=/config/swiss.json",
        "ghcr.io/bunnyiesart/swiss:latest"
      ]
    }
  }
}
```

Replace `/home/you/...` with the absolute path to your config file. `-i` (not `-t`) is required for stdio MCP transport. Restart Claude Code after updating `mcp.json`, then call `lookup_ip("8.8.8.8")` to verify.

---

## Quick start (local venv)

```bash
git clone https://github.com/bunnyiesart/swiss
cd swiss
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Create your config file as above, set credentials as environment variables, then register with Claude Code:

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

Env var format: `SWISS_<SERVICE>_<FIELD>` (all caps). Examples:

```bash
export SWISS_VIRUSTOTAL_API_KEY="..."
export SWISS_ABUSEIPDB_API_KEY="..."
export SWISS_GREYNOISE_API_KEY="..."        # optional — omit for community tier
export SWISS_MALWAREBAZAAR_API_KEY="..."    # same key covers ThreatFox + URLhaus
export SWISS_CENSYS_API_KEY="..."           # API ID
export SWISS_CENSYS_API_PASSWORD="..."      # API Secret
export SWISS_MISP_URL="https://misp.internal"
export SWISS_MISP_API_KEY="..."
```

---

## Integrations

Detailed per-integration docs including where to get API keys, tier differences, and returned fields: [docs/integrations.md](docs/integrations.md)

**Free keys required:** VirusTotal · AbuseIPDB · GreyNoise · Shodan · IPInfo · AlienVault OTX · urlscan.io · Project Honeypot · MalwareBazaar · ThreatFox · URLhaus (last three share one key from [auth.abuse.ch](https://auth.abuse.ch/))

**Works without any key:** GreyNoise (community tier) · Feodo Tracker · Tor exit check · Team Cymru · MITRE ATT&CK · crt.sh · BGPView · WHOIS · NVD · maclookup · LOLBas · blockchain · event IDs · decode · DNS-over-HTTPS · wafw00f

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

Architecture and contribution guide: [docs/architecture.md](docs/architecture.md)
