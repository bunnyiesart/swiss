# Tools

swiss exposes three categories of MCP tools: aggregated enrichment tools, dedicated (favorited) tools, and utility tools.

---

## Aggregated enrichment tools

These fan out to all enabled sources in parallel. Sources that aren't configured are silently omitted from the result. The return value is a dict keyed by source name.

### `lookup_ip(ip)`

Investigate an IP address across all enabled threat intelligence sources.

**Sources:** VirusTotal · AbuseIPDB · GreyNoise · Shodan · IPInfo · IBM X-Force · AlienVault OTX · Project Honeypot · Feodo Tracker · Tor exit check · Team Cymru · MISP* · Graylog* · DFIR-IRIS* · Wazuh* · custom blacklists*

*private — only included when `enabled: true` in config*

**Notes:**
- Project Honeypot is IPv4-only and is automatically skipped for IPv6 addresses.
- GreyNoise runs without an API key (community tier). Set an API key for enterprise data.

**Example:**
```
lookup_ip("185.220.101.47")
```

```json
{
  "virustotal":  {"malicious": 12, "suspicious": 0, "country": "DE", ...},
  "abuseipdb":   {"abuse_confidence_score": 100, "total_reports": 847, ...},
  "greynoise":   {"noise": true, "classification": "malicious", ...},
  "shodan":      {"open_ports": [80, 443, 9001], "org": "Frantech Solutions", ...},
  "tor_exit":    {"is_exit_node": true},
  ...
}
```

---

### `lookup_domain(domain)`

Investigate a domain across all enabled threat intelligence sources.

**Sources:** VirusTotal · AlienVault OTX · WHOIS · urlscan.io · IBM X-Force · MISP* · Graylog* · DFIR-IRIS* · custom blacklists*

**Example:**
```
lookup_domain("evil-phishing.com")
```

---

### `lookup_hash(hash)`

Look up a file hash across all enabled threat intelligence sources.

**Sources:** VirusTotal · MalwareBazaar · ThreatFox · IBM X-Force · AlienVault OTX · Team Cymru (MHR, MD5 only) · MISP* · custom blacklists*

**Accepts:** MD5 (32 hex) · SHA1 (40 hex) · SHA256 (64 hex)

**Example:**
```
lookup_hash("44d88612fea8a8f36de82e1278abb02f")
```

---

### `lookup_url(url)`

Investigate a URL across all enabled threat intelligence sources.

**Sources:** VirusTotal · urlscan.io · URLhaus · IBM X-Force · MISP* · custom blacklists*

**Example:**
```
lookup_url("https://evil.example.com/payload.exe")
```

---

### `enrich(ioc)`

Auto-detect the IOC type and dispatch to the appropriate `lookup_*` tool. Also handles defanged input.

**Detected types:** IP · domain · URL · MD5 · SHA1 · SHA256 · CVE · MAC address

**Defanging support:** `hxxps://` → `https://` · `evil[.]com` → `evil.com` · `1.1.1[.]1` → `1.1.1.1`

**Returns:** `{"ioc_type": "<type>", "results": {...}}`

**Example:**
```
enrich("hxxps://evil[.]com/malware.exe")
```
```json
{
  "ioc_type": "url",
  "results": {
    "virustotal": {...},
    "urlscan": {...},
    ...
  }
}
```

---

## Dedicated (favorited) tools

Each favorited integration gets its own dedicated MCP tool at startup. These call only that one source — no fan-out, lower latency.

The tool name is the service key. The default set:

### `virustotal(ioc)`

Check any IOC against VirusTotal. Accepts IP, domain, hash (MD5/SHA1/SHA256), or URL.

### `abuseipdb(ip)`

Check an IPv4 address against AbuseIPDB. Returns abuse confidence score, total reports, usage type, and ISP.

### `greynoise(ip)`

Check an IPv4 address against GreyNoise. Returns `noise` (is it mass-scanning the internet?), `riot` (is it a known benign service?), and classification.

- **No key:** community tier — noise/riot/classification/name
- **With key:** enterprise tier — adds tags, metadata, raw_data, first_seen

### `shodan(ip)`

Check an IPv4 address against Shodan. Returns open ports, detected vulnerabilities, organization, country, and hostnames.

### `urlscan(target)`

Submit a domain or URL to urlscan.io. History-first: checks for an existing scan within the last 7 days before submitting a new one. Returns page title, screenshot URL, DOM summary, and verdict.

### `malwarebazaar(hash)`

Look up a file hash (MD5/SHA1/SHA256) on MalwareBazaar. Returns file name, type, size, signature (malware family), tags, and ClamAV detections.

### `cymru(ioc)`

Query Team Cymru's free DNS-based services. No API key required.

- **IP** → ASN origin lookup: ASN number, announced prefix, country, registry, allocation date, and org name
- **MD5 hash** → Malware Hash Registry (MHR): last seen date and AV detection percentage across Cymru's sensor network

Other IOC types return an unsupported error.

### `misp(ioc)` *(private, when enabled)*

Check any IOC against your MISP instance. Returns matched attributes and event count.

---

## Utility tools

These tools do not query threat intel sources — they perform analysis, lookups, or decoding locally or against single authoritative sources.

### `lookup_technique(technique_id)`

Look up a MITRE ATT&CK technique. Uses the enterprise STIX bundle fetched from MITRE's GitHub and cached for 24 hours. Revoked and deprecated techniques are excluded.

**Accepts:** Technique ID (`T1059`, `T1059.001`) or name (`PowerShell`) — case-insensitive.

**Returns:** Name, tactics, platforms, description, detection guidance, mitigations (up to 10), and ATT&CK URL.

**No API key required.**

**Example:** `lookup_technique("T1059.001")`

```json
{
  "source": "mitre",
  "found": true,
  "id": "T1059.001",
  "name": "PowerShell",
  "tactics": ["execution"],
  "platforms": ["Windows"],
  "description": "Adversaries may abuse PowerShell...",
  "detection": "Monitor process execution...",
  "mitigations": ["Disable or Remove Feature or Program"],
  "url": "https://attack.mitre.org/techniques/T1059/001/"
}
```

---

### `lookup_cve(cve_id)`

Look up a CVE in the NVD 2.0 database.

**Returns:** Published date, last modified, English description, CVSS v3.1 base score and severity, CWE list, first 5 reference URLs.

**Example:** `lookup_cve("CVE-2021-44228")`

---

### `lookup_mac(mac)`

Look up the manufacturer for a MAC address via maclookup.app.

**Accepts:** Any common MAC format — `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF`, `AABB.CCDD.EEFF`

**Returns:** Vendor name, country, OUI type (UAA/LAA/multicast).

---

### `lookup_useragent(ua)`

Parse a User-Agent string into its components. Fully offline — uses the ua-parser library.

**Returns:** Browser family and version, OS family and version, device family, `is_mobile`, `is_bot`.

**Example:** `lookup_useragent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...")`

---

### `lookup_eventid(event_id, platform)`

Look up a Windows, Sysmon, Exchange, SharePoint, or SQL Server event ID. Uses a bundled JSON file — no network call.

**Parameters:**
- `event_id` — event ID number as a string, e.g. `"4624"`
- `platform` — `windows` (default) · `sysmon` · `exchange` · `sharepoint` · `sql`

**Returns:** Event name, description, category, MITRE ATT&CK technique IDs.

**Coverage:** ~80 events including Windows Security (4608–7045), Sysmon 1–29, Exchange, SharePoint, SQL Server audit events.

---

### `lookup_lolbas(name)`

Search the LOLBas (Living Off The Land Binaries and Scripts) database. Fetched from the LOLBas GitHub feed and cached for 30 minutes.

**Example:** `lookup_lolbas("certutil")`

**Returns:** Description, commands with use cases (execute/download/bypass/etc.), detection hints, and references.

---

### `lookup_blockchain(address)`

Look up a Bitcoin address or transaction hash on blockchain.com.

**Accepts:**
- Bitcoin address (Base58) → returns balance, transaction count, and recent transactions
- 64-character transaction hash → returns block height, fee, input/output summary

---

### `decode(value, encoding)`

Decode or transform an encoded string. Fully offline — no network calls.

**Encodings:**
| Value | What it does |
|---|---|
| `base64` | Standard base64 decode |
| `base64url` | URL-safe base64 decode |
| `hex` | Hex string → UTF-8 |
| `url` | URL percent-decode |
| `rot13` | ROT13 transform |
| `defang` | Inverse re-fang: `https://` → `hxxps://`, `.` → `[.]` |
| `magic` | Try all encodings, return those producing ≥80% printable ASCII (default) |

**Example:** `decode("aGVsbG8=")` → `{"output": "hello", "encoding": "base64"}`

---

### `resolve_domain(domain, record_type)`

Resolve a domain using DNS-over-HTTPS via Google DNS (`dns.google/resolve`).

**Record types:** `A` (default) · `AAAA` · `MX` · `NS` · `TXT` · `CNAME` · `SOA`

**Returns:** DNS answers with record data and TTL, status code, and status name.

**Example:** `resolve_domain("google.com", "MX")`
