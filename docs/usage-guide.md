# Usage guide

Step-by-step workflows for common SOC analyst tasks. Each section shows what to say to Claude, which tool fires, and what to focus on in the result.

---

## 1. Verify your setup

Before your first real investigation, confirm the server is alive and at least the keyless sources are responding:

> "look up 8.8.8.8"

Claude calls `lookup_ip("8.8.8.8")`. With no API keys at all you should still see results from GreyNoise (community tier), Team Cymru, Feodo Tracker, and Tor exit check:

```json
{
  "greynoise": {"noise": false, "riot": true, "name": "Google Public DNS", ...},
  "cymru":     {"asn": "15169", "org": "Google LLC", "country": "US", ...},
  "feodo":     {"listed": false},
  "tor_exit":  {"is_exit_node": false}
}
```

If every source comes back `"error": "not_configured"`, your env vars aren't being picked up. See [configuration.md](configuration.md).

---

## 2. Investigate a suspicious IP

An IP appears in a firewall alert, proxy log, or SIEM hit.

> "investigate 185.220.101.47"
> "what do we know about 185.220.101.47?"

Claude calls `lookup_ip("185.220.101.47")` and fans out to all configured sources in parallel. Key fields to read:

| Source | Field | What it tells you |
|---|---|---|
| `abuseipdb` | `abuse_confidence_score` | > 80 = strong signal; 100 = widely confirmed |
| `abuseipdb` | `total_reports` | how many reporters, over what time period |
| `greynoise` | `noise` + `classification` | `noise: true, classification: "malicious"` = known mass-scanner |
| `greynoise` | `riot` | `true` = known benign service (CDN, DNS resolver, etc.) |
| `tor_exit` | `is_exit_node` | `true` = traffic may be anonymized through Tor |
| `feodo` | `listed` | `true` = confirmed botnet C2 (Dridex, Emotet, etc.) |
| `virustotal` | `malicious` | engine count that flagged this IP |
| `shodan` | `open_ports` | unexpected ports are suspicious (9001 = Tor relay, 4444 = common RAT) |
| `cymru` | `asn` + `org` | ASN attribution — useful for blocklist scope |

**Want just one source fast?**

> "greynoise check on 185.220.101.47"
> "abuseipdb score for 185.220.101.47"

Claude calls `greynoise("185.220.101.47")` or `abuseipdb("185.220.101.47")` directly — no fan-out overhead.

---

## 3. Investigate a suspicious domain

A domain appears in a phishing email, DNS log, or proxy block.

> "look up the domain evil-c2.example.com"
> "what is evil-c2.example.com?"

Claude calls `lookup_domain("evil-c2.example.com")`. Key fields:

| Source | Field | What it tells you |
|---|---|---|
| `virustotal` | `malicious` | engine count |
| `whois` | `creation_date` | registered recently = suspicious |
| `whois` | `registrar` | some registrars are known abuse havens |
| `urlscan` | `malicious` + `screenshot` | page verdict and a screenshot URL to review |
| `alienvault` | `pulse_count` | how many OTX threat feeds reference this domain |

**For infrastructure context — subdomains, DNS records, cert history:**

> "passive recon on evil-c2.example.com"
> "what subdomains does evil-c2.example.com have?"

Claude calls `recon("evil-c2.example.com")` and returns:

- **crt.sh** — all subdomains that have had TLS certificates issued (passive subdomain enumeration)
- **DNS** — A, AAAA, MX, NS, TXT, CNAME records
- **WHOIS** — registrar, creation date, nameservers

**Get a live page render and screenshot:**

> "urlscan this domain: evil-c2.example.com"

Claude calls `urlscan("evil-c2.example.com")`. Returns page title, IP, country, DOM summary, and a `screenshot` URL you can open in a browser.

---

## 4. Investigate a suspicious file hash

A hash comes from endpoint telemetry, a sandbox report, or a memory dump.

> "is this hash malicious? 44d88612fea8a8f36de82e1278abb02f"
> "look up hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

Claude calls `lookup_hash(hash)` and fans out to VirusTotal, MalwareBazaar, ThreatFox, IBM X-Force, AlienVault OTX, and Team Cymru (MD5 only).

Key fields:

| Source | Field | What it tells you |
|---|---|---|
| `virustotal` | `malicious` | engine count; check `name` for the family name |
| `malwarebazaar` | `signature` | malware family name |
| `malwarebazaar` | `tags` | e.g. `["emotet", "loader"]` |
| `threatfox` | `iocs` | C2 addresses this hash was seen communicating with |
| `cymru` | `detection_pct` | percentage of Cymru's sensor network that flagged it (MD5 only) |

**Team Cymru's Malware Hash Registry works with no API key:**

> "cymru check this MD5: 44d88612fea8a8f36de82e1278abb02f"

Claude calls `cymru("44d88612fea8a8f36de82e1278abb02f")` and returns `last_seen` and `detection_pct` instantly via DNS.

---

## 5. Investigate a suspicious URL

A URL appears in a phishing email, proxy log, or EDR command-line.

> "look up https://evil.example.com/invoice.exe"
> "is this URL malicious? https://evil.example.com/payload.zip"

Claude calls `lookup_url(url)` and checks VirusTotal, urlscan.io, URLhaus, and IBM X-Force.

**Get a page render and screenshot directly:**

> "scan https://evil.example.com on urlscan"

Claude calls `urlscan("https://evil.example.com")`. urlscan searches for an existing scan first (within the last 7 days). A new scan is only submitted if none is found — so for well-known domains the result is near-instant.

---

## 6. Work with defanged IOCs

Threat intel reports, CTI feeds, and email notifications routinely defang IOCs to prevent accidental clicks. Paste them directly — swiss re-fangs them automatically when you use `enrich`.

> "enrich hxxps://malicious[.]example[.]com/payload.exe"
> "investigate 185[.]220[.]101[.]47"
> "what is this: 44d88612fea8a8f36de82e1278abb02f"

Claude calls `enrich(ioc)` which:
1. Re-fangs the input (`hxxp://` → `http://`, `[.]` → `.`, `[:]` → `:`, `[at]` → `@`)
2. Detects the IOC type: IP · domain · URL · MD5 · SHA1 · SHA256 · CVE · MAC address
3. Dispatches to the right `lookup_*` tool

The result includes an `ioc_type` field so you can confirm detection was correct:

```json
{"ioc_type": "url", "results": {"virustotal": {...}, "urlscan": {...}, ...}}
```

---

## 7. Check whether a service is exposed

During lateral movement investigation, firewall rule validation, or before a deployment.

> "is SSH exposed on 10.1.2.3?"
> "check if port 3389 on 192.168.1.50 is reachable from the internet"

Claude calls `check_exposure("10.1.2.3", 22)` which runs:

- **Active TCP probe** — reports `reachable: true/false`, round-trip latency, and any grabbed banner
- **Shodan** — historical scan data for that host (if key configured)
- **Censys** — same (if key configured)

Without a port:

> "what does Shodan show for 203.0.113.5?"

Claude calls `check_exposure("203.0.113.5")` for passive data only (no active probe).

---

## 8. Fingerprint a WAF

During phishing infrastructure analysis, red team work, or before submitting a scan.

> "what WAF is in front of https://target.example.com?"
> "detect waf on https://shop.example.com"

Claude calls `detect_waf("https://target.example.com")` using wafw00f with all signatures enabled.

```json
{
  "source": "waf",
  "url": "https://target.example.com",
  "detected": ["Cloudflare"],
  "generic_detected": false
}
```

- `detected: []` — no WAF identified
- `generic_detected: true` — a WAF is present but couldn't be fingerprinted
- `detected: ["Cloudflare", "ModSecurity"]` — multiple matches (run with `-a` flag)

---

## 9. Look up a MITRE ATT&CK technique

During incident response, when writing detection rules, or drafting a report.

> "what is T1059.001?"
> "look up the PowerShell ATT&CK technique"
> "what techniques cover Tor C2?"

Claude calls `lookup_technique("T1059.001")` or `lookup_technique("PowerShell")`. Accepts technique ID or name — case-insensitive. Returns tactics, platforms, description, detection guidance, mitigations, and the ATT&CK URL.

> The first call in a session downloads the ~20 MB MITRE enterprise STIX bundle from GitHub. It's cached for 24 hours — subsequent calls are instant.

---

## 10. Look up a CVE

> "what is CVE-2021-44228?"
> "show me the Log4Shell vulnerability"
> "CVSS score for CVE-2023-44487?"

Claude calls `lookup_cve("CVE-2021-44228")`. Returns CVSS v3 score and severity, published and last-modified dates, description, CWEs, and reference URLs from NVD.

---

## 11. Decode a suspicious string

All encoding/decoding is fully offline.

**Base64** — common in obfuscated PowerShell, phishing payloads, and encoded C2 traffic:

> "decode aGVsbG8="
> "what is this base64: cG93ZXJzaGVsbA=="

Claude calls `decode("aGVsbG8=", "base64")` → `{"output": "hello"}`

**Hex** — common in shellcode, registry values:

> "decode hex 68656c6c6f"

**URL-encoded** — common in web logs and phishing links:

> "decode %68%65%6c%6c%6f"

**ROT13** — common in forum posts, CTF challenges:

> "decode rot13: uryyb"

**Not sure of the encoding?**

> "what is this string: aGVsbG8="

Claude calls `decode("aGVsbG8=", "magic")` which tries all encodings and returns every one that decodes to ≥80% printable ASCII.

**Defang an IOC for pasting into a report or ticket:**

> "defang https://evil.example.com"

Claude calls `decode("https://evil.example.com", "defang")` → `"hxxps://evil[.]example[.]com"`

---

## 12. Look up a Windows or Sysmon event ID

During log review, detection engineering, or alert triage. Fully offline — uses a bundled JSON file.

> "what is Windows event 4624?"
> "what does Sysmon event 1 mean?"
> "look up event ID 7045"

Claude calls `lookup_eventid("4624", "windows")` or `lookup_eventid("1", "sysmon")`. Returns the event name, description, category, and mapped MITRE ATT&CK technique IDs.

Supported platforms: `windows` · `sysmon` · `exchange` · `sharepoint` · `sql`

---

## 13. Check a living-off-the-land binary

During malware analysis, incident response, or writing detection rules.

> "what can certutil do maliciously?"
> "lolbas lookup mshta"
> "how is rundll32 abused?"

Claude calls `lookup_lolbas("certutil")`. Returns known malicious use cases (execute, download, bypass, etc.), example commands, detection hints, and references — sourced from the LOLBas GitHub feed.

---

## 14. Look up a MAC address

When you find an unknown device in your network, or see a MAC in an ARP table, DHCP log, or 802.1X event.

> "who makes the device with MAC 00:50:56:a4:bd:5a?"
> "look up MAC address 00-1A-2B-3C-4D-5E"

Claude calls `lookup_mac("00:50:56:a4:bd:5a")`. Returns manufacturer name, country, and OUI type. `00:50:56` is VMware — a MAC in this range on a physical network segment is unusual.

---

## 15. Parse a User-Agent string

From WAF logs, proxy logs, or IDS alerts. Fully offline.

> "parse this user agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ..."
> "is this user agent a bot? curl/7.68.0"

Claude calls `lookup_useragent(ua)`. Returns browser family, browser version, OS family, OS version, device type, `is_mobile`, and `is_bot`.

---

## 16. Resolve a domain

DNS resolution over HTTPS via Google DNS — useful when you want to avoid touching your local resolver's cache, or when working in a remote environment.

> "resolve evil.example.com"
> "what are the MX records for gmail.com?"
> "TXT records for example.com"

Claude calls `resolve_domain("gmail.com", "MX")`. Returns DNS answers with record data and TTL.

Supported record types: `A` · `AAAA` · `MX` · `NS` · `TXT` · `CNAME` · `SOA`

---

## Putting it together: a full triage

An IDS fires on outbound traffic from a workstation to `185.220.101.47:9001`.

**Step 1 — Fan-out on the destination IP:**
> "investigate 185.220.101.47"

→ `lookup_ip("185.220.101.47")` comes back: Tor exit node, AbuseIPDB score 100, GreyNoise classification `malicious`, open port 9001.

**Step 2 — Check the suspicious process hash from the endpoint:**
> "look up hash 44d88612fea8a8f36de82e1278abb02f"

→ `lookup_hash(...)` returns MalwareBazaar signature `Emotet`, ThreatFox C2 matches, VT detection count.

**Step 3 — Identify the technique:**
> "what ATT&CK technique is Tor-based C2 traffic?"

→ `lookup_technique("T1090.003")` returns Proxy: Multi-hop Proxy — tactics, detection guidance, mitigations.

**Step 4 — Decode a suspicious PowerShell argument from the process tree:**
> "decode this base64: cG93ZXJzaGVsbCAtZW5jb2RlZA=="

→ `decode(...)` returns the plaintext command.

**Step 5 — Check the binary being abused:**
> "lolbas certutil"

→ `lookup_lolbas("certutil")` returns download and execute use cases with example commands.

**Step 6 — Look up the Sysmon event that captured it:**
> "what is Sysmon event 1?"

→ `lookup_eventid("1", "sysmon")` returns Process Create with MITRE T1059 mapping.

Each step builds context. swiss fans out in parallel and drops unconfigured sources silently, so you always get a dense result from whatever keys you have — and the gaps tell you exactly which integrations to set up next.

---

## Tips

**You don't need special syntax.** Just describe what you want. Claude understands "investigate", "look up", "decode", "what is", "check", "scan", etc. and routes to the right tool.

**Not_configured is not an error.** `{"error": "not_configured"}` means a source's API key isn't set. It's silently omitted from aggregated `lookup_*` results — it only appears if you call a dedicated tool (e.g. `virustotal()`) directly. Add the key and restart to unlock that source.

**Use dedicated tools for speed.** `greynoise("1.2.3.4")` is faster than `lookup_ip("1.2.3.4")` when you only care about noise classification. Same for `cymru`, `abuseipdb`, `shodan`, etc.

**Start with the aggregated tool, drill with dedicated ones.** Run `lookup_ip` first to see the full picture, then call `shodan("ip")` or `abuseipdb("ip")` directly if you need to dig into a specific source.

**GreyNoise works with no key.** The community tier returns noise/riot/classification. Set `SWISS_GREYNOISE_API_KEY` for enterprise data (tags, metadata, raw port/path data).

**Three abuse.ch tools share one key.** MalwareBazaar, ThreatFox, and URLhaus all use `SWISS_MALWAREBAZAAR_API_KEY` / `SWISS_THREATFOX_API_KEY` / `SWISS_URLHAUS_API_KEY` — but you register once at [auth.abuse.ch](https://auth.abuse.ch/) and copy the same key into all three.

**Team Cymru needs no key at all.** `cymru("ip")` for ASN attribution and `cymru("md5")` for malware hash ratio work via DNS — no registration, no rate limit.
