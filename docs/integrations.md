# Integrations

Per-integration reference: where to get API keys, tier differences, and what fields are returned.

---

## VirusTotal

**Key:** Required for any queries. Free tier: 4 requests/min, 500/day.

**Get key:** [virustotal.com](https://www.virustotal.com/) → sign in → profile → API key

**Methods:** `check_ip` · `check_domain` · `check_hash` · `check_url`

**Returned fields (IP):**
```json
{
  "source": "virustotal",
  "malicious": 3,
  "suspicious": 0,
  "harmless": 58,
  "undetected": 10,
  "country": "DE",
  "asn": 51167,
  "as_owner": "Contabo GmbH",
  "tags": ["tor"],
  "last_analysis_date": "2024-01-15T12:00:00"
}
```

**Returned fields (hash):** adds `name`, `type_description`, `size`, `meaningful_name`, `popular_threat_classification`

**Returned fields (URL):** adds `url`, `title`, `final_url`, `last_final_url`

---

## AbuseIPDB

**Key:** Required. Free tier: 1,000 checks/day.

**Get key:** [abuseipdb.com](https://www.abuseipdb.com/) → sign in → API

**Methods:** `check_ip`

**Returned fields:**
```json
{
  "source": "abuseipdb",
  "ip": "1.2.3.4",
  "abuse_confidence_score": 87,
  "total_reports": 142,
  "num_distinct_users": 38,
  "last_reported_at": "2024-01-15T10:22:00+00:00",
  "isp": "Frantech Solutions",
  "usage_type": "Data Center/Web Hosting/Transit",
  "domain": "frantech.ca",
  "country_code": "CA",
  "is_tor": false,
  "is_public": true
}
```

---

## GreyNoise

**Key:** Optional. Without a key the community tier is used automatically.

**Get key:** [greynoise.io](https://www.greynoise.io/) → sign up → free community key

**Tier differences:**

| Field | Community (no key) | Enterprise (with key) |
|---|---|---|
| noise / riot / classification | ✓ | ✓ |
| name, link, last_seen | ✓ | ✓ |
| tags | — | ✓ |
| metadata (org, country, OS, etc.) | — | ✓ |
| raw_data (ports, paths, useragents) | — | ✓ |
| first_seen | — | ✓ |

**Returned fields (community):**
```json
{
  "source": "greynoise",
  "ip": "1.2.3.4",
  "noise": true,
  "riot": false,
  "classification": "malicious",
  "name": "unknown",
  "last_seen": "2024-01-15"
}
```

---

## Shodan

**Key:** Required. Free tier gives limited API access (no filters, 1 result/query).

**Get key:** [shodan.io](https://www.shodan.io/) → sign up → account overview

**Methods:** `check_ip`

**Returned fields:**
```json
{
  "source": "shodan",
  "ip": "1.2.3.4",
  "found": true,
  "org": "Frantech Solutions",
  "isp": "Frantech Solutions",
  "country_name": "Canada",
  "hostnames": ["ns1.frantech.ca"],
  "open_ports": [22, 80, 443],
  "vulns": ["CVE-2021-44228"],
  "tags": ["cdn"],
  "last_update": "2024-01-15T00:00:00"
}
```

---

## IPInfo

**Key:** Optional on the free tier (50,000 requests/month). Key increases limits.

**Get key:** [ipinfo.io](https://ipinfo.io/) → sign up

**Methods:** `check_ip`

**Returned fields:**
```json
{
  "source": "ipinfo",
  "ip": "1.2.3.4",
  "hostname": "example.com",
  "city": "Toronto",
  "region": "Ontario",
  "country": "CA",
  "org": "AS3257 GTT Communications Inc.",
  "timezone": "America/Toronto",
  "is_vpn": false,
  "is_proxy": false,
  "is_tor": false
}
```

*Privacy fields (`is_vpn`, `is_proxy`, `is_tor`) only appear on paid tiers.*

---

## IBM X-Force Exchange

**Key:** Requires both `api_key` and `api_password` (Basic Auth pair).

**Get key:** [ibm.com](https://exchange.xforce.ibmcloud.com/) → sign in with IBM ID → API access

**Methods:** `check_ip` · `check_domain` · `check_hash` · `check_url`

**Returned fields (IP):**
```json
{
  "source": "ibm_xforce",
  "ip": "1.2.3.4",
  "score": 8.4,
  "categories": {"Botnet": true},
  "geo": {"country": "Germany"},
  "subnets": [{"subnet": "1.2.3.0/24", "score": 8.4}]
}
```

---

## AlienVault OTX

**Key:** Required. Free.

**Get key:** [otx.alienvault.com](https://otx.alienvault.com/) → sign up → settings → API key

**Methods:** `check_ip` · `check_domain` · `check_hash`

**Returned fields:**
```json
{
  "source": "alienvault",
  "ip": "1.2.3.4",
  "country": "Germany",
  "asn": "AS51167 Contabo GmbH",
  "pulse_count": 14,
  "malware_families": ["Mirai", "Gafgyt"],
  "industries": ["Government"]
}
```

---

## urlscan.io

**Key:** Required for submissions. Free tier: 100 public scans/day.

**Get key:** [urlscan.io](https://urlscan.io/) → sign up → settings → API key

**Methods:** `check_domain` · `check_url`

**Behaviour:** History-first — searches for an existing scan within the last 7 days before submitting a new one. Returns `{"pending": true, "uuid": "..."}` if a new scan is submitted but hasn't completed within 30 seconds.

**Returned fields:**
```json
{
  "source": "urlscan",
  "url": "https://evil.com/",
  "domain": "evil.com",
  "ip": "1.2.3.4",
  "country": "DE",
  "title": "Login - My Bank",
  "server": "nginx",
  "screenshot": "https://urlscan.io/screenshots/...",
  "verdict_score": 85,
  "verdict_malicious": true,
  "brands": ["PayPal"],
  "scan_date": "2024-01-15T12:00:00"
}
```

---

## Project Honeypot (HTTP:BL)

**Key:** Required. Free.

**Get key:** [projecthoneypot.org](https://www.projecthoneypot.org/) → sign up → HTTP:BL access key

**Methods:** `check_ip` (IPv4 only — IPv6 returns `{"error": "ipv6_not_supported"}`)

**How it works:** DNS-based lookup — reverses the IP octets, prepends the API key, queries `{key}.{reversed_ip}.dnsbl.httpbl.org`. No HTTP requests.

**Returned fields:**
```json
{
  "source": "honeypot",
  "ip": "1.2.3.4",
  "listed": true,
  "days_since_last": 3,
  "threat_score": 75,
  "visitor_types": ["comment_spammer", "harvester"]
}
```

---

## MalwareBazaar

**Key:** Required. Free via [auth.abuse.ch](https://auth.abuse.ch/).

> The same key from auth.abuse.ch covers MalwareBazaar, ThreatFox, and URLhaus.

**Methods:** `check_hash` (MD5/SHA1/SHA256)

**Returned fields (found):**
```json
{
  "source": "malwarebazaar",
  "found": true,
  "file_name": "invoice.exe",
  "file_type": "exe",
  "file_size": 472064,
  "md5": "...",
  "sha1": "...",
  "sha256": "...",
  "first_seen": "2024-01-10 08:00:00",
  "last_seen": "2024-01-15 12:00:00",
  "signature": "Emotet",
  "tags": ["emotet", "loader"],
  "reporter": "abuse_ch",
  "intelligence": ["Doc.Downloader.Emotet"]
}
```

---

## ThreatFox

**Key:** Required. Free via [auth.abuse.ch](https://auth.abuse.ch/).

**Methods:** `check_hash`

**Returned fields (found):**
```json
{
  "source": "threatfox",
  "found": true,
  "count": 3,
  "iocs": [
    {
      "ioc": "1.2.3.4:4444",
      "ioc_type": "ip:port",
      "threat_type": "botnet_cc",
      "malware": "Cobalt Strike",
      "confidence_level": 90,
      "first_seen": "2024-01-10 08:00:00",
      "tags": ["cobalt-strike"]
    }
  ]
}
```

---

## URLhaus

**Key:** Required. Free via [auth.abuse.ch](https://auth.abuse.ch/).

**Methods:** `check_url` · `check_host`

**Returned fields (URL, found):**
```json
{
  "source": "urlhaus",
  "found": true,
  "url_status": "online",
  "threat": "malware_download",
  "tags": ["exe", "Emotet"],
  "date_added": "2024-01-10 08:00:00",
  "reporter": "abuse_ch"
}
```

---

## Feodo Tracker

**Key:** None required.

**Methods:** `check_ip`

Fetches the Feodo Tracker JSON blocklist once and caches it for 5 minutes. Queries are local after the first fetch.

**Returned fields:**
```json
{
  "source": "feodo",
  "ip": "1.2.3.4",
  "listed": true,
  "malware": "Dridex",
  "port": 443
}
```

---

## Tor Exit Nodes

**Key:** None required.

**Methods:** `check_ip`

Fetches the Tor Project bulk exit node list once and caches it for 5 minutes.

**Returned fields:**
```json
{
  "source": "tor_exit",
  "ip": "1.2.3.4",
  "is_exit_node": true
}
```

---

## MISP *(private)*

**Key:** Requires `url` and `api_key`. `enabled: false` by default.

**Get key:** Your MISP instance → Administration → Auth Keys

**Methods:** `check_ip` · `check_domain` · `check_hash` · `check_url`

**Returned fields:**
```json
{
  "source": "misp",
  "found": true,
  "count": 5,
  "attributes": [
    {"type": "ip-dst", "value": "1.2.3.4", "event_id": 142, "category": "Network activity"}
  ]
}
```

---

## Graylog *(private)*

**Key:** Requires `url`, `username`, and `password`. `enabled: false` by default.

**Methods:** `top_events(ioc)` — searches last 24 hours, returns up to 10 hits.

**Returned fields:**
```json
{
  "source": "graylog",
  "total_count": 47,
  "recent_hits": [
    {"timestamp": "2024-01-15T12:00:00Z", "message": "...", "source": "firewall-01"}
  ]
}
```

---

## DFIR-IRIS *(private)*

**Key:** Requires `url` and `api_key`. `enabled: false` by default.

**Methods:** `related_cases(ioc)` — searches cases mentioning the IOC.

**Returned fields:**
```json
{
  "source": "dfir_iris",
  "case_count": 2,
  "cases": [
    {"case_id": 14, "title": "Ransomware Incident Jan 2024"}
  ]
}
```

---

## Wazuh *(private)*

**Key:** Requires `url`, `username`, and `password`. `enabled: false` by default.

**Methods:** `recent_alerts(ioc)` — queries alerts from the last 24 hours, limit 10.

**Returned fields:**
```json
{
  "source": "wazuh",
  "alert_count": 3,
  "alerts": [
    {"id": "1705312800.12345", "rule_description": "Web attack detected", "agent": "workstation-01"}
  ]
}
```

---

## Custom blacklists

Not a single service — swiss fetches each configured URL and checks for exact line matches.

**Returned value:** A list of matching entries (one per matching blacklist).

```json
"custom_blacklists": [
  {"name": "Internal C2 IPs", "url": "https://threat.internal/c2-ips.txt", "match": "185.220.101.47"}
]
```

See [configuration.md](configuration.md#custom-blacklists) for setup.
