# swiss — Roadmap

## Legend
- ✅ Done
- 🔄 In progress
- 🔲 Planned
- 💡 Idea / under consideration

---

## Phase 1 — Foundation ✅
Core infrastructure and the most-used SOC lookup sources.

- ✅ FastMCP server skeleton, config system, mode-600 enforcement
- ✅ IOC auto-detection (`detect_ioc_type`) with defang normalization
- ✅ TTL cache (`lib/cache.py`)
- ✅ Parallel fan-out (`_parallel`) across all enabled sources
- ✅ Favorites system — dynamic dedicated tool per integration
- ✅ VirusTotal, AbuseIPDB, GreyNoise, Shodan, IPInfo, IBM X-Force, AlienVault OTX
- ✅ urlscan.io (history-first, submit only if no recent scan)
- ✅ MalwareBazaar, ThreatFox, URLhaus (abuse.ch suite)
- ✅ Project Honeypot, Feodo Tracker, Tor exit node check
- ✅ Team Cymru (ASN lookup + malware hash ratio, no API key)
- ✅ MISP, Graylog, DFIR-IRIS, Wazuh (private integrations)
- ✅ Custom blacklists (configurable URL list, exact-line match, TTL cache)
- ✅ Utility tools: WHOIS, CVE/NVD, MAC lookup, User-Agent parser, Event IDs, LOLBas, blockchain, decode, DNS-over-HTTPS
- ✅ Censys host scanning (env-var credentials)

## Phase 2 — Recon & Active Checks ✅
Active and passive recon tooling beyond IP/domain enrichment.

- ✅ Passive recon: crt.sh, BGPView, DNS records (`lib/recon.py`)
- ✅ Internet exposure check: TCP probe + banner grab (`lib/exposure.py`)
- ✅ WAF detection via wafw00f subprocess (`lib/waf.py`)
- ✅ MITRE ATT&CK technique lookup (STIX bundle, 24h cache)

## Phase 3 — Packaging & CI/CD ✅
Production-grade delivery and quality gates.

- ✅ Dockerfile (`python:3.12-slim`)
- ✅ `.dockerignore`
- ✅ GitHub Actions CI: test matrix Python 3.11 / 3.12 / 3.13
- ✅ GitHub Actions CD: build + push multi-arch image (`linux/amd64` + `linux/arm64`) to `ghcr.io/bunnyiesart/swiss` on merge to main
- ✅ GHA layer cache (`type=gha`) for fast rebuilds

## Phase 4 — Test Coverage 🔄
Bring every wrapper to the same standard as the Phase 1 core.

Missing test files (18 wrappers):

| Wrapper | Priority | Notes |
|---|---|---|
| `urlscan.py` | High | Complex: history-first, polling, 7-day window |
| `custom_blacklists.py` | High | Exact-line match, cache, multi-list fan-out |
| `alienvault.py` | High | Used in `lookup_ip`, `lookup_domain`, `lookup_hash` |
| `ipinfo.py` | Medium | Simple GET, straightforward |
| `ibm_xforce.py` | Medium | Basic-auth, covers IP/domain/hash/URL |
| `threatfox.py` | Medium | POST to abuse.ch, similar to MalwareBazaar |
| `urlhaus.py` | Medium | POST to abuse.ch |
| `whois.py` | Medium | Library call, timeout edge cases |
| `cve.py` | Medium | NVD API, CVSS parsing |
| `dns_doh.py` | Medium | DoH, record-type routing |
| `lolbas.py` | Medium | TTL cache + fuzzy name match |
| `useragent.py` | Low | Offline library, simple |
| `maclookup.py` | Low | Simple GET |
| `blockchain.py` | Low | Simple GET |
| `misp.py` | Low | Private — needs mock server |
| `graylog.py` | Low | Private — needs mock server |
| `dfir_iris.py` | Low | Private — needs mock server |
| `wazuh.py` | Low | Private — needs mock server |

## Phase 5 — New Integrations 🔲
Sources blocked by browser-only access or no public API — pending workarounds or new APIs.

| Source | Type | Blocker |
|---|---|---|
| Talos Intelligence | IP / domain reputation | No public REST API |
| Barracuda Central | IP reputation | No public REST API |
| MXToolbox | DNS / blacklist | Rate-limited; possible unofficial API |
| Microsoft Error Code DB | Utility | Browser-only |
| Winbindex | PE hash → Windows file | Browser-only; scraping feasible |
| fileinfo.com | File type lookup | Browser-only |
| Pulsedive | IP / domain / URL | Free API key available |
| Hybrid Analysis | Hash / URL sandbox | Free API key available |
| Any.run | Hash / URL sandbox | Free API key available |
| Maltiverse | IP / domain / hash | Free API key available |
| CIRCL MISP feeds | Hash / IP | Public feeds, no key |
| EmailRep | Email address reputation | Free API key available |

## Phase 6 — UX & Performance 💡
Quality-of-life improvements once the integration surface is stable.

- 🔲 Async I/O (replace `ThreadPoolExecutor` with `asyncio` + `httpx`) — lower latency for fan-out tools
- 🔲 Result scoring — single `risk_score` field aggregated across sources on `enrich()`
- 🔲 `lookup_email(email)` aggregated tool — EmailRep + HaveIBeenPwned + VirusTotal
- 🔲 Structured severity tags on each result (`clean` / `suspicious` / `malicious` / `unknown`)
- 🔲 Per-integration timeout config (some sources are consistently slower)
- 🔲 `--dry-run` / `--list-tools` CLI flags for local debugging without Claude
- 🔲 Changelog auto-generation from conventional commits

## Phase 7 — Security Hardening 💡
Defense-in-depth for a tool that handles sensitive IOCs.

- 🔲 Input length limits and character validation on all tool parameters
- 🔲 Rate-limit awareness — respect `X-RateLimit-*` headers, back off gracefully instead of erroring
- 🔲 Secret scanning in CI (e.g. `truffleHog` / `gitleaks`) to catch accidental key commits
- 🔲 SBOM generation on Docker publish
- 🔲 Dependabot / Renovate for dependency updates
