import ipaddress
from datetime import datetime, timezone

from lib.dns_doh import DNSDoH

_MD5_LEN = 32


class Cymru:
    def __init__(self):
        self._doh = DNSDoH()

    def lookup_asn(self, ip: str) -> dict:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"source": "cymru", "ip": ip, "error": "invalid_ip"}

        try:
            if addr.version == 4:
                rev = ".".join(reversed(ip.split(".")))
                query = f"{rev}.origin.asn.cymru.com"
            else:
                expanded = addr.exploded.replace(":", "")
                rev = ".".join(reversed(expanded))
                query = f"{rev}.origin6.asn.cymru.com"

            r = self._doh.resolve(query, "TXT")
            if r.get("error"):
                return {"source": "cymru", "ip": ip, "error": r["error"]}
            if not r["answers"] or r.get("status_code") == 3:
                return {"source": "cymru", "ip": ip, "found": False}

            raw = r["answers"][0]["data"].strip('"').strip()
            parts = [p.strip() for p in raw.split("|")]
            if len(parts) < 5:
                return {"source": "cymru", "ip": ip, "error": "unexpected_response", "raw": raw}

            asn, prefix, country, registry, allocated = parts[:5]

            org = ""
            org_r = self._doh.resolve(f"AS{asn}.asn.cymru.com", "TXT")
            if not org_r.get("error") and org_r.get("answers"):
                org_raw = org_r["answers"][0]["data"].strip('"').strip()
                org_parts = [p.strip() for p in org_raw.split("|")]
                org = org_parts[-1] if org_parts else ""

            return {
                "source":    "cymru",
                "ip":        ip,
                "found":     True,
                "asn":       asn,
                "prefix":    prefix,
                "country":   country,
                "registry":  registry,
                "allocated": allocated,
                "org":       org,
            }
        except Exception as e:
            return {"source": "cymru", "ip": ip, "error": str(e)}

    def check_hash(self, hash_val: str) -> dict:
        if len(hash_val) != _MD5_LEN:
            return {"source": "cymru", "hash": hash_val, "error": "md5_only"}

        try:
            query = f"{hash_val.lower()}.malware.hash.cymru.com"
            r = self._doh.resolve(query, "TXT")
            if r.get("error"):
                return {"source": "cymru", "hash": hash_val, "error": r["error"]}
            if not r["answers"] or r.get("status_code") == 3:
                return {"source": "cymru", "hash": hash_val, "found": False}

            raw = r["answers"][0]["data"].strip('"').strip()
            parts = [p.strip() for p in raw.split("|")]
            if len(parts) < 2:
                return {"source": "cymru", "hash": hash_val, "error": "unexpected_response", "raw": raw}

            last_seen = datetime.fromtimestamp(int(parts[0]), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            return {
                "source":        "cymru",
                "hash":          hash_val,
                "found":         True,
                "last_seen":     last_seen,
                "detection_pct": int(parts[1]),
            }
        except Exception as e:
            return {"source": "cymru", "hash": hash_val, "error": str(e)}
