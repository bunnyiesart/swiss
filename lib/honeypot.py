import ipaddress
import re
import socket

_KEY_RE = re.compile(r"^[a-z]{12}$")
_TYPE_MAP = {1: "suspicious", 2: "harvester", 4: "comment_spammer"}


class ProjectHoneypot:
    def __init__(self, api_key: str):
        self._key = api_key

    def check_ip(self, ip: str) -> dict:
        if not self._key:
            return {"source": "honeypot", "error": "not_configured"}

        if not _KEY_RE.match(self._key):
            return {"source": "honeypot", "error": "invalid_api_key_format"}

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"source": "honeypot", "error": "invalid_ip"}

        if addr.version != 4:
            return {"source": "honeypot", "error": "ipv6_not_supported"}

        reversed_ip = ".".join(reversed(ip.split(".")))
        hostname = f"{self._key}.{reversed_ip}.dnsbl.httpbl.org"

        try:
            response = socket.gethostbyname(hostname)
        except socket.gaierror:
            return {"source": "honeypot", "ip": ip, "listed": False}

        parts = response.split(".")
        if len(parts) != 4 or parts[0] != "127":
            return {"source": "honeypot", "ip": ip, "listed": False}

        days_since_last = int(parts[1])
        threat_score = int(parts[2])
        type_bitmask = int(parts[3])

        visitor_types = [label for bit, label in _TYPE_MAP.items() if type_bitmask & bit]
        if type_bitmask == 0:
            visitor_types = ["search_engine"]

        return {
            "source":            "honeypot",
            "ip":                ip,
            "listed":            True,
            "days_since_last":   days_since_last,
            "threat_score":      threat_score,
            "visitor_types":     visitor_types,
        }
