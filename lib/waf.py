import json
import subprocess
import sys


class WAFDetector:
    def detect(self, url: str) -> dict:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "wafw00f", "-a", "-o", "-", "-f", "json", url],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode not in (0, 1):
                return {"source": "waf", "url": url, "error": result.stderr.strip() or "non-zero exit"}

            raw = result.stdout.strip()
            if not raw:
                return {"source": "waf", "url": url, "detected": [], "generic_detected": False}

            entries = json.loads(raw)
            detected = [
                e["firewall"]
                for e in entries
                if e.get("firewall") and e["firewall"].lower() not in ("none", "generic")
            ]
            generic = any(
                e.get("firewall", "").lower() == "generic"
                for e in entries
            )
            return {
                "source":          "waf",
                "url":             url,
                "detected":        detected,
                "generic_detected": generic,
            }
        except subprocess.TimeoutExpired:
            return {"source": "waf", "url": url, "error": "timeout"}
        except json.JSONDecodeError as e:
            return {"source": "waf", "url": url, "error": f"json_parse_error: {e}"}
        except Exception as e:
            return {"source": "waf", "url": url, "error": str(e)}
