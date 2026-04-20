import socket
import time


class ExposureChecker:
    def probe(self, host: str, port: int) -> dict:
        start = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=5) as s:
                latency_ms = round((time.monotonic() - start) * 1000, 1)
                s.settimeout(1)
                try:
                    banner = s.recv(256).decode("utf-8", errors="replace").strip()
                except (socket.timeout, OSError):
                    banner = ""
            return {
                "source":     "exposure",
                "host":       host,
                "port":       port,
                "reachable":  True,
                "latency_ms": latency_ms,
                "banner":     banner,
            }
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return {
                "source":    "exposure",
                "host":      host,
                "port":      port,
                "reachable": False,
                "error":     str(e),
            }
        except Exception as e:
            return {"source": "exposure", "host": host, "port": port, "error": str(e)}
