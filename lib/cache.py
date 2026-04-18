import threading
import time


class TTLCache:
    """Thread-safe in-process TTL cache.

    Used by list-based sources (Feodo, Tor, LOLBas, custom blacklists)
    to avoid fetching remote data on every IOC lookup.
    """

    def __init__(self, ttl: int = 300):
        self._ttl = ttl
        self._store: dict = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            val, ts = entry
            if time.monotonic() - ts > self._ttl:
                del self._store[key]
                return None
            return val

    def set(self, key: str, val) -> None:
        with self._lock:
            self._store[key] = (val, time.monotonic())
