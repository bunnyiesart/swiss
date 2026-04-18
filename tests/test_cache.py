import threading
import time

import pytest
from lib.cache import TTLCache


def test_set_and_get():
    cache = TTLCache(ttl=60)
    cache.set("key", "value")
    assert cache.get("key") == "value"


def test_miss_returns_none():
    cache = TTLCache(ttl=60)
    assert cache.get("nonexistent") is None


def test_ttl_expiry(monkeypatch):
    cache = TTLCache(ttl=10)
    base = time.monotonic()
    monkeypatch.setattr("lib.cache.time.monotonic", lambda: base)
    cache.set("key", "value")

    monkeypatch.setattr("lib.cache.time.monotonic", lambda: base + 11)
    assert cache.get("key") is None


def test_ttl_not_expired(monkeypatch):
    cache = TTLCache(ttl=10)
    base = time.monotonic()
    monkeypatch.setattr("lib.cache.time.monotonic", lambda: base)
    cache.set("key", "value")

    monkeypatch.setattr("lib.cache.time.monotonic", lambda: base + 9)
    assert cache.get("key") == "value"


def test_overwrite():
    cache = TTLCache(ttl=60)
    cache.set("key", "v1")
    cache.set("key", "v2")
    assert cache.get("key") == "v2"


def test_thread_safety():
    cache = TTLCache(ttl=60)
    errors = []

    def writer(i):
        try:
            cache.set(f"key{i}", i)
        except Exception as e:
            errors.append(e)

    def reader(i):
        try:
            cache.get(f"key{i}")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(50)]
    threads += [threading.Thread(target=reader, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
