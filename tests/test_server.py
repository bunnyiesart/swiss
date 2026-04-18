import pytest
from server import _parallel


def test_parallel_basic():
    def fast(x):
        return {"source": "fast", "value": x}

    results = _parallel({"fast": (fast, "hello")})
    assert "fast" in results
    assert results["fast"]["value"] == "hello"


def test_parallel_drops_not_configured():
    def real(x):
        return {"source": "real", "value": x}

    def unconfigured(x):
        return {"source": "svc", "error": "not_configured"}

    results = _parallel({
        "real": (real, "hi"),
        "unconfigured": (unconfigured, "hi"),
    })
    assert "real" in results
    assert "unconfigured" not in results


def test_parallel_keeps_api_errors():
    def failing(x):
        return {"source": "svc", "error": "api_error"}

    results = _parallel({"svc": (failing, "x")})
    assert "svc" in results
    assert results["svc"]["error"] == "api_error"


def test_parallel_handles_exception():
    def explodes(x):
        raise RuntimeError("boom")

    results = _parallel({"explodes": (explodes, "x")})
    assert "explodes" in results
    assert "error" in results["explodes"]


def test_parallel_empty():
    assert _parallel({}) == {}


def test_parallel_multiple_sources():
    def s1(x): return {"source": "s1", "data": x}
    def s2(x): return {"source": "s2", "data": x}
    def s3(x): return {"source": "s3", "error": "not_configured"}

    results = _parallel({"s1": (s1, "v"), "s2": (s2, "v"), "s3": (s3, "v")})
    assert set(results.keys()) == {"s1", "s2"}
