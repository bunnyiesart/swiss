"""A configured key must never reach a tool result.

Regression for the leak measured 25 Sep 2026 behind the SOC gateway:
swiss_lookup_ip's ipinfo error path returned
`403 ... https://ipinfo.io/8.8.8.8/json?token=<key>` to the analyst.
"""

import asyncio
from unittest.mock import MagicMock, patch

import requests

from lib.redact import REDACTED, safe_error, scrub, secret_values

KEY = "s3cr3t-ipinfo-key+/="


def _http_error(url: str) -> requests.HTTPError:
    resp = requests.Response()
    resp.status_code = 403
    resp.reason = "Forbidden"
    resp.url = url
    return requests.HTTPError(f"403 Client Error: Forbidden for url: {url}", response=resp)


def test_secret_values_reads_secret_fields_only(monkeypatch):
    monkeypatch.setenv("SWISS_IPINFO_API_KEY", KEY)
    monkeypatch.setenv("SWISS_GRAYLOG_URL", "https://graylog.example")
    monkeypatch.setenv("SWISS_GRAYLOG_PASSWORD", "hunter22")
    monkeypatch.setenv("SWISS_SHODAN_API_KEY", "abc")  # too short to mask
    vals = secret_values()
    assert KEY in vals and "hunter22" in vals
    assert "https://graylog.example" not in vals
    assert "abc" not in vals


def test_safe_error_drops_query_string_even_for_unknown_keys(monkeypatch):
    for k in list(__import__("os").environ):
        if k.startswith("SWISS_"):
            monkeypatch.delenv(k)
    err = _http_error("https://api.shodan.io/shodan/host/1.2.3.4?key=never-configured")
    out = safe_error(err)
    assert "never-configured" not in out
    assert f"https://api.shodan.io/shodan/host/1.2.3.4?{REDACTED}" in out
    assert "403" in out


def test_safe_error_masks_raw_and_url_encoded_values(monkeypatch):
    monkeypatch.setenv("SWISS_IPINFO_API_KEY", KEY)
    enc = requests.utils.quote(KEY, safe="")
    out = safe_error(RuntimeError(f"bad key {KEY} / {enc} in path /x/{enc}/y"))
    assert KEY not in out and enc not in out
    assert out.count(REDACTED) == 3


def test_scrub_walks_nested_results(monkeypatch):
    monkeypatch.setenv("SWISS_VIRUSTOTAL_API_KEY", KEY)
    got = scrub({"a": [KEY, {"b": f"x{KEY}y"}], KEY: 1, "n": 5})
    assert KEY not in repr(got)
    assert got["n"] == 5


def test_ipinfo_sends_token_as_header_not_query(monkeypatch):
    from lib.ipinfo import IPInfo

    c = IPInfo(KEY)
    assert c._session.headers["Authorization"] == f"Bearer {KEY}"
    fake = MagicMock()
    fake.raise_for_status.return_value = None
    fake.json.return_value = {"ip": "8.8.8.8"}
    with patch.object(c._session, "get", return_value=fake) as get:
        c.check_ip("8.8.8.8")
    args, kwargs = get.call_args
    assert KEY not in args[0]
    assert "params" not in kwargs or KEY not in repr(kwargs["params"])


def test_ipinfo_403_does_not_echo_key(monkeypatch):
    from lib.ipinfo import IPInfo

    monkeypatch.setenv("SWISS_IPINFO_API_KEY", KEY)
    c = IPInfo(KEY)
    boom = _http_error(f"https://ipinfo.io/8.8.8.8/json?token={KEY}")
    with patch.object(c._session, "get", side_effect=boom):
        out = c.check_ip("8.8.8.8")
    assert KEY not in repr(out)
    assert "403" in out["error"]


def test_middleware_scrubs_tool_results_end_to_end(monkeypatch):
    """Through a real MCP client: a tool that returns, and one that raises,
    a configured key both come back without it."""
    from fastmcp import Client, FastMCP

    from server import ScrubSecrets

    monkeypatch.setenv("SWISS_IPINFO_API_KEY", KEY)
    srv = FastMCP("t")
    srv.add_middleware(ScrubSecrets())

    @srv.tool
    def echo() -> dict:
        return {"error": f"403 for url: https://x.test/?token={KEY}", "raw": KEY}

    @srv.tool
    def explode() -> dict:
        raise RuntimeError(f"upstream said {KEY}")

    async def run():
        async with Client(srv) as client:
            ok = await client.call_tool("echo", {})
            bad = await client.call_tool("explode", {}, raise_on_error=False)
            return ok, bad

    ok, bad = asyncio.run(run())
    for res in (ok, bad):
        dumped = repr(res.content) + repr(getattr(res, "structured_content", None))
        assert KEY not in dumped
    assert REDACTED in repr(ok.content)
    assert bad.is_error


def test_parallel_exception_is_scrubbed(monkeypatch):
    from server import _parallel

    monkeypatch.setenv("SWISS_IPINFO_API_KEY", KEY)

    def explodes(x):
        raise RuntimeError(f"GET https://ipinfo.io/{x}/json?token={KEY} failed")

    out = _parallel({"ipinfo": (explodes, "8.8.8.8")})
    assert KEY not in repr(out)
