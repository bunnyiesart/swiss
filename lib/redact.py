"""Keep credentials out of anything a tool hands back to the client.

Every client in lib/ turns a failure into {"error": str(e)}, and requests
renders an HTTPError or ConnectionError with the full request URL -- query
string included. A service that takes its key as a query parameter (shodan's
`key`, and ipinfo's `token` until it moved to a header) therefore echoed the
key straight into the tool result, and through it to whoever called the tool.

Two layers, both applied here rather than trusted to each client:

- safe_error() for the error strings the clients build: drops every URL's
  query string, then masks known secret values.
- scrub() for whole tool results: masks known secret values anywhere in a
  str/dict/list, in raw and URL-encoded form. server.py applies it to every
  tool call through a middleware, so a new client that forgets safe_error()
  still cannot leak a configured key.

"Known secret values" are the SWISS_<SERVICE>_<FIELD> environment variables
whose FIELD lib/config.py treats as a secret. They are read on every call, not
cached, so there is no second copy of a credential living in this module.
"""

import os
import re
from urllib.parse import quote, quote_plus

REDACTED = "[redacted]"

# Mirrors lib/config.py _SECRET_FIELDS, as env-var suffixes.
_SECRET_SUFFIXES = ("_API_KEY", "_API_PASSWORD", "_USERNAME", "_PASSWORD")

# Values shorter than this are not masked: a four-character "key" is not a
# credential worth the false positives of masking it in every result.
_MIN_LEN = 4

# The query string of any http(s) URL, up to whitespace, a quote or a closing
# paren/bracket -- which is where requests' messages end a URL.
_QUERY = re.compile(r"(https?://[^\s'\"?#]+)\?[^\s'\")\]#]*")


def secret_values() -> list[str]:
    """Return every configured secret value, longest first."""
    vals = set()
    for name, value in os.environ.items():
        if name.startswith("SWISS_") and name.endswith(_SECRET_SUFFIXES):
            value = value.strip()
            if len(value) >= _MIN_LEN:
                vals.add(value)
    return sorted(vals, key=len, reverse=True)


def _forms(value: str) -> list[str]:
    forms = [value]
    for enc in (quote(value, safe=""), quote_plus(value)):
        if enc not in forms:
            forms.append(enc)
    return forms


def _scrub_str(text: str, secrets: list[str]) -> str:
    for value in secrets:
        for form in _forms(value):
            if form in text:
                text = text.replace(form, REDACTED)
    return text


def scrub(obj, secrets: list[str] | None = None):
    """Return obj with every configured secret value masked.

    Walks str, dict (keys and values), list and tuple; anything else is
    returned unchanged.
    """
    if secrets is None:
        secrets = secret_values()
    if not secrets:
        return obj
    if isinstance(obj, str):
        return _scrub_str(obj, secrets)
    if isinstance(obj, dict):
        return {scrub(k, secrets): scrub(v, secrets) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(v, secrets) for v in obj]
    if isinstance(obj, tuple):
        return tuple(scrub(v, secrets) for v in obj)
    return obj


def safe_error(exc: BaseException) -> str:
    """Render exc for a tool result: no URL query strings, no secret values."""
    text = _QUERY.sub(lambda m: f"{m.group(1)}?{REDACTED}", str(exc))
    return scrub(text)
