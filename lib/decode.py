import base64
import codecs
import string
import urllib.parse


def _is_printable(text: str, threshold: float = 0.8) -> bool:
    if not text:
        return False
    printable = set(string.printable)
    ratio = sum(1 for c in text if c in printable) / len(text)
    return ratio >= threshold


def _try_base64(value: str) -> str | None:
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.b64decode(padded)
        text = decoded.decode("utf-8")
        if _is_printable(text):
            return text
    except Exception:
        pass
    return None


def _try_base64url(value: str) -> str | None:
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        text = decoded.decode("utf-8")
        if _is_printable(text):
            return text
    except Exception:
        pass
    return None


def _try_hex(value: str) -> str | None:
    try:
        clean = value.replace(" ", "").replace("0x", "")
        decoded = bytes.fromhex(clean).decode("utf-8")
        if _is_printable(decoded):
            return decoded
    except Exception:
        pass
    return None


def _defang(value: str) -> str:
    v = value
    v = v.replace("https://", "hxxps://")
    v = v.replace("http://", "hxxp://")
    v = v.replace("ftp://", "fxp://")
    # Replace dots in IPs and domains (not in paths/queries)
    import re
    v = re.sub(r"(?<=[a-zA-Z0-9])\.", "[.]", v)
    v = v.replace("@", "[@]")
    return v


class Decoder:
    def decode(self, value: str, encoding: str = "magic") -> dict:
        enc = encoding.lower().strip()

        if enc == "base64":
            result = _try_base64(value)
            return {"source": "decode", "encoding": "base64", "input": value,
                    "output": result} if result is not None else \
                   {"source": "decode", "encoding": "base64", "error": "decode_failed"}

        if enc == "base64url":
            result = _try_base64url(value)
            return {"source": "decode", "encoding": "base64url", "input": value,
                    "output": result} if result is not None else \
                   {"source": "decode", "encoding": "base64url", "error": "decode_failed"}

        if enc == "hex":
            result = _try_hex(value)
            return {"source": "decode", "encoding": "hex", "input": value,
                    "output": result} if result is not None else \
                   {"source": "decode", "encoding": "hex", "error": "decode_failed"}

        if enc == "url":
            return {"source": "decode", "encoding": "url", "input": value,
                    "output": urllib.parse.unquote(value)}

        if enc == "rot13":
            return {"source": "decode", "encoding": "rot13", "input": value,
                    "output": codecs.encode(value, "rot_13")}

        if enc == "defang":
            return {"source": "decode", "encoding": "defang", "input": value,
                    "output": _defang(value)}

        if enc == "magic":
            attempts = [
                ("base64",    _try_base64(value)),
                ("base64url", _try_base64url(value)),
                ("hex",       _try_hex(value)),
                ("url",       urllib.parse.unquote(value) if "%" in value else None),
                ("rot13",     codecs.encode(value, "rot_13")),
            ]
            results = [{"encoding": name, "output": out} for name, out in attempts if out is not None]
            return {"source": "decode", "encoding": "magic", "input": value, "results": results}

        return {"source": "decode", "error": f"unknown encoding: {encoding}"}
