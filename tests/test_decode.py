from lib.decode import Decoder


def test_decode_base64():
    d = Decoder()
    result = d.decode("aGVsbG8gd29ybGQ=", "base64")
    assert result["source"] == "decode"
    assert result["output"] == "hello world"
    assert "error" not in result


def test_decode_hex():
    d = Decoder()
    result = d.decode("68656c6c6f", "hex")
    assert result["output"] == "hello"


def test_decode_url():
    d = Decoder()
    result = d.decode("hello%20world", "url")
    assert result["output"] == "hello world"


def test_decode_rot13():
    d = Decoder()
    result = d.decode("hello", "rot13")
    assert result["output"] == "uryyb"


def test_decode_defang():
    d = Decoder()
    result = d.decode("https://evil.com", "defang")
    assert "hxxps" in result["output"]
    assert "[.]" in result["output"]


def test_decode_magic_base64():
    d = Decoder()
    result = d.decode("aGVsbG8gd29ybGQ=", "magic")
    assert result["source"] == "decode"
    assert result["encoding"] == "magic"
    encodings = [r["encoding"] for r in result["results"]]
    assert "base64" in encodings


def test_decode_unknown_encoding():
    d = Decoder()
    result = d.decode("test", "nope")
    assert "error" in result
