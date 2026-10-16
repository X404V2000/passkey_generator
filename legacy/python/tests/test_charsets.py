import pytest
from passkey_gen.charsets import (
    ALPHANUMERIC_CHARS,
    COMPLEX_CHARS,
    HEX_CHARS,
    BASE64URL_CHARS,
    READABLE_CHARS,
    CharsetPreset,
    get_charset,
)


def test_charset_presets():
    assert get_charset(CharsetPreset.ALPHANUMERIC) == ALPHANUMERIC_CHARS
    assert get_charset(CharsetPreset.COMPLEX) == COMPLEX_CHARS
    assert get_charset(CharsetPreset.HEX) == HEX_CHARS
    assert get_charset(CharsetPreset.BASE64URL) == BASE64URL_CHARS
    assert get_charset(CharsetPreset.READABLE) == READABLE_CHARS


def test_charset_presets_by_string():
    assert get_charset("alphanumeric") == ALPHANUMERIC_CHARS
    assert get_charset("HEX") == HEX_CHARS
    assert get_charset("complex") == COMPLEX_CHARS


def test_custom_charset_valid():
    custom = "abc123!?"
    resolved = get_charset(custom)
    assert set(resolved) == set(custom)
    assert len(resolved) == len(set(custom))


def test_custom_charset_too_small():
    with pytest.raises(ValueError, match="at least 2 unique characters"):
        get_charset("a")

    with pytest.raises(ValueError, match="at least 2 unique characters"):
        get_charset("aaaa")


def test_custom_charset_non_ascii():
    with pytest.raises(ValueError, match="outside printable ASCII range"):
        get_charset("abc\x00def")

    with pytest.raises(ValueError, match="outside printable ASCII range"):
        get_charset("abc\ndef")
