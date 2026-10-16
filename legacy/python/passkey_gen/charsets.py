"""
Character sets and alphabet definitions for secure passkey generation.
"""

from enum import Enum
import string


class CharsetPreset(str, Enum):
    """Supported standard character set presets."""
    ALPHANUMERIC = "alphanumeric"
    COMPLEX = "complex"
    HEX = "hex"
    BASE64URL = "base64url"
    READABLE = "readable"


# Define strictly verified character sets
# Avoid unicode ambiguities and control characters
ALPHANUMERIC_CHARS: str = string.ascii_letters + string.digits  # 62 chars
HEX_CHARS: str = "0123456789abcdef"  # 16 chars
BASE64URL_CHARS: str = string.ascii_letters + string.digits + "-_"  # 64 chars

# Safe punctuation excluding problematic shell/escaping characters like quotes, backticks, backslashes
SAFE_SYMBOLS: str = "!#$%&*+-=?@^_~"
COMPLEX_CHARS: str = string.ascii_letters + string.digits + SAFE_SYMBOLS  # 75 chars

# Human-readable alphabet: removes easily confused characters (0/O, 1/l/I)
READABLE_CHARS: str = (
    "23456789"
    "abcdefghijkmnpqrstuvwxyz"
    "ABCDEFGHJKLMNPQRSTUVWXYZ"
)  # 56 chars

PRESET_MAP: dict[CharsetPreset, str] = {
    CharsetPreset.ALPHANUMERIC: ALPHANUMERIC_CHARS,
    CharsetPreset.COMPLEX: COMPLEX_CHARS,
    CharsetPreset.HEX: HEX_CHARS,
    CharsetPreset.BASE64URL: BASE64URL_CHARS,
    CharsetPreset.READABLE: READABLE_CHARS,
}


def get_charset(preset_or_custom: CharsetPreset | str) -> str:
    """
    Resolve and validate a character set.
    Ensures unique characters, minimum diversity, and no non-ASCII control characters.
    """
    if isinstance(preset_or_custom, CharsetPreset):
        return PRESET_MAP[preset_or_custom]

    # Check if string matches a preset name
    try:
        preset = CharsetPreset(preset_or_custom.lower())
        return PRESET_MAP[preset]
    except ValueError:
        pass

    # Custom charset: sanitize and validate
    cleaned = "".join(sorted(set(preset_or_custom)))
    if len(cleaned) < 2:
        raise ValueError("A character set must contain at least 2 unique characters.")
    
    # Ensure all characters are printable ASCII (avoid invisible/control byte injection)
    for ch in cleaned:
        if ord(ch) < 32 or ord(ch) > 126:
            raise ValueError(f"Invalid character in charset: ordinal {ord(ch)} is outside printable ASCII range.")
            
    return cleaned
