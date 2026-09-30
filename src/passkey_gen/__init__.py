"""
passkey_gen: Cryptographically secure, zero-cache passkey generation.
"""

from passkey_gen.charsets import CharsetPreset, get_charset
from passkey_gen.clipboard import SecureClipboard
from passkey_gen.display import display_ephemeral
from passkey_gen.generator import PasskeyGenerator
from passkey_gen.memory import SecurePasskey, zeroize_buffer
from passkey_gen.process import check_security_status, harden_process
from passkey_gen.webauthn import (
    WebAuthnAlgorithm,
    WebAuthnPasskey,
    generate_webauthn_passkey,
)

__version__ = "1.0.0"
__all__ = [
    "CharsetPreset",
    "get_charset",
    "PasskeyGenerator",
    "SecurePasskey",
    "zeroize_buffer",
    "SecureClipboard",
    "display_ephemeral",
    "harden_process",
    "check_security_status",
    "WebAuthnAlgorithm",
    "WebAuthnPasskey",
    "generate_webauthn_passkey",
]
