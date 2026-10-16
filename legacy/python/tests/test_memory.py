import ctypes
import pytest
from passkey_gen.memory import SecurePasskey, zeroize_buffer


def test_zeroize_bytearray():
    arr = bytearray(b"SecretPasskey12345")
    assert any(b != 0 for b in arr)
    zeroize_buffer(arr)
    assert all(b == 0 for b in arr)


def test_zeroize_ctypes_array():
    c_buf = ctypes.create_string_buffer(b"SensitiveSecretValue", 20)
    assert c_buf.raw == b"SensitiveSecretValue"
    zeroize_buffer(c_buf)
    assert c_buf.raw == b"\x00" * 20


def test_secure_passkey_lifecycle():
    raw = b"my_super_secure_passkey_token_12"
    passkey = SecurePasskey(raw)

    assert passkey.length == len(raw)
    assert not passkey.is_destroyed
    assert passkey.get_value() == raw.decode("ascii")

    # Explicit destroy
    passkey.destroy()
    assert passkey.is_destroyed

    # Access after destruction must raise RuntimeError
    with pytest.raises(RuntimeError, match="zeroized and destroyed"):
        passkey.get_value()

    # Calling destroy again is idempotent and safe
    passkey.destroy()


def test_secure_passkey_context_manager():
    raw = b"context_managed_passkey_test_123"
    with SecurePasskey(raw) as passkey:
        assert passkey.get_value() == raw.decode("ascii")
        assert not passkey.is_destroyed

    assert passkey.is_destroyed
    with pytest.raises(RuntimeError, match="zeroized and destroyed"):
        passkey.get_value()


def test_secure_passkey_no_leaks_in_repr_or_str():
    secret = b"do_not_leak_in_logs_12345"
    with SecurePasskey(secret) as passkey:
        str_repr = str(passkey)
        repr_str = repr(passkey)

        assert secret.decode("ascii") not in str_repr
        assert secret.decode("ascii") not in repr_str
        assert "REDACTED" in str_repr
        assert "ACTIVE" in repr_str

    assert "DESTROYED" in repr(passkey)
