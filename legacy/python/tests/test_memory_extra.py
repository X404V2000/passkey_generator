import os
import tempfile
import pytest
from passkey_gen.memory import SecurePasskey, zeroize_buffer


def test_zeroize_empty():
    zeroize_buffer(bytearray())
    zeroize_buffer(None)


def test_secure_passkey_write_to_fd():
    raw = b"1234567890abcdef"
    with tempfile.TemporaryFile(mode="w+b") as tmp:
        with SecurePasskey(raw) as passkey:
            passkey.write_to_fd(tmp.fileno(), add_newline=True)

        tmp.seek(0)
        content = tmp.read()
        assert content == raw + b"\n"

    # Attempting to write after destruction should raise RuntimeError
    with pytest.raises(RuntimeError):
        passkey.write_to_fd(1)


def test_secure_passkey_del():
    passkey = SecurePasskey(b"temporary_secret_key")
    assert not passkey.is_destroyed
    del passkey  # invokes __del__ which calls destroy()
