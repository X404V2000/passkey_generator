from unittest.mock import MagicMock, patch
from passkey_gen.display import display_ephemeral
from passkey_gen.memory import SecurePasskey


def test_display_ephemeral_nontty(capsys):
    passkey = SecurePasskey(b"nontty_test_passkey_12345678")
    with patch("sys.stdout.isatty", return_value=False):
        display_ephemeral(passkey, entropy_bits=190.5)

    captured = capsys.readouterr()
    assert "nontty_test_passkey_12345678" in captured.out


def test_display_ephemeral_interactive_immediate_exit():
    passkey = SecurePasskey(b"interactive_test_key_12345678")
    with patch("sys.stdout.isatty", return_value=True), patch("sys.stdin.isatty", return_value=True):
        # Simulate pressing 'q' immediately
        with patch("passkey_gen.display._read_key_nonblocking", return_value="q"):
            with patch("sys.stdout.write") as mock_write:
                display_ephemeral(passkey, entropy_bits=190.5, timeout_seconds=10, copy_to_clipboard=True)
                assert passkey.is_destroyed
