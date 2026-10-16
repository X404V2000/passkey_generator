from unittest.mock import MagicMock, patch
from passkey_gen.clipboard import SecureClipboard


def test_clipboard_copy_and_clear_osc52():
    # Force fallback to OSC 52
    with patch("passkey_gen.clipboard.shutil.which", return_value=None):
        with patch("sys.stdout.write") as mock_write, patch("sys.stdout.flush") as mock_flush:
            success = SecureClipboard.copy("TestSecret123")
            assert success is True
            assert mock_write.called
            # Verify OSC 52 sequence format
            args, _ = mock_write.call_args
            assert args[0].startswith("\033]52;c;")

            clear_success = SecureClipboard.clear()
            assert clear_success is True


def test_clipboard_copy_wayland():
    with patch.object(SecureClipboard, "_is_wayland", return_value=True):
        with patch("passkey_gen.clipboard.shutil.which", side_effect=lambda x: "/usr/bin/wl-copy" if x == "wl-copy" else None):
            with patch("subprocess.Popen") as mock_popen:
                mock_proc = MagicMock()
                mock_proc.returncode = 0
                mock_proc.communicate.return_value = (b"", b"")
                mock_popen.return_value = mock_proc

                assert SecureClipboard.copy("WaylandSecret") is True
                assert mock_popen.called


def test_clipboard_schedule_wipe_zero():
    # 0 or negative seconds does nothing
    with patch("subprocess.Popen") as mock_popen:
        SecureClipboard.schedule_background_wipe(0)
        assert not mock_popen.called
