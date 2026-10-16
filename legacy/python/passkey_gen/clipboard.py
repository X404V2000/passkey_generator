"""
Secure clipboard management with automated zero-trace wiping.
Supports Wayland (wl-copy), X11 (xclip, xsel), and ANSI OSC 52 fallback.
"""

import base64
import os
import shutil
import subprocess
import sys
import time
from typing import Optional


class SecureClipboard:
    """
    Handles clipboard copying with automated time-based wiping to prevent
    sensitive secrets from persisting in OS clipboard histories.
    """

    @staticmethod
    def _is_wayland() -> bool:
        return bool(os.environ.get("WAYLAND_DISPLAY"))

    @classmethod
    def copy(cls, text: str) -> bool:
        """
        Copy text to the system clipboard using the most secure available mechanism.
        """
        data = text.encode("utf-8")

        # 1. Prefer Wayland wl-copy if running under Wayland
        if cls._is_wayland() and shutil.which("wl-copy"):
            try:
                proc = subprocess.Popen(
                    ["wl-copy"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                proc.communicate(input=data, timeout=2)
                if proc.returncode == 0:
                    return True
            except Exception:
                pass

        # 2. X11 xclip
        if shutil.which("xclip"):
            try:
                proc = subprocess.Popen(
                    ["xclip", "-selection", "clipboard"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                proc.communicate(input=data, timeout=2)
                if proc.returncode == 0:
                    return True
            except Exception:
                pass

        # 3. X11 xsel
        if shutil.which("xsel"):
            try:
                proc = subprocess.Popen(
                    ["xsel", "--clipboard", "--input"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                proc.communicate(input=data, timeout=2)
                if proc.returncode == 0:
                    return True
            except Exception:
                pass

        # 4. Fallback: OSC 52 ANSI terminal escape sequence
        # Supported by modern terminals (GNOME Terminal, Alacritty, Kitty, iTerm2, WezTerm)
        try:
            b64_payload = base64.b64encode(data).decode("ascii")
            osc52_seq = f"\033]52;c;{b64_payload}\a"
            sys.stdout.write(osc52_seq)
            sys.stdout.flush()
            return True
        except Exception:
            return False

    @classmethod
    def clear(cls) -> bool:
        """
        Actively overwrite and clear the clipboard.
        """
        cleared = False

        if cls._is_wayland() and shutil.which("wl-copy"):
            try:
                subprocess.run(
                    ["wl-copy", "--clear"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2,
                    check=False,
                )
                cleared = True
            except Exception:
                pass

        if shutil.which("xclip"):
            try:
                proc = subprocess.Popen(
                    ["xclip", "-selection", "clipboard"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                proc.communicate(input=b"", timeout=2)
                cleared = True
            except Exception:
                pass

        if shutil.which("xsel"):
            try:
                subprocess.run(
                    ["xsel", "--clipboard", "--clear"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2,
                    check=False,
                )
                cleared = True
            except Exception:
                pass

        # Send OSC 52 clear sequence to terminal
        try:
            sys.stdout.write("\033]52;c;!\a")
            sys.stdout.flush()
            cleared = True
        except Exception:
            pass

        return cleared

    @classmethod
    def schedule_background_wipe(cls, delay_seconds: int) -> None:
        """
        Spawn a detached background process to wipe clipboard after delay_seconds.
        Ensures the secret is wiped even if the CLI exits immediately.
        """
        if delay_seconds <= 0:
            return

        cmd = [
            sys.executable,
            "-c",
            f"import time; from passkey_gen.clipboard import SecureClipboard; time.sleep({delay_seconds}); SecureClipboard.clear()",
        ]

        try:
            subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,  # detach process from terminal
            )
        except Exception:
            pass
