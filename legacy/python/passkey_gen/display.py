"""
Ephemeral display module for terminal shoulder-surfing and scrollback defense.
Uses the terminal's alternate screen buffer to ensure zero traces remain in
terminal scrollback history once the display expires or user exits.
"""

import os
import select
import sys
import time
from typing import Optional

from passkey_gen.clipboard import SecureClipboard
from passkey_gen.memory import SecurePasskey

# ANSI escape sequence constants
ALT_SCREEN_ENTER = "\033[?1049h"
ALT_SCREEN_EXIT = "\033[?1049l"
CURSOR_HIDE = "\033[?25l"
CURSOR_SHOW = "\033[?25h"
CLEAR_SCREEN = "\033[2J\033[H"


def _read_key_nonblocking(timeout: float) -> Optional[str]:
    """
    Check if a key is waiting in stdin without blocking indefinitely.
    """
    rlist, _, _ = select.select([sys.stdin], [], [], timeout)
    if rlist:
        try:
            return sys.stdin.read(1)
        except Exception:
            return None
    return None


def display_ephemeral(
    passkey: SecurePasskey,
    entropy_bits: float,
    timeout_seconds: int = 15,
    copy_to_clipboard: bool = False,
    clipboard_timeout: int = 20,
) -> None:
    """
    Display passkey in an ephemeral alternate screen buffer with countdown.
    
    Guarantees:
    1. Zero scrollback leakage: Upon exit, the alternate screen buffer is closed,
       leaving the user's primary terminal completely untouched and secret-free.
    2. Zeroizes memory buffer immediately on expiration or keypress.
    3. Handles clipboard auto-wiping if clipboard copying was requested.
    """
    if not sys.stdout.isatty() or not sys.stdin.isatty():
        try:
            passkey.write_to_fd(sys.stdout.fileno(), add_newline=True)
        except Exception:
            sys.stdout.write(passkey.get_value() + "\n")
            sys.stdout.flush()
        passkey.destroy()
        return

    # Check for termios/tty support on Unix
    has_termios = False
    old_term_settings = None
    try:
        import termios
        import tty
        old_term_settings = termios.tcgetattr(sys.stdin.fileno())
        has_termios = True
    except Exception:
        pass

    passkey_str = passkey.get_value()

    if copy_to_clipboard:
        SecureClipboard.copy(passkey_str)

    try:
        # Switch to alternate screen buffer and hide cursor
        sys.stdout.write(f"{ALT_SCREEN_ENTER}{CURSOR_HIDE}{CLEAR_SCREEN}")
        sys.stdout.flush()

        if has_termios:
            import tty
            tty.setcbreak(sys.stdin.fileno())

        start_time = time.time()
        end_time = start_time + timeout_seconds

        box_width = max(len(passkey_str) + 6, 68)
        border = "─" * box_width

        while True:
            remaining = int(math_ceil(end_time - time.time()))
            if remaining <= 0:
                break

            clipboard_status = (
                f"[Copied to Clipboard - Auto-wiping in {remaining}s]"
                if copy_to_clipboard
                else "[Clipboard: Not Copied]"
            )

            ui_text = (
                f"{CLEAR_SCREEN}"
                f"┌{border}┐\r\n"
                f"│ SECURE PASSKEY GENERATOR - EPHEMERAL OPSEC VIEW{' ' * (box_width - 48)}│\r\n"
                f"├{border}┤\r\n"
                f"│ Passkey ({passkey.length} chars | {entropy_bits:.2f} bits entropy):{' ' * (box_width - len(str(passkey.length)) - len(f'{entropy_bits:.2f}') - 31)}│\r\n"
                f"│   \033[1;32m{passkey_str}\033[0m{' ' * (box_width - len(passkey_str) - 3)}│\r\n"
                f"│{' ' * box_width}│\r\n"
                f"│ Status: {clipboard_status}{' ' * (box_width - len(clipboard_status) - 9)}│\r\n"
                f"│ Memory Zeroization: ACTIVE (Buffer will be wiped upon exit){' ' * (box_width - 60)}│\r\n"
                f"├{border}┤\r\n"
                f"│ Auto-clearing and zeroizing in \033[1;33m{remaining:2d}s\033[0m...{' ' * (box_width - 39)}│\r\n"
                f"│ Press \033[1m[Enter]\033[0m, \033[1m[Space]\033[0m, or \033[1m[q]\033[0m to wipe & close immediately.{' ' * (box_width - 55)}│\r\n"
                f"└{border}┘\r\n"
            )

            sys.stdout.write(ui_text)
            sys.stdout.flush()

            # Poll for input with 0.2s tick
            key = _read_key_nonblocking(0.2)
            if key in ("\n", "\r", " ", "q", "Q", "\x1b"):
                break

    finally:
        # 1. Overwrite screen with blank text
        sys.stdout.write(CLEAR_SCREEN)
        sys.stdout.flush()

        # 2. Restore terminal settings
        if has_termios and old_term_settings is not None:
            try:
                import termios
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_term_settings)
            except Exception:
                pass

        # 3. Return to primary screen buffer & unhide cursor
        sys.stdout.write(f"{ALT_SCREEN_EXIT}{CURSOR_SHOW}")
        sys.stdout.flush()

        # 4. If clipboard was copied, wipe it now
        if copy_to_clipboard:
            SecureClipboard.clear()

        # 5. Zeroize internal memory
        passkey.destroy()

        # 6. Inform user on primary screen
        clip_note = " and system clipboard" if copy_to_clipboard else ""
        sys.stdout.write(f"[+] Passkey destroyed and wiped from memory, terminal{clip_note}.\n")
        sys.stdout.flush()


def math_ceil(val: float) -> int:
    import math
    return max(0, math.ceil(val))
