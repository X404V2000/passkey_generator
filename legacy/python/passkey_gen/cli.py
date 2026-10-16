"""
Command-Line Interface for the Secure Passkey Generator.
Focuses on operational security, zero-trace execution, and defense in depth.
"""

import argparse
import os
import signal
import sys
from typing import Optional

try:
    import resource
except ImportError:
    resource = None

from passkey_gen.charsets import CharsetPreset, get_charset
from passkey_gen.generator import (
    DEFAULT_PRESET_LENGTHS,
    MAX_PASSKEY_LENGTH,
    MIN_PASSKEY_LENGTH,
    PasskeyGenerator,
)
from passkey_gen.process import check_security_status, harden_process


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="passkey-gen",
        description="Stateless, cryptographically secure passkey generator with volatile memory sanitization.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-l",
        "--length",
        type=int,
        default=32,
        help=f"Passkey length in characters. Standards presets are 32 or 64. Bounds: [{MIN_PASSKEY_LENGTH}, {MAX_PASSKEY_LENGTH}].",
    )

    parser.add_argument(
        "-c",
        "--charset",
        type=str,
        default=CharsetPreset.ALPHANUMERIC.value,
        help="Charset preset (alphanumeric, complex, hex, base64url, readable) or a custom set of characters.",
    )

    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=1,
        help="Number of passkeys to generate sequentially. Each is zeroized before the next is produced.",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Output raw passkey only, omitting formatting and entropy calculations (ideal for piping).",
    )

    parser.add_argument(
        "--show-entropy",
        action="store_true",
        help="Display the information-theoretic entropy (in bits) for the selected configuration.",
    )

    parser.add_argument(
        "-e",
        "--ephemeral",
        type=int,
        nargs="?",
        const=15,
        default=None,
        help="Display passkey in an ephemeral, alternate-screen buffer that leaves 0 scrollback traces (default 15s).",
    )

    parser.add_argument(
        "-C",
        "--copy",
        action="store_true",
        help="Copy generated passkey to system clipboard with automated zero-trace wiping.",
    )

    parser.add_argument(
        "--copy-timeout",
        type=int,
        default=20,
        help="Timeout in seconds before wiping the clipboard (default 20s).",
    )

    parser.add_argument(
        "--audit",
        action="store_true",
        help="Inspect and report kernel and OS process security posture (ptrace, core dumps, dumpable flags).",
    )

    # WebAuthn / FIDO2 Passkey Arguments
    parser.add_argument(
        "--webauthn",
        action="store_true",
        help="Generate a FIDO2 / WebAuthn asymmetric resident passkey (ES256 / Ed25519) instead of a symmetric token.",
    )

    parser.add_argument(
        "--webauthn-alg",
        type=str,
        default="ES256",
        choices=["ES256", "Ed25519"],
        help="Asymmetric algorithm for WebAuthn passkey (default: ES256).",
    )

    parser.add_argument(
        "--export-private",
        action="store_true",
        help="Include the PKCS#8 private key in WebAuthn export (zeroized from RAM immediately after output).",
    )

    parser.add_argument(
        "--passphrase",
        type=str,
        default=None,
        help="Passphrase to encrypt the exported private key using AES-256-CBC.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Format output as WebAuthn-compliant JSON structure.",
    )

    return parser.parse_args(args)


def main(argv: Optional[list[str]] = None) -> int:
    harden_process()

    # Handle SIGINT cleanly
    signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(130))

    args = parse_args(argv)

    if args.audit:
        status = check_security_status()
        sys.stdout.write("[*] Linux Process Defense Audit:\n")
        sys.stdout.write(f"  - Core Dumps Disabled (RLIMIT_CORE=0): {'[SECURE]' if status.get('core_dumps_disabled') else '[INSECURE]'}\n")
        sys.stdout.write(f"  - Non-Dumpable (PR_SET_DUMPABLE=0):     {'[SECURE] (ptrace & /proc/mem blocked)' if status.get('ptrace_protected') else '[INSECURE]'}\n")
        sys.stdout.write(f"  - No New Privileges (PR_SET_NO_NEW_PRIVS=1): {'[SECURE]' if status.get('no_new_privs') else '[INSECURE]'}\n")
        sys.stdout.write(f"  - Memory Lock Available (mlock):       {'[ENABLED]' if status.get('mlock_available') else '[UNAVAILABLE]'}\n")
        return 0

    if args.webauthn:
        import json
        from passkey_gen.webauthn import WebAuthnAlgorithm, generate_webauthn_passkey

        alg = WebAuthnAlgorithm.ES256 if args.webauthn_alg == "ES256" else WebAuthnAlgorithm.ED25519
        with generate_webauthn_passkey(algorithm=alg) as cred:
            if args.copy:
                from passkey_gen.clipboard import SecureClipboard
                # Copy public key COSE base64 to clipboard
                SecureClipboard.copy(cred.public_key_cose_b64)
                SecureClipboard.schedule_background_wipe(args.copy_timeout)
                if not args.quiet:
                    sys.stderr.write(f"[+] COSE public key copied to clipboard (auto-wipes in {args.copy_timeout}s)\n")

            cred_dict = cred.to_dict(include_private_key=args.export_private, passphrase=args.passphrase)

            if args.json:
                sys.stdout.write(json.dumps(cred_dict, indent=2) + "\n")
            else:
                sys.stdout.write("=" * 64 + "\n")
                sys.stdout.write(f"  FIDO2 / WebAuthn Passkey ({cred.algorithm.value})\n")
                sys.stdout.write("=" * 64 + "\n")
                sys.stdout.write(f"Credential ID (base64url):\n  {cred.credential_id}\n\n")
                sys.stdout.write(f"Public Key (COSE - base64url):\n  {cred.public_key_cose_b64}\n\n")
                sys.stdout.write(f"Public Key (PEM):\n{cred.public_key_pem}\n")
                if args.export_private:
                    sys.stdout.write(f"Private Key (PKCS#8 PEM):\n{cred_dict['privateKeyPem']}\n")
                sys.stdout.write("=" * 64 + "\n")
                sys.stdout.flush()

        return 0

    try:
        charset_str = get_charset(args.charset)
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1

    if args.count < 1 or args.count > 1000:
        sys.stderr.write("Error: Count must be between 1 and 1000.\n")
        return 1

    generator = PasskeyGenerator()
    entropy_bits = generator.calculate_entropy_bits(args.length, len(charset_str))

    # Mode 1: Ephemeral display mode
    if args.ephemeral is not None:
        if args.count > 1:
            sys.stderr.write("Error: Ephemeral display mode supports single passkey generation (count=1).\n")
            return 1

        from passkey_gen.display import display_ephemeral

        passkey = generator.generate(length=args.length, charset=charset_str)
        display_ephemeral(
            passkey=passkey,
            entropy_bits=entropy_bits,
            timeout_seconds=args.ephemeral,
            copy_to_clipboard=args.copy,
            clipboard_timeout=args.copy_timeout,
        )
        return 0

    # Mode 2: Standard output / Piped / Scripted mode
    if args.show_entropy and not args.quiet:
        sys.stderr.write(
            f"[*] Charset size: {len(charset_str)} chars | Length: {args.length} chars | Entropy: {entropy_bits:.2f} bits\n"
        )

    try:
        stdout_fd = sys.stdout.fileno()
    except Exception:
        stdout_fd = None

    for _ in range(args.count):
        try:
            with generator.generate(length=args.length, charset=charset_str) as passkey:
                if args.copy:
                    from passkey_gen.clipboard import SecureClipboard
                    SecureClipboard.copy(passkey.get_value())
                    SecureClipboard.schedule_background_wipe(args.copy_timeout)
                    if not args.quiet:
                        sys.stderr.write(
                            f"[+] Passkey copied to clipboard (will be auto-wiped in {args.copy_timeout}s)\n"
                        )

                if stdout_fd is not None:
                    # Direct OS file descriptor write avoids intermediate Python string caches
                    passkey.write_to_fd(stdout_fd, add_newline=True)
                else:
                    sys.stdout.write(passkey.get_value() + "\n")
                    sys.stdout.flush()
        except Exception as exc:
            sys.stderr.write(f"Generation error: {exc}\n")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
