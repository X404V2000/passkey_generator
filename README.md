# TokenGen (`passkey-gen`)

> ## ⚠️ Project status — read before installing
>
> TokenGen is migrating from a **legacy Python implementation** to a **Rust implementation**.
>
> | | Rust (`src/`) | Python (`src/passkey_gen/`) |
> |---|---|---|
> | Status | **Supported.** F1 (entropy) and F2 (key generation) are frozen. | **Legacy — do not use for real secrets.** |
> | Zeroization | Enforced by the type system (`Zeroizing<T>`) | `SecurePasskey` only; **not** `WebAuthnPasskey` |
> | Constant-time comparisons | `subtle` types | Not available |
> | Memory locking (`mlock`) | Sound (stable buffer address) | Best-effort; GC may move data |
>
> **The Python implementation does not satisfy this project's own security invariants and must not be relied on.** Specifically, `WebAuthnPasskey.destroy()` drops a reference without wiping memory, and `export_private_key_pem()` returns an unwipeable `str` containing the private key. See [`docs/LANGUAGE_DECISION.md`](docs/LANGUAGE_DECISION.md) §4 for the verified findings.
>
> Security guarantees in the sections below describe the **Rust** implementation unless explicitly stated otherwise.

A cryptographically secure, stateless passkey and secret key generator engineered with a **defense-in-depth** security architecture.

## Core Security Guarantees

1. **Kernel OS CSPRNG Entropy Source**:
   - Uses `os.urandom()` backed by the Linux kernel entropy pool (`getrandom(2)` / `/dev/urandom`).
   - Prevents PRNG state compromise, predictable seeding, and algorithmic sequence recovery.

2. **Zero Modulo Bias (Rejection Sampling)**:
   - Naive modulus operations (`rand_byte % len(charset)`) skew character probabilities when 256 is not evenly divisible by the charset length.
   - This implementation computes rejection thresholds $\text{limit} = 256 - (256 \pmod{|\text{charset}|})$ and discards out-of-range entropy bytes, mathematically ensuring uniform probability distribution ($\frac{1}{|\text{charset}|}$) across all characters.

3. **Stateless & Zero Caching**:
   - Completely stateless: does **not** store, cache, memoize, or log any generated key.
   - The generator holds no internal history of previously generated keys.

4. **Volatile Memory Sanitization & Destruction**:
   - Standard Python strings (`str`) are immutable and reside in PyMalloc heap arenas until reclaimed by garbage collection.
   - `passkey-gen` encapsulates secrets inside [`SecurePasskey`](file:///home/deathrok/Desktop/projects/passkey_generator/src/passkey_gen/memory.py), backed by native C buffers (`ctypes`).
   - On context exit or `.destroy()`, memory is actively wiped using OS-level `explicit_bzero` / `memset` and zeroized byte-by-byte.
     - **Scope of this guarantee (Python):** it applies to `SecurePasskey` only. It does **not** apply to `WebAuthnPasskey`, whose `destroy()` sets `self._private_key = None` without wiping, and which never calls `zeroize_buffer` or `mlock`.
   - Implements memory locking (`mlock`) to pin secret buffers in physical RAM and prevent paging to unencrypted swap disks.
   - Redacts string representations (`repr` / `str`) to prevent accidental leakage in debug logs or exception tracebacks.

5. **Linux Kernel Process Hardening (Anti-Snooping & Anti-Dump)**:
   - Sets `RLIMIT_CORE = 0` to permanently block core dump creation upon abnormal termination or crash.
   - Enforces `prctl(PR_SET_DUMPABLE, 0)`:
     - Disallows other processes running under the same UID from reading `/proc/<pid>/mem`.
     - Blocks `ptrace(PTRACE_ATTACH)` debugger attachments and memory inspection.
     - Changes `/proc/<pid>/` ownership to `root:root`.
   - Enforces `prctl(PR_SET_NO_NEW_PRIVS, 1)` to prevent child executions from acquiring elevated permissions.

---

## What This Tool Cannot Do

Stated because a limitation the user is not told about is a limitation they will assume away.

- **Memory locking and core-dump disabling are Linux-only in the current revision.** Guarantees 4 and
  5 depend on `mlock`/`munlock` and `setrlimit(RLIMIT_CORE)`, which are POSIX interfaces. The Windows
  backend is **deferred**: on a non-Unix target these capabilities are **not provided at all**, and
  the library reports `NotSupported` rather than silently succeeding. Code that asks for a lock on
  Windows receives an error; it does not receive a false assurance.
- **Zeroization is best-effort against a privileged attacker.** Wiping memory protects against
  crashes, swap files, and later reuse of the same allocation. It does not protect against a
  compromised kernel, a hypervisor, or hardware that can read physical memory.
- **A copy of a secret is not automatically protected.** `Secret<T>` wipes what it owns. Copying its
  bytes into an ordinary `Vec<u8>`, a `String`, or a language runtime that manages memory itself
  creates material that nothing will wipe. This is a property of the surrounding language, not of
  this library.
- **`#[must_use]` is not exhaustive.** Discarding the whole `(Secret, MemoryLockStatus)` tuple warns,
  but `let (secret, _) = Secret::new(buf);` does not. The caller must read the status; the type
  system will not force them to.
- **This is not a key store.** `Secret<T>` protects a buffer for the duration of an operation. It does
  not persist, rotate, or manage keys.

### The USB session guard (F3.5)

- **The session guard is Linux-only in the current revision.** It binds a session to the device backing a
  working directory, using `/sys/dev/block`, `/sys/block/<dev>/device/*`, and `/dev/disk/by-uuid` — Linux
  facilities. On macOS and Windows the backend is **not provided**, and the guard reports `NotSupported`
  rather than silently reporting a session as present. **This is deliberate and enforced at compile time**:
  the backend is gated `#[cfg(target_os = "linux")]`, so those platforms cannot acquire a backend that
  cannot work.
- **It detects; it does not exit.** `check()` reports whether the bound device is still the same one. Acting
  on that — dropping secrets, closing the UI — is the caller's job. The guard cannot meet the one-second
  bound on its own: it owns 250 ms of it.
- **The guard does not assert how quickly a caller reacts.** Its latency test measures *detection* only.
  A session meets the end-to-end bound only if the caller also polls at least every 250 ms and acts
  promptly — including while blocked on input.
- **`Unverifiable` is treated as a failure, not a warning.** If a device's serial or filesystem UUID cannot
  be read, the guard refuses rather than binding to a weaker signal. On a drive that exposes no serial in
  sysfs at all, the guard will **not run at all** until that path is implemented. Failing closed is
  intended, and this narrows which drives work.
- **A device soldered internally but attached over USB is treated as removable.** It is indistinguishable
  from an external drive by any signal the operating system exposes. Refusing every USB device to defend
  against that configuration would reject every external drive.
- **Removability is decided by how a device is attached, not by the kernel's `removable` flag.** The flag
  cannot distinguish a USB enclosure that presents a fixed disk (which reports `0`) from an internal drive
  (which also reports `0`). A tool that trusted the flag alone would refuse a legitimate external hard
  drive.
- **The guard verifies the device, not the filesystem.** It confirms the same device is still present and
  has the same identity. It does not check that the filesystem on it is intact, uncorrupted, or unmodified.
- **An attacker who images the medium wins.** The guard binds to a device's identity — its serial and
  filesystem UUID. It cannot detect data copied onto identical media, because identity is a property of the
  device, not of its contents.

---

## Installation & Environment

The virtual environment is set up at `pass_`:

```bash
# Activate virtual environment
source pass_/bin/activate

# Install in editable mode
pip install -e .
```

---

## Command-Line Usage

The command `passkey-gen` is installed directly into `pass_/bin/passkey-gen`.

### 1. Default (32 characters, alphanumeric)
```bash
./pass_/bin/passkey-gen
```
*Output:*
```
qnlvqsXzkJUAOIZNazv6AUgKvDlsguVP
```

### 2. High-Entropy 64 characters
```bash
./pass_/bin/passkey-gen -l 64
```

### 3. Custom Length & Character Set Preset
```bash
# 50 characters using complex punctuation set
./pass_/bin/passkey-gen -l 50 -c complex

# 32 characters in hexadecimal
./pass_/bin/passkey-gen -l 32 -c hex

# URL-safe base64
./pass_/bin/passkey-gen -l 64 -c base64url

# Human-readable (excludes 0/O, 1/l/I to prevent ambiguity)
./pass_/bin/passkey-gen -l 32 -c readable
```

### 4. Display Information-Theoretic Entropy
```bash
./pass_/bin/passkey-gen -l 32 --show-entropy
```
*Output:*
```
[*] Charset size: 62 chars | Length: 32 chars | Entropy: 190.53 bits
qnlvqsXzkJUAOIZNazv6AUgKvDlsguVP
```

### 5. Ephemeral Zero-Trace Display (Terminal Scrollback Defense)
```bash
# Displays passkey in an alternate screen buffer with live countdown (15s default)
# Exiting or expiry completely reverts terminal screen leaving 0 scrollback lines
./pass_/bin/passkey-gen -l 64 -e

# Custom duration (e.g. 10 seconds)
./pass_/bin/passkey-gen -l 32 -e 10
```

### 6. Secure Clipboard with Automated Auto-Wipe
```bash
# Copies to clipboard (Wayland/X11/OSC 52) and automatically wipes clipboard after 20s
./pass_/bin/passkey-gen -l 32 -C

# Combine Ephemeral Display + Clipboard: wipes both when dismissed
./pass_/bin/passkey-gen -l 64 -e -C

# Custom clipboard auto-wipe timeout (e.g. 45 seconds)
./pass_/bin/passkey-gen -l 64 -C --copy-timeout 45
```

### 7. Piping / Silent Mode
```bash
./pass_/bin/passkey-gen -l 64 -q
```

### 8. Kernel Process Defense Audit
```bash
./pass_/bin/passkey-gen --audit
```
*Output:*
```
[*] Linux Process Defense Audit:
  - Core Dumps Disabled (RLIMIT_CORE=0): [SECURE]
  - Non-Dumpable (PR_SET_DUMPABLE=0):     [SECURE] (ptrace & /proc/mem blocked)
  - No New Privileges (PR_SET_NO_NEW_PRIVS=1): [SECURE]
  - Memory Lock Available (mlock):       [ENABLED]
```

### 9. FIDO2 / WebAuthn Asymmetric Passkey Generation
```bash
# Generate standard ES256 (NIST P-256) WebAuthn Passkey
./pass_/bin/passkey-gen --webauthn

# Generate Ed25519 (EdDSA) WebAuthn Passkey
./pass_/bin/passkey-gen --webauthn --webauthn-alg Ed25519

# Export in WebAuthn-compliant JSON format
./pass_/bin/passkey-gen --webauthn --json

# Export encrypted PKCS#8 private key
./pass_/bin/passkey-gen --webauthn --export-private --passphrase "MySecurePassphrase"
```

---

## Python API Usage

### 1. Symmetric High-Entropy Tokens (Zero Caching)
```python
from passkey_gen import PasskeyGenerator, CharsetPreset

generator = PasskeyGenerator()

# Use context manager: memory is wiped immediately upon exiting the block
with generator.generate(length=32, charset=CharsetPreset.ALPHANUMERIC) as key:
    secret = key.get_value()
    # Consume secret (e.g. hash it with Argon2 or send over secure socket)

# Here, key memory has been actively zeroized via explicit_bzero/memset
# key.get_value() will raise RuntimeError if accessed!
```

### 2. FIDO2 / WebAuthn Resident Credentials
```python
from passkey_gen import WebAuthnAlgorithm, generate_webauthn_passkey

# Generate an ES256 or Ed25519 resident credential
with generate_webauthn_passkey(WebAuthnAlgorithm.ES256) as passkey:
    print("Credential ID:", passkey.credential_id)
    print("Public Key (COSE Base64url):", passkey.public_key_cose_b64)
    print("Public Key (JWK):", passkey.public_key_jwk)

    # Sign an authentication challenge assertion (clientDataHash)
    signature = passkey.sign_assertion(b"test_challenge_hash_32_bytes___")

# WARNING: contrary to earlier versions of this document, exiting this block does
# NOT wipe the private key. WebAuthnPasskey.destroy() sets self._private_key = None,
# which drops the reference without zeroizing memory. Do not rely on this class to
# protect long-lived private key material. See docs/LANGUAGE_DECISION.md §4.
```

---

## Running the Test Suite

```bash
./pass_/bin/pytest -v --cov=passkey_gen
```
All tests verify memory zeroization, modulo bias elimination (Chi-square statistical goodness-of-fit), lifecycle guarantees, and input validation.
