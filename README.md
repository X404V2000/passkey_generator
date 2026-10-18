# TokenGen (`passkey-gen`)

> ## ⚠️ Project status — read before installing
>
> TokenGen's supported implementation is **Rust**. The legacy Python has been **removed from the trust
> path** (F3.9): it is no longer installed by any packaging path, and it lives under `legacy/python/` with a
> README explaining why it cannot satisfy this project's invariants.
>
> | | Rust (`src/`, `tokengen-sys/`) | Python (`legacy/python/`) |
> |---|---|---|
> | Status | **Supported.** F1, F2, F3 and F3.5 are frozen. | **Legacy — do not use for real secrets.** Not installed by any packaging path. |
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
   - The legacy Python encapsulated secrets inside `SecurePasskey`, backed by native C buffers (`ctypes`). It now lives under `legacy/python/` and is not installed.
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
- **On a drive that exposes no serial of its own, the guard binds to the USB enclosure instead.** Ordinary
  USB flash drives often have no disk serial. The guard then identifies the *enclosure*: it still notices the
  drive being unplugged, a different drive substituted, or the same drive moved to another port — but it does
  **not** notice the memory inside the same enclosure being replaced. Which kind of binding you have is
  reported rather than assumed. Refusing such drives entirely was the alternative, and it would have made the
  tool unusable on a very common class of USB stick.
- **A device soldered internally but attached over USB is treated as removable.** It is indistinguishable
  from an external drive by any signal the operating system exposes. Refusing every USB device to defend
  against that configuration would reject every external drive.
- **Removability is decided mainly by how a device is attached, not by the kernel's `removable` flag.** The
  flag cannot distinguish a USB enclosure that presents a fixed disk (which reports `0`) from an internal
  drive (which also reports `0`), so a tool that trusted the flag alone would refuse a legitimate external
  hard drive. A **removable** transport (USB, eMMC, Thunderbolt, FireWire) is accepted on that basis alone;
  a **fixed** transport (NVMe, ATA, SATA) is accepted if the kernel reports the media as removable, which is
  the correct behaviour for a card reader or a media slot. So the rule is not "the flag never matters" — it
  matters for fixed transports, by design.
- **The working directory must be on a real block device.** A directory on a `tmpfs`, an overlay filesystem
  (common inside containers), or a network mount has **no device behind it**, so the guard cannot bind and the
  tool exits with code 4. This is reported as *"not on a block device at all"* rather than as a missing
  device, because the remedies differ — replugging a drive will never fix a `tmpfs` path.
- **The guard verifies the device, not the filesystem.** It confirms the same device is still present and
  has the same identity. It does not check that the filesystem on it is intact, uncorrupted, or unmodified.
- **An attacker who images the medium wins.** The guard binds to a device's identity — its serial and
  filesystem UUID. It cannot detect data copied onto identical media, because identity is a property of the
  device, not of its contents. This also covers a device that under-reports its own serial length: it would
  yield a shorter (prefix) serial, but two different devices still differ, so a swap is still detected.
- **The device identification is verified against USB hardware; the platform backends are not verified at
  all.** What has been exercised on real hardware is the Linux device path, with USB drives attached — a
  removable drive is accepted, an internal root is refused, and identity survives unplugging and re-plugging.
  What has **not** been exercised anywhere is the macOS and Windows backend, because those backends do not
  exist yet; those platforms are compiled by CI and then refuse with `NotSupported`. Compiled is not
  verified, and this tool should not be trusted on macOS or Windows until that work lands.

---
## Status: there is no installable command yet

**TokenGen 1.0 has not been released.** The `pip install .` path that used to install a `passkey-gen` command
**has been removed**, because the only implementation that could back it was the legacy Python, which violates
this project's own invariants. See [`legacy/python/README.md`](legacy/python/README.md) and `SECURITY.md`.

**This is deliberate.** Installing **no** command is honest; installing the **wrong** one is not. The Rust
CLI is feature **F4**, and it does not exist yet.

| I want to… | Where to go |
|---|---|
| Build and test the Rust library | `cargo test --release --locked --features test-hooks -p tokengen` |
| Read the design and the guarantees | [`docs/`](docs/) — `F1_DESIGN.md`, `F2_DESIGN.md`, `F3_DESIGN.md`, `F3.5_DESIGN.md` |
| Know what this tool cannot do | [the section above](#what-this-tool-cannot-do) — **read this before trusting anything** |
| Report a vulnerability | [`SECURITY.md`](SECURITY.md) |
| Understand the roadmap and the gate | [`plan/PROJECT_PLAN.md`](plan/PROJECT_PLAN.md) |
| See what is being worked on | [`plan/mailroom/`](plan/mailroom/) and [`plan/reports/`](plan/reports/) |

## Building and testing

Requires **Rust 1.85** (pinned in `rust-toolchain.toml`).

```bash
cargo build --release --locked
cargo test --release --locked --features test-hooks -p tokengen      # the main crate
cargo test --release --locked -p tokengen-sys                        # the platform crate
cargo clippy --all-targets --features test-hooks -- -D warnings
cargo fmt --check
./scripts/cfg_check.sh                                               # compiles the deferred cfg branches
```

The whole suite runs in **CI on Linux, macOS and Windows** for every push. A green matrix means the code
**compiles and the tests pass** on those platforms — it does **not** mean the tool works on them; see the
platform note in [What This Tool Cannot Do](#the-usb-session-guard-f35).

## What is actually implemented

| Feature | State |
|---|---|
| **F1** — CSPRNG entropy | **Frozen.** Kernel CSPRNG, no user-space PRNG state. |
| **F2** — charset / rejection sampling | **Frozen.** Zero modulo bias. |
| **F3** — zeroization, memory locking, core-dump suppression | **Frozen.** Linux only. |
| **F3.5** — USB session guard | **Frozen** at `3c9dcbc`. Linux only. |
| **F4** — CLI | **Not started.** Until it exists there is no user-facing tool. |
| F5–F10 | Not started. See the roadmap. |

## A note on the legacy Python

`legacy/python/` holds the original Python prototype. It is **unmaintained, not installed, and not part of
the trust path**, and its own README explains why it cannot satisfy G3 (fail-closed). It is kept only because
it is the sole end-to-end WebAuthn/CBOR reference in the repository, which **F4** will want when that
behaviour is rebuilt in Rust.

**Do not use it. Do not rely on its tests** — they are not run by any CI job.
