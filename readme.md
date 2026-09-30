```markdown
# TokenGen — Secure Portable Token & Passkey Generator

**Version:** 1.0 (Draft)
**Status:** In development — F1 (Entropy Module) complete; see roadmap below
**License:** (to be decided — recommend GPLv3 or Apache-2.0 for auditability)
**Homepage:** (to be filled in when published)
**Source:** (to be filled in when published)
**Contact:** (to be filled in — recommend a dedicated security@ address)

---

## Table of Contents

1. [What This Is](#1-what-this-is)
2. [What This Is Not](#2-what-this-is-not)
3. [What This Tool Cannot Do](#3-what-this-tool-cannot-do)
4. [Who This Is For](#4-who-this-is-for)
5. [How It Works](#5-how-it-works)
6. [Installation & Usage](#6-installation--usage)
7. [Security Model](#7-security-model)
8. [Threat Model](#8-threat-model)
9. [Verifying Your Download](#9-verifying-your-download)
10. [Privacy & Footprint](#10-privacy--footprint)
11. [Roadmap](#11-roadmap)
12. [Frequently Asked Questions](#12-frequently-asked-questions)
13. [Reporting Security Issues](#13-reporting-security-issues)
14. [Building From Source](#14-building-from-source)
15. [Contributing](#15-contributing)
16. [License](#16-license)
17. [Changelog](#17-changelog)

---

## 1. What This Is

TokenGen is a **portable, offline, open-source tool** for generating cryptographically secure tokens, passkeys, passwords, and API keys of arbitrary length (32 characters and beyond).

Key properties:

- **Runs directly from a USB drive.** No installation on the host computer.
- **Works on Windows, Linux, and macOS** from the same USB drive (separate binaries per OS, single drive).
- **100% offline.** No network code is compiled into the binary. Ever.
- **Open source.** Every line is auditable.
- **No footprint on the host.** The tool writes nothing to the host's disk, registry, `$HOME`, `%APPDATA%`, `~/Library`, or anywhere else.
- **Auto-clears on USB removal.** When you unplug the drive, the app closes immediately and zeroizes its memory.
- **Cryptographically correct.** Uses the operating system's CSPRNG (`getrandom` syscall) with rejection sampling — not `rand()`, not `Math.random()`, not time-based seeds, not modulo bias.

TokenGen is designed for:

- People who need long, high-entropy secrets but don't want to trust closed-source web generators.
- People who work across multiple machines and want a consistent, portable tool.
- People who want a tool that is honest about its limits.

---

## 2. What This Is Not

TokenGen is **not**:

- A password manager. It does not store, sync, or remember your keys. It generates them; storing them is your responsibility.
- A hardware security module. It is software running on a general-purpose computer.
- A guarantee of safety on a compromised machine. If your host has a keylogger, no software tool can protect you.
- A replacement for a YubiKey, Nitrokey, or other dedicated hardware token. Those provide stronger guarantees against host compromise.
- A way to bypass OS security. It does not exploit autorun, HID emulation, or any other trick.
- A cloud service. It does not call home. It does not check for updates. It does not phone anywhere.

---

## 3. What This Tool Cannot Do

We are honest about limits. Read this section carefully. If any of these matter to your threat model, TokenGen is not sufficient on its own.

### 3.1 It cannot auto-launch without a user click

Modern operating systems (Windows since 2011, macOS, most Linux desktops) **block automatic execution of programs from removable media** by design. This is a security feature that prevents exactly the kind of "malicious USB" attacks you want to avoid.

TokenGen ships a **Launch helper** on each OS. You double-click it once. That is the maximum safe "auto-launch" that exists today.

Any tool claiming to auto-run on plug-in is either:
- Exploiting an OS vulnerability (i.e., it is malware), or
- Lying.

We do neither.

### 3.2 It cannot erase OS-level USB logs

Your operating system records USB plug/unplug events in system logs, regardless of what any application does:

- **Windows:** `setupapi.dev.log`, Event Viewer, prefetch files, shellbags, USBSTOR registry entries
- **macOS:** Unified log (`log show`), `system.log`, Spotlight metadata
- **Linux:** `journalctl`, `dmesg`, `udev` events

**TokenGen cannot delete these.** They live in the host OS, outside the app's reach, and deleting them would require administrator/root privileges (which would itself leave traces).

What TokenGen *does* guarantee: **it writes none of its own files to the host.** No cache, no config, no history, no temp files on the host disk.

If you need zero host-side forensics, run TokenGen from a live OS (Tails, etc.) or a dedicated machine.

### 3.3 It cannot protect you from a compromised host

If the machine you run TokenGen on has:

- A **keylogger** — your keystrokes are captured regardless of what TokenGen does
- A **screen recorder** or **screen scraper** — your displayed keys are captured
- A **clipboard manager** that logs history — if you copy a key, it may be logged
- A **rootkit** or kernel-level malware — all bets are off

TokenGen mitigates what it can (screen-only display by default, optional clipboard with auto-clear, scramble-on-blur, memory locking) but cannot defeat a compromised kernel.

**Rule:** Only run TokenGen on machines you trust.

### 3.4 It cannot prevent cold-boot RAM attacks

We call `mlock()`/`VirtualLock()` to prevent key material from being swapped to disk, and we zeroize memory aggressively. However:

- On some systems (macOS without entitlements, some Linux configs, Windows under certain policies) memory locking is **denied by the OS**.
- Cold-boot attacks can sometimes recover RAM contents even after power-off.

**Mitigation in TokenGen:** If memory locking fails, we show a visible warning and continue. We do not hide this.

### 3.5 It cannot detect a physically cloned USB

An attacker with physical access to your USB drive can clone it (including filesystem UUID). We bind to:

- Mount path
- Filesystem UUID
- Hardware serial (via OS-specific APIs)

If all three are cloned perfectly, our binding is defeated. Hardware serial cloning is difficult but not impossible on some USB controllers.

**Mitigation:** Use a USB drive with a hardware serial number that cannot be rewritten (most reputable brands). Never leave your USB unattended.

### 3.6 It cannot stop you from using a weak character set or short length

TokenGen enforces minimums (see [§7.5](#75-length-and-charset-rules)) but you can request a weak configuration if you insist. We warn; we do not block. The tool's job is to be correct, not paternalistic.

### 3.7 It cannot guarantee "the device completely forgets it"

There is no such guarantee possible from userland software. We say this plainly. See [§10](#10-privacy--footprint) for what we actually guarantee.

---

## 4. Who This Is For

TokenGen is appropriate for:

- Developers who need API keys, session tokens, or salts generated locally.
- Privacy-conscious users who do not trust web-based generators.
- System administrators who need a portable, offline, auditable tool.
- Journalists, activists, or researchers who work on untrusted machines and want a tool that leaves no app-level trace.
- Anyone who needs a password longer than 32 characters and wants correct, unbiased generation.

TokenGen is **not** appropriate for:

- Anyone who needs protection against a compromised host OS.
- Anyone who needs hardware-backed key storage (use a YubiKey/Nitrokey).
- Anyone who needs keys to persist across sessions (use a password manager).
- Anyone who needs automatic execution on USB insertion (no safe tool does this).

---

## 5. How It Works

### 5.1 High-level flow

1. You insert the TokenGen USB drive into a computer.
2. You open the drive and double-click `Launch` (per-OS name below).
3. The Launch helper:
   a. Computes the SHA-256 hash of the main binary.
   b. Verifies the binary's detached signature against a public key **embedded in the launcher at build time**.
   c. If verification fails, refuses to run and shows a clear error.
   d. If verification succeeds, launches the main binary.
4. The main binary:
   a. Binds to the USB (mount path + filesystem UUID + hardware serial).
   b. Attempts to lock memory (`mlock`/`VirtualLock`); warns if denied.
   c. Disables core dumps.
   d. Shows a small window with options.
5. You choose length, charset, and mode; the tool generates a key using the OS CSPRNG.
6. The key is displayed on screen. It is **not** written to disk.
7. You either memorize/transcribe it, or (optionally, with explicit click) copy it to the clipboard, which auto-clears after a configurable timeout.
8. When you unplug the USB, the app detects the removal within ~500ms, zeroizes all memory, closes the window, and exits.

### 5.2 Entropy source

TokenGen does **not** implement its own random number generator. It calls the OS CSPRNG:

| OS | Syscall |
|---|---|
| Windows | `BCryptGenRandom` |
| Linux | `getrandom(2)` |
| macOS | `SecRandomCopyBytes` |

In Rust, this is wrapped by the `getrandom` crate. If the OS call fails, TokenGen **fails closed** — it refuses to generate a key rather than falling back to a weaker source.

### 5.3 Key generation algorithm

For character-based keys:

1. Request N bytes from the OS CSPRNG.
2. Map bytes to characters using **rejection sampling** — never modulo (`byte % len`), which introduces bias.
3. Repeat until the requested key length is filled.

For word-based keys (Diceware-style):

1. Use the EFF long wordlist (7,776 words, ~12.9 bits entropy per word).
2. Select words using the same rejection-sampling approach.
3. Default: 6 words (~77 bits). Recommended: 8 words (~103 bits).

### 5.4 Memory handling

- All key material lives in `Zeroizing<Vec<u8>>` wrappers.
- On drop, memory is overwritten with zeros before deallocation.
- `mlock`/`VirtualLock` prevents swapping to disk (when the OS permits).
- On USB removal, all key buffers are explicitly zeroized before process exit.
- Core dumps are disabled at startup to prevent accidental RAM dumps containing keys.

### 5.5 Session guard

Every 500 ms, the app checks whether the USB is still mounted. If the mount disappears (drive unplugged, ejected, or forcibly removed):

1. Zeroize all in-memory key material.
2. Close the UI window immediately.
3. Exit the process within 1 second.

Before every sensitive operation, the app re-verifies the USB's identity (mount path + UUID + serial). If the identity has changed, it aborts — this defends against a mid-session swap attack.

---

## 6. Installation & Usage

### 6.1 Installation

**There is no installation.** TokenGen is portable.

1. Download the release for your OS (see [§9](#9-verifying-your-download)).
2. Copy the entire `TokenGen/` folder to the root of a USB drive.
3. Optionally, mark the drive read-only via a physical switch if your drive supports it.

### 6.2 USB layout

```
TokenGen/
├── README.md              (this file)
├── LICENSE
├── CHANGELOG.md
├── SECURITY.md            (how to report vulnerabilities)
├── VERIFY.md              (step-by-step verification guide)
├── checksums.txt          (SHA-256 of every binary in this release)
├── checksums.txt.sig      (detached signature of checksums.txt)
├── win/
│   ├── Launch.cmd         (double-click this)
│   ├── generator.exe
│   ├── generator.exe.sig
│   └── README-WIN.txt
├── linux/
│   ├── Launch.sh          (double-click this)
│   ├── generator          (ELF binary)
│   ├── generator.sig
│   └── README-LINUX.txt
└── macos/
    ├── Launch.command     (double-click this)
    ├── generator          (Mach-O binary)
    ├── generator.sig
    └── README-MACOS.txt
```

### 6.3 Usage — Windows

1. Plug in the USB.
2. Open File Explorer, navigate to `TokenGen\win\`.
3. Double-click `Launch.cmd`.
4. If Windows SmartScreen warns, click "More info" → "Run anyway" **only if you have verified the signature** (see [§9](#9-verifying-your-download)).
5. The TokenGen window opens.

### 6.4 Usage — Linux

1. Plug in the USB.
2. Open your file manager, navigate to `TokenGen/linux/`.
3. Double-click `Launch.sh`. If your file manager refuses to run it:
   ```
   chmod +x Launch.sh generator
   ./Launch.sh
   ```
4. The TokenGen window opens.

### 6.5 Usage — macOS

1. Plug in the USB.
2. Open Finder, navigate to `TokenGen/macos/`.
3. Right-click `Launch.command` → Open → Open (the first time only; macOS remembers).
4. If Gatekeeper blocks it, verify the signature first, then allow it in System Settings → Privacy & Security.
5. The TokenGen window opens.

### 6.6 Generating a key

1. Choose length (default: 32).
2. Choose charset (default: uppercase + lowercase + digits + symbols).
3. Or choose word mode (default: 6 words).
4. Click **Generate**.
5. The key appears on screen.
6. Either:
   - Transcribe it manually (most secure), or
   - Click **Copy** — clipboard auto-clears after the timeout (default 20s).
7. When done, close the window or unplug the USB.

### 6.7 Unplugging

You do not need to close the app first. Unplug the USB and the app will:

- Zeroize memory
- Close the window
- Exit within ~1 second

If your OS requires "Safely Remove Hardware," use it — but TokenGen does not depend on graceful ejection.

---

## 7. Security Model

### 7.1 Trust boundaries

```
┌─────────────────────────────────────────────────────────┐
│  TRUSTED                                                │
│  ├── The TokenGen source code (auditable)               │
│  ├── The signed binary (verified via launcher)          │
│  ├── The OS CSPRNG syscall (getrandom/BCryptGenRandom)  │
│  └── The USB itself (physically in your possession)     │
├─────────────────────────────────────────────────────────┤
│  SEMI-TRUSTED                                           │
│  ├── The host OS (assumed honest but not private)       │
│  └── The USB controller firmware (assumed honest)       │
├─────────────────────────────────────────────────────────┤
│  UNTRUSTED                                              │
│  ├── Any network                                          │
│  ├── Any web-based generator                              │
│  └── Any host we did not personally verify              │
└─────────────────────────────────────────────────────────┘
```

### 7.2 Cryptographic primitives

| Purpose | Primitive | Notes |
|---|---|---|
| Random bytes | OS CSPRNG | `getrandom` crate |
| Charset mapping | Rejection sampling | No modulo bias |
| Signature verification | Ed25519 | Launcher → main binary |
| Checksums | SHA-256 | Release integrity |
| Constant-time compare | `subtle` crate | For any secret comparison |
| Memory zeroization | `zeroize` crate | Prevents compiler optimization |

We implement **no cryptography ourselves**. Every primitive comes from a well-audited crate or the OS.

### 7.3 Defenses against USB-borne attacks

| Attack | Defense |
|---|---|
| Malicious USB impersonating TokenGen | Launcher verifies main binary signature before running |
| Autorun-based malware on USB | We do not use autorun; we require one user click |
| HID emulation ("fake keyboard") | We do not emulate HID; the launcher is a normal executable |
| Binary swapped on USB | Launcher's embedded public key detects tampering |
| Both binary and signature swapped | Launcher itself is code-signed (OS-level); second trust root |
| USB swapped mid-session | Session guard re-verifies identity on every sensitive op |
| USB cloned (path + UUID) | Hardware serial binding raises the bar |
| Malicious `Launch.cmd`/`.sh`/`.command` | Launcher scripts are also signed; verification is the first action |

### 7.4 Defenses against host-side attacks

| Attack | Defense | Residual risk |
|---|---|---|
| Keylogger | None possible in userland | User must trust the host |
| Screen recorder | Scramble on blur; warn user | Not defeated |
| Clipboard hijack | Clipboard off by default; auto-clear | Mitigated, not eliminated |
| Swap-to-disk leak | `mlock`/`VirtualLock`; warn if denied | OS-dependent |
| Core dump leak | Core dumps disabled at startup | Effective on well-behaved OSes |
| Cold-boot RAM | Zeroize on exit; `mlock` | Mitigated, not eliminated |
| Host disk forensics | No app-level writes to host disk | OS-level USB logs remain |

### 7.5 Length and charset rules

**Minimums enforced by the UI (warnings, not hard blocks):**

| Mode | Minimum | Recommended | Notes |
|---|---|---|---|
| Character key | 16 chars | 32+ chars | 32 chars from 94-symbol set ≈ 210 bits |
| Word key | 5 words | 8 words | ~65 bits vs ~103 bits |

**Charsets available:**

- `ABC…Z` (26)
- `abc…z` (26)
- `0-9` (10)
- Symbols: `!@#$%^&*()-_=+[]{}<>?/|~` (26)
- Custom (advanced users only)

You may request fewer classes and shorter lengths. The tool warns; it does not block.

### 7.6 What "no network" means

The binary is compiled with **no networking dependencies**. CI checks:

- No `socket`, `connect`, `bind`, `send`, `recv` symbols in the binary.
- No HTTP/TLS crates in `Cargo.toml`.
- No DNS resolution calls.

If you find network code in TokenGen, it is a bug — please report it.

---

## 8. Threat Model

### 8.1 In scope

| Threat | Mitigation |
|---|---|
| Weak RNG producing predictable keys | OS CSPRNG only; fail closed |
| Modulo bias in charset mapping | Rejection sampling |
| Malicious USB substituting our binary | Launcher signature verification |
| Malicious USB clone (path + UUID) | Hardware serial binding |
| USB swap mid-session | Session guard re-verification |
| Key material lingering in RAM after use | `Zeroizing`, `mlock`, explicit wipe |
| Key material leaking to swap | `mlock`/`VirtualLock` |
| Key material leaking to core dump | Core dumps disabled at startup |
| Shoulder surfing | Screen-only display; scramble on blur |
| Clipboard history capture | Clipboard off by default; auto-clear when used |
| Supply chain attacks on dependencies | Minimal deps; `cargo-audit`/`cargo-deny` in CI |
| Tampered release binary | Detached signature + code-signing certificate |
| Fake download site | Single official source; published public key |
| User error (weak settings) | Warn (not block) on weak choices |

### 8.2 Out of scope

| Threat | Why out of scope |
|---|---|
| Compromised host OS (rootkit, kernel malware) | Userland tools cannot defend |
| Physical keylogger (hardware) | Outside software's reach |
| Compromised CPU/microcode | Beyond scope |
| Evil-maid attacks on the USB drive | Assume USB stays in user's possession |
| Attacker with physical access to user's machine during use | Outside software's reach |
| Coercion ("rubber-hose cryptanalysis") | Outside software's reach |
| Nation-state-level hardware implants | Outside scope for this tool |
| OS-level USB insertion logs | Cannot be erased from userland |

### 8.3 Assumptions

- The user's OS is honest and not compromised.
- The user's USB drive is physically in their possession and not tampered with.
- The user has verified the release signature before first use.
- The user is not under active physical surveillance during use.

---

## 9. Verifying Your Download

**Do this before you first run TokenGen.** It takes 2 minutes and it is the difference between "secure tool" and "malware delivery vehicle."

### 9.1 Get the signing key

Our release signing public key is:

```
Fingerprint: (to be filled in at first release)
Public key:  (to be filled in at first release)
Published at: (homepage URL)
              (repo URL)
              (this README)
```

**Verify the fingerprint via at least two independent channels** (e.g., our website and a signed release announcement). Do not trust a single source.

### 9.2 Verify the checksums

```
# Linux / macOS
sha256sum -c checksums.txt

# macOS (if sha256sum not present)
shasum -a 256 -c checksums.txt

# Windows (PowerShell)
Get-FileHash -Algorithm SHA256 .\win\generator.exe
# Compare against the value in checksums.txt manually
```

### 9.3 Verify the signature

Using `minisign` (recommended) or GPG:

```
minisign -Vm checksums.txt -P <our-public-key>
```

Or with GPG:

```
gpg --verify checksums.txt.sig checksums.txt
```

If verification fails, **do not run the binary**. Delete the download and re-download from the official source.

### 9.4 Verify OS-level code signature (optional, strong)

- **Windows:** Right-click `generator.exe` → Properties → Digital Signatures. The signer should be our publisher name.
- **macOS:** `codesign -dv --verbose=4 ./generator`
- **Linux:** No standard; rely on `minisign`/GPG.

### 9.5 What the launcher checks

The launcher, on each run, verifies:

1. SHA-256 of the main binary matches the value in `checksums.txt` (or an embedded copy — see release notes for the current scheme).
2. Detached signature `generator.sig` verifies against the public key **embedded in the launcher**.

If either fails, the launcher refuses to run the main binary and shows an error.

---

## 10. Privacy & Footprint

### 10.1 What TokenGen guarantees

**No files written to the host disk.** Specifically:

- No registry writes (Windows)
- No `plist`/`~/Library` writes (macOS)
- No `~/.config`/`dconf`/`gsettings` writes (Linux)
- No temp files outside the USB itself
- No "recent files" / MRU integration
- No shell history entries
- No log files anywhere except the screen

**No network activity.** Not one byte.

**No telemetry.** Ever.

**Memory zeroized on exit.** All key buffers explicitly overwritten.

**Process exits on USB removal.** Within ~1 second.

### 10.2 What TokenGen cannot guarantee

**OS-level USB insertion logs persist.** See [§3.2](#32-it-cannot-erase-os-level-usb-logs). These are outside our control.

**Forensic artifacts on the host may exist** beyond our reach:

- Windows: Prefetch, Amcache, ShimCache, shellbags, Jump Lists, USBSTOR registry keys, Event Log entries
- macOS: Unified log entries, Spotlight indexing of the USB mount, FSEvents
- Linux: `journalctl`/`dmesg`/`udev` events, shell history if you ran commands manually

**If the host is compromised, all guarantees are void.**

### 10.3 Honest summary

> TokenGen leaves **no application-level footprint** on the host.
> The host OS will still know a USB was inserted — this is normal,
> unavoidable, and outside our control.
> If you need zero host-side traces, use a live OS or a dedicated machine.

---

## 11. Roadmap

Development proceeds feature by feature. Each feature is frozen (blueprint → code → review → tests → commit) before the next begins.

| Feature | Description | Status |
|---|---|---|
| F1 | Core CSPRNG Entropy Module | ✅ Blueprint locked |
| F2 | Charset + Rejection Sampling Generator | ⏳ Next |
| F3 | Zeroization, `mlock`, core-dump disable | Planned |
| F3.5 | Session Guard (USB presence + identity) | Planned |
| F3.6 | Host Footprint Elimination | Planned |
| F4 | CLI Interface | Planned |
| F5 | Secure Display (screen-only, scramble-on-blur) | Planned |
| F6 | Optional Clipboard with Auto-Clear | Planned |
| F7 | Portable Config (next to binary only) | Planned |
| F7.5 | Launch Helper with Signature Verification | Planned |
| F8 | USB Self-Verification Tool | Planned |
| F9 | Release Signing & Checksum Pipeline | Planned |
| F10 | GUI | Planned |

Features may be reordered if dependencies require it. Scope may be reduced if a feature cannot be built safely.

---

## 12. Frequently Asked Questions

**Q: Why doesn't it auto-run when I plug in the USB?**
A: Because modern OSes block that behavior to prevent malware. Any tool that auto-runs on plug-in is either exploiting a vulnerability or lying. We require one double-click. See [§3.1](#31-it-cannot-auto-launch-without-a-user-click).

**Q: Can you make it fully portable so nothing is left on the host?**
A: We already do — no app-level files. But the OS still logs USB insertion. That is outside our control. See [§10](#10-privacy--footprint).

**Q: Why not use Python/JavaScript/Electron?**
A: Runtime dependencies expand the attack surface, make verification harder, and are rarely truly portable. We use Rust for memory safety and static binaries.

**Q: Is this a password manager?**
A: No. It generates keys. Storing them is your job. See [§2](#2-what-this-is-not).

**Q: Can I trust this with my most important secrets?**
A: Only after you have (a) verified the release signature, (b) reviewed the source, (c) understand the limits in [§3](#3-what-this-tool-cannot-do), and (d) are running on a machine you trust.

**Q: What happens if I lose the USB?**
A: Nothing catastrophic. TokenGen does not store your generated keys (unless you explicitly enable a storage feature — off by default and not yet implemented). The USB only contains the tool, not your secrets.

**Q: What happens if someone steals my USB?**
A: They get the tool, not your keys (assuming you did not enable storage). They could attempt to use the tool themselves. They cannot recover past keys from the USB.

**Q: Does it work on Windows XP / old Linux / macOS 10.x?**
A: No. Minimum versions are listed in each platform's `README-*.txt`. We target currently supported OSes.

**Q: Can I use it on a work computer?**
A: Only if your employer permits it. Many corporate environments restrict USB use, and TokenGen is not designed to circumvent such policies. Check your org's rules.

**Q: Why is the code so conservative (no unsafe, no fallback RNG, etc.)?**
A: Because this is a security tool. Every "convenience" fallback is a potential vulnerability. We choose correctness over cleverness.

**Q: Can I fork this and remove the launcher?**
A: Yes — it is open source. But you lose the signature verification, which is a core security property. We recommend against it.

**Q: Where can I find the security design document?**
A: In the `docs/` folder of the source repository. Every feature has a `F*_DESIGN.md` alongside it.

**Q: How do I know the binary I downloaded is the one you built?**
A: Reproducible builds. Anyone can rebuild from source and compare hashes. See [§14](#14-building-from-source).

---

## 13. Reporting Security Issues

**Do not open a public issue for security bugs.**

Email: `security@<domain>` (PGP key fingerprint to be published here)

Please include:

- A clear description of the issue
- Steps to reproduce
- Affected version(s)
- Your assessment of impact
- Whether you wish to be credited (default: yes, unless you ask otherwise)

We aim to:

- Acknowledge within 72 hours
- Triage within 7 days
- Ship a fix or a documented mitigation within 30 days for high-severity issues

We do not currently offer a bug bounty. We do offer public credit and our gratitude.

---

## 14. Building From Source

### 14.1 Requirements

- Rust 1.75 or newer (`rustup` recommended)
- For cross-compilation: platform-specific toolchains
- For reproducible builds: Docker (recommended) or Nix

### 14.2 Build

```
git clone <repo-url>
cd tokengen
cargo build --release
```

Binary appears at `target/release/generator`.

### 14.3 Reproducible build

We publish a Dockerfile that pins every tool version. To reproduce a release:

```
docker build -t tokengen-build -f docker/Dockerfile .
docker run --rm -v "$PWD:/src" tokengen-build
sha256sum target/release/generator
# Compare with the value in checksums.txt for the matching release
```

If the hashes differ, please report it. Reproducibility is a security property, not a nice-to-have.

### 14.4 Dependencies

Kept intentionally minimal:

- `getrandom` — OS CSPRNG interface
- `zeroize` — memory zeroization
- `subtle` — constant-time comparison
- (UI framework to be chosen at F10)

Every dependency is pinned and audited in CI with `cargo-audit` and `cargo-deny`.

---

## 15. Contributing

Contributions are welcome, but the bar is high for a security tool.

Before opening a PR:

1. Read the design doc for the feature you are touching (`docs/F*_DESIGN.md`).
2. Ensure `cargo test`, `cargo clippy -- -D warnings`, `cargo audit`, and `cargo deny check` all pass.
3. Do not add dependencies without justification in the PR description.
4. Do not introduce `unsafe`, `unwrap`, `expect`, or `panic!` in library code.
5. Add tests for any new behavior.
6. Update the relevant `F*_DESIGN.md` if the design changes.

We will reject PRs that:

- Add telemetry, analytics, or network code
- Add dependencies without clear need
- Weaken any invariant in [§7](#7-security-model)
- Skip tests for security-relevant code

---

## 16. License

(To be decided. Recommended: Apache-2.0 or GPLv3. Both are OSI-approved and permit auditability. GPLv3 prevents proprietary forks; Apache-2.0 maximizes reuse. Choose based on your values.)

---

## 17. Changelog

See `CHANGELOG.md`. Every release lists:

- Added / changed / removed / fixed
- Dependency changes (with version diffs)
- Security-relevant changes highlighted at top
- Signing key fingerprint used for the release

---

## Appendix A — File Format Reference

- `checksums.txt` — one line per file: `<sha256>  <path>`
- `checksums.txt.sig` — detached Ed25519 signature over `checksums.txt`
- `generator.sig` — detached Ed25519 signature over `generator` binary
- Launch helper per OS: `Launch.cmd`, `Launch.sh`, `Launch.command` — each embeds the release public key

## Appendix B — Environment Variables

**TokenGen reads none.** No `$HOME`, no `%APPDATA%`, no config paths. This is deliberate.

## Appendix C — Command-Line Flags (planned for F4)

To be documented at F4. Default behavior when no flags are given: launch the GUI.

## Appendix D — Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Generic error |
| 2 | Entropy failure (OS CSPRNG unavailable) |
| 3 | USB identity mismatch (possible swap attack) |
| 4 | Signature verification failed |
| 5 | Memory-lock failed in strict mode (not currently triggered; see [§3.4](#34-it-cannot-prevent-cold-boot-ram-attacks)) |

---

**End of README.**

*This document is versioned alongside the code. Any change to behavior must be reflected here before the release ships.*
```

---
