# TokenGen

**A passkey and secret vault for a USB drive — offline, fail-closed, and honest about what it does not yet do.**

TokenGen generates, stores, manages, protects, and displays secrets and passkeys entirely from a removable
drive. It never contacts a network. It refuses to run rather than run weakened. And it states, on this page,
exactly which parts of that sentence are true today.

---

## ⚠️ Read this before anything else

**TokenGen is not finished.** It is published early so the security work is auditable from the beginning.

| Capability | State |
|---|---|
| **Generate** secrets from kernel entropy | **WORKS.** Frozen, hardware-verified. |
| **Protect** secrets in memory (zeroization, locking, no core dumps) | **WORKS** on Linux. Frozen. |
| **Bind** a session to a specific USB drive | **WORKS** on Linux. Frozen. |
| **Store** secrets on the drive | **NOT BUILT.** Nothing is persisted. |
| **Manage** them (list, rename, delete, rotate) | **NOT BUILT.** |
| **Display** them safely (no scrollback, clipboard auto-clear) | **NOT BUILT.** The tool prints to stdout. |
| Back up / restore | **NOT BUILT.** |
| Windows and macOS | **NOT BUILT.** Both refuse, deliberately. |

**What that means in practice today:** if you run TokenGen, it will produce a secret and print it. **It will
not save it anywhere.** If you want to keep it, you must copy it into a password manager yourself — and the
tool will warn you that it is now in your terminal scrollback.

**We are telling you this because the alternative is worse.** A tool that generated a "passkey" and gave you
nowhere to put it, while looking finished, would cause exactly the loss it exists to prevent. The storage
layer is the next major piece of work, and it is designed around not losing your data (see
[Roadmap](#roadmap)).

---

## What TokenGen is for

Every password manager asks you to trust a browser extension, a cloud sync, or both. TokenGen's position is
that **the secret never leaves hardware you hold, and the machine it runs on never learns it.**

When finished it will be:

- **Generates** — secrets from the operating system's CSPRNG, with no user-space PRNG state and no modulo
  bias, at lengths you choose from a defined character set.
- **Stores** — an encrypted vault on the USB drive, bound to that drive's identity, so a copy of the file
  alone opens nothing.
- **Manages** — named entries, listing, rotation, deletion, with every mutation auditable.
- **Protects** — memory is locked and wiped on drop, compiled in rather than remembered; core dumps are
  suppressed; secrets are never written to the host disk or to logs.
- **Displays** — on request, briefly, never into scrollback by default, never auto-filled into a page.

**And deliberately does not:** contact any network, sync to any service, integrate with a browser extension,
or store anything on the host machine.

---

## Design commitments

These are not aspirations. Each is enforced by the test suite, and several are enforced by the compiler.

**1. Fail closed, always.**
Every failure path refuses. A guard that cannot verify something says so and stops. There is no
"degrade gracefully" branch in any security-critical path — that pattern is precisely how a tool reports
success while protecting nothing.

**2. Secrets are wiped by construction, not by discipline.**
`Secret<T>` zeroizes on drop and cannot be cloned or formatted. `#![forbid(unsafe_code)]` on the main crate
means a mistake is a compile error. The `unsafe` that memory locking requires is confined to one sub-crate
behind a safe API, in enumerated modules whose count is checked by a script.

**3. The device binding is real, and its limits are stated.**
A session is bound to the identity of the drive the working directory lives on — filesystem UUID plus the
drive's own serial. Pulling the drive, or substituting another, is detected.

Some drives expose no serial of their own. For those the guard binds to the **USB enclosure** instead, and
**says so** — because an enclosure binding does not detect someone replacing the memory inside the same
enclosure. You are told which guarantee you have rather than assumed to have the stronger one.

**4. No external binaries, no shell, no subprocess.**
TokenGen does not shell out to `lsblk`, `mount`, `gpg`, or anything else. Every mechanism is implemented in
Rust against the kernel interface directly, so there is no `PATH` to poison and no argument to inject.

**5. Three third-party dependencies.**
`getrandom`, `zeroize`, and `libc` (Unix target only). That is the entire external dependency graph — there
is no cryptography library, because there is no vault yet to encrypt. A security tool's supply chain is an
attack surface, and this one is small enough to read in an afternoon.

**6. The method is part of the product.**
Every feature is frozen against a specific commit after an anchored gate run: cold rebuild from an extracted
copy, all gates green, CI green on three platforms. Every amendment and every defect found is recorded — see
[Why the failures are public](#why-the-failures-are-public).

---

## Using it today

Requires a Rust toolchain and Linux. **A removable drive must be attached and mounted**, and your working
directory must be on it.

```console
$ cd /media/you/YOUR-DRIVE
$ tokengen status
tokengen 0.1.0
session guard: present
binding level: DISK — the serial belongs to the medium, so replacing the enclosure is detected.

$ tokengen generate -l 32
Xk9mP2vQ7rT4wY8nB3cF6hJ5sL1dG0zA
```

That secret is **printed and gone**. Nothing was saved. Copy it now, or it is lost.

```console
$ tokengen generate -c hex -l 64      # character sets: alnum, lower, upper, digits, hex
$ tokengen status                     # what the guard sees, without generating
$ tokengen help
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | success |
| `2` | usage error |
| `3` | **security refusal** — no drive, wrong drive, or an identity that cannot be verified |
| `4` | this location or platform cannot be used (no device backend, or the working directory has no block device) |
| `5` | generation failed |

**One rule with no exceptions: a non-zero exit leaves stdout empty.** A script cannot mistake a refusal for
a secret, because a refusal produces no output at all.

---

## What TokenGen cannot do

Stated because a limitation the user is not told about is a limitation they will assume away.

**About storage (the big one):**

- **Nothing is stored.** There is no vault yet. A generated secret exists only in the terminal until you copy
  it. This is the most significant gap and the next major piece of work.
- **There is no recovery.** No backup, no export, no recovery code — because there is nothing to recover yet.
  When the vault ships, **recovery will be an encrypted export the user controls**, never a cloud service and
  never a backdoor. Losing the drive while holding that export is recoverable; losing both is not, and no
  design changes that.

**About platforms:**

- **Linux only.** Windows and macOS have no device backend; TokenGen refuses there rather than pretending.
- **Memory locking and core-dump suppression are Linux-only** in this revision.
- **The working directory must be on a real block device.** A `tmpfs`, an overlay filesystem, or a network
  mount has no device behind it, so the guard cannot bind and exits with code 4.

**About the threat model:**

- **Zeroization is best-effort against a privileged attacker.** Wiping memory protects against a later reader
  of that memory. It cannot defeat code running in the same process, a kernel that ignores it, or a hardware
  attacker.
- **A copy of a secret is not automatically protected.** `Secret<T>` wipes what it owns.
- **This is not a key store yet** — and when it becomes one, the vault's encryption will be a documented,
  reviewed construction rather than something improvised.
- **`#[must_use]` is not exhaustive.** Discarding the whole return value of a capture warns at compile time;
  destructuring it to discard one part does not.
- **The session guard detects; it does not exit.** It reports when the bound device changed. A caller that
  ignores the report has ignored it — which is why the CLI checks twice, once at capture and once
  immediately before output.
- **On a drive with no serial of its own, the guard binds to the enclosure.** Unplugging, substitution, and
  moving ports are detected. **Replacing the memory inside the enclosure is not.**
- **A device soldered internally but attached over USB is treated as removable.** The two are
  indistinguishable.

---

## Why the failures are public

This repository keeps a record of every defect found, including the ones that were embarrassing: a guard that
reported a `tmpfs` path as a missing device; a `status` command that quietly broke the no-output-on-failure
rule; a device-identity walk that could bind to the **host controller** instead of the drive, making two
different drives look identical and defeating the swap detection entirely.

That last one was found by adversarial review, not by the author. It is documented here because a security
tool that only publishes its successes is asking you to trust a claim you cannot check.

The recurring lesson is recorded too: **checkers that silently ignore input they do not recognise report
coverage they do not have.** Three separate defects came from that single shape.

See [`docs/`](docs/) for design records, completion reports, and the amendments that document every change to
a frozen artifact.

---

## Roadmap

Ordered by what reduces risk fastest, not by what is most visible.

| Feature | What it delivers | State |
|---|---|---|
| **Vault** | encrypted store on the drive; the thing that makes this a password manager | **Next** |
| **Encrypted export** | user-controlled backup and recovery | With the vault |
| **Display / clipboard** | safe reveal, auto-clear, never scrollback by default | Planned |
| **Passphrase prompt** | so the vault can be unlocked | Planned |
| **Release pipeline** | signed binaries, checksums, reproducible builds | Planned |
| **Windows / macOS** | the same guarantees off Linux | Blocked on hardware to verify against |

**On WebAuthn:** TokenGen's name suggests WebAuthn credential generation. The Rust engine does **not**
implement CBOR attestation or credential structures today — it generates high-entropy secrets. A non-runnable
reference implementation of that encoding is kept in `legacy/python/` so the Rust work can be checked against
it when it is built. **If you need WebAuthn credentials today, TokenGen is not that tool yet.**

---

## Building and verifying

```console
$ cargo build --release --locked -p tokengen-cli
$ cargo test --release --locked --workspace
$ ./scripts/cfg_check.sh          # every cfg branch compiles, not just the active one
$ ./scripts/footprint_check.sh    # no file/environment write surface in shipped code
$ ./scripts/dependency_check.sh   # the dependency allow-list holds
```

Requires Rust **1.85** (pinned in `rust-toolchain.toml`; declared honestly in `Cargo.toml` because `zeroize`
1.9.0 requires it).

**No reproducible-build guarantee yet, and no signed releases.** Until those exist, a binary you did not build
yourself cannot be verified — build from source.

---

## Security

Report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md). Private vulnerability reporting is
enabled on this repository.

**Do not open a public issue for a security defect.** The disclosure route is checked and working; please use
it.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).
