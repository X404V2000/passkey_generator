# Vault — Threat Model (Bruce, Security Officer)

**Status:** design stage. **No code is being written.** This document exists so the blueprint can be attacked
before it is built, not after.

**Authority:** this threat model constrains the blueprint. Any blueprint decision that violates a MUST here is
rejected before implementation.

---

## 1. What we are protecting

| Asset | Consequence of compromise |
|---|---|
| **Vault contents** — users' passkeys and secrets | **Irreversible** account compromise across every site the user holds |
| **The master passphrase** | Unlocks everything, everywhere the user reused it |
| **Vault availability** | **Permanent loss of every credential stored** — this is the failure the Founder named first |
| **User trust in the device binding** | If a swap goes undetected, a user may hand their vault to the wrong machine |

**Note the asymmetry.** Confidentiality breaches are bad; **availability loss is unrecoverable**. A design that
trades availability for a marginal confidentiality gain is almost certainly wrong here.

---

## 2. Adversaries, in priority order

| # | Adversary | Capability | Must be defeated? |
|---|---|---|---|
| **A1** | **Thief with the stick** | Has the USB; may know the user; may have their other passwords | **MUST** — the passphrase plus device binding must make the stick alone useless |
| **A2** | **Malware on the host** | Runs as the user; reads files, memory, keystrokes. Cannot read kernel memory it lacks privileges for | **MUST** defeat *offline theft of the vault file*; **CANNOT** defeat a host that watches the passphrase as it is typed. Stated, not hidden |
| **A3** | **Corruption / bad flash** | The stick dies, sector rot, power loss mid-write | **MUST NOT lose data that was previously confirmed written** |
| **A4** | **User error** | Forgotten passphrase, deleted a file, formatted the stick | **MUST** be recoverable by the user's own export |
| **A5** | **Supply chain** | A dependency is compromised | **MUST** keep the dependency set small, pinned, and checked |
| **A6** | **Shoulder surfer / scrollback** | Sees the screen, reads terminal history | **MUST** be addressed at display time |
| **A7** | **Physical hardware attack** | Cold boot, bus sniffing, chip-off | **OUT OF SCOPE** — no software defence is honest here |

---

## 3. The requirement that must not be violated

> **"We cannot afford people losing their passkeys."**
> **"Not having leaks because of a stick defect, or generating a passkey with nowhere to save it."**

Decoded into testable MUSTs:

* **S1 — Atomic writes.** A crash or power loss during a write must leave either the old vault or the new one.
  **Never a half-written vault.** This is the single most likely cause of catastrophic loss.
* **S2 — Corruption detection.** Bit rot must be *detected* and reported, not silently decrypted into garbage.
* **S3 — Explicit recovery.** The user can always export an encrypted backup. The design must make recovery
  possible **without us** — no server, no escrow, no reset.
* **S4 — No silent data loss on upgrade.** A vault written by version *n* must remain readable at *n+1*, or the
  reader must refuse and say so.

---

## 4. Decisions this threat model imposes on the blueprint

These are constraints, not suggestions.

### 4.1 Two independent factors, and the vault must state which ones it used

* **Passphrase** → Argon2id → key **K1**
* **Device binding** → a per-stick value → key **K2**
* Vault key **K = HKDF(K1 ‖ K2)** — neither factor alone yields K

**MUST:** the vault header records which factors were used. A "passphrase-only" vault is a **different security
claim** and must be visibly labelled as such — including in the exported file, so its holder knows it is weaker.

**MUST NOT:** silently fall back from two factors to one. A missing device factor is a refusal, not a
degradation. (This is G3 applied to the vault.)

### 4.2 Device binding must not make recovery impossible

The Founder chose USB-primary + encrypted export. **These pull against each other**: if K requires the device,
an exported file is useless on a new stick — and that is precisely "losing your passkeys."

**Resolution — the export is a separate construction, and this is the crux of the design:**

| Artifact | Bound to | Purpose |
|---|---|---|
| **Vault** (on the stick) | passphrase **+** device | normal operation |
| **Export** (user-chosen location) | passphrase **only**, with a *higher* Argon2id cost | recovery onto a replacement stick |

**MUST:** the export is created by an explicit user action that **explains the tradeoff** — "this file is
protected by your passphrase alone; anyone holding it and guessing your passphrase gets everything." It is
never created silently.

### 4.3 Argon2id parameters must be measured, not chosen

**MUST:** parameters are selected by a **probe on real hardware**, recorded, and stored in the vault header so
a future reader knows the cost. A number picked from a blog post is not a decision, it is a guess.

**MUST:** the parameters are **upgradeable** — the header records them, and re-keying is possible.

### 4.4 Every write is atomic

**MUST:** write to a temporary file, `fsync`, atomically rename, `fsync` the parent directory. Document the
exact sequence and its limits on each filesystem. **ExFAT and FAT32 — the usual formats on USB sticks — have
weaker rename and fsync guarantees than ext4.** This must be measured, not assumed.

**MUST:** keep the previous good vault until the new one is confirmed.

### 4.5 Constant-time everywhere it matters

**MUST:** passphrase verification and all tag comparisons use constant-time primitives (`subtle`). The project
already treats this as an invariant for comparisons; the vault is where it matters most.

### 4.6 Memory hygiene extends to the vault

**MUST:** the decrypted vault, the derived keys, and every secret pass through `Secret<T>`. Keys are locked
and wiped. The vault is never written to swap, temp files, or logs.

**MUST:** the plaintext vault never leaves the process — display shows one entry, never the whole vault.

### 4.7 The dependency increase must be justified and pinned

Adding ~6 crates to a project with 3 is a **tenfold increase in supply-chain surface.**

**MUST:** every added crate is named, version-pinned, justified, and added to `scripts/shipped-deps.txt` with
its raison d'être. `cargo deny` must be in place **before** the vault ships.

---

## 5. What this threat model does NOT claim

* **A compromised host defeats everything.** If malware watches the keystrokes, it has the passphrase. We
  reduce the window; we do not close it. The README will say so.
* **A lost stick and a lost export means lost data.** No design changes that. The user is told, in advance,
  in the words on the export command.
* **Hardware attacks are out of scope** and will be stated as such.

---

## 6. Findings that must be closed before the blueprint is approved

| # | Finding | State |
|---|---|---|
| B1 | No measured Argon2id parameters exist yet | **Probe required** |
| B2 | Atomic-write guarantees on **exFAT/FAT32** are unmeasured | **Probe required** |
| B3 | The export's weaker binding must be stated in the file itself, not only in docs | **Design requirement** |
| B4 | No vault format version field exists in any design yet | **Design requirement** |
| B5 | `cargo deny` is not yet configured | **Blocker for shipping** |

**Bruce's position: the blueprint may be written, but B1 and B2 must be probed before any format is frozen,
because they change the design.**
