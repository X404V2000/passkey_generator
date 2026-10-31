# Blueprint — Vault: generate, store, manage, protect, display

**Feature:** Vault. **Author:** Ada, Chief Architect. **Status:** draft for review, not frozen.
**Constraints:** `docs/VAULT_THREAT_MODEL.md` (Bruce, amended after Grace's review) and T-0004 V1–V6.
**Anchor:** `c85466b`.

> **Production code does not exist for this feature.** Implementation begins only after Grace accepts this
> blueprint. Nothing here is measured unless it says so.

---

## 1. Purpose and non-goals

**Purpose.** Turn TokenGen from a secret generator into a vault: secrets are stored encrypted on a removable
drive, bound to that drive and to a passphrase, and can be listed, revealed, renamed, rotated and deleted.

**Non-goals, stated so they cannot creep in:**

* **No network, ever** (G1). No sync, no cloud, no telemetry (G10).
* **No WebAuthn/CBOR credentials.** Separate feature; the name overpromises and the README says so.
* **No Windows/macOS** until a device backend exists.
* **No browser integration**, no auto-fill, no extension.
* **Not a key store for arbitrary crypto operations.** It stores secrets; it does not sign with them.

## 2. What already exists that this builds on

| Capability | Where | Used for |
|---|---|---|
| `SessionGuard::capture` / `check` / `identity` | `src/session.rs` | device binding factor; swap detection |
| `DeviceIdentity { uuid, serial, serial_source }` | `src/session.rs` | the per-stick value that feeds K2 |
| `Secret<T>` (`Zeroizing`, not `Clone`/`Debug`) | `src/zeroize.rs` | every plaintext and key |
| `generate_key_os` / `Charset` | `src/generator.rs` | generating new entries inside the vault |
| `getrandom` | dep | **all** salts and nonces |
| fail-closed `SessionError` / `GeneratorError` | — | refusal paths |

**Not available and must be added:** `argon2`, `aes-gcm` (or `chacha20poly1305`), `hkdf`, `sha2`, `subtle`.

## 3. Public API (complete — every type named here exists in the design)

```rust
// src/vault/mod.rs
pub struct Vault;                       // no public fields; constructed only by unlock/open
pub struct VaultEntry {                 // metadata only, never the secret
    pub name: String,
    pub created: u64,                   // unix seconds
    pub updated: u64,
    pub kind: EntryKind,
}
pub enum EntryKind { Secret, Passphrase }

pub enum VaultError {
    NotOnRemovableDevice,               // reuses SessionError's meaning
    NotDiskBound,                       // B1: enclosure-level drive — vault creation refused
    DeviceMismatch,                     // this vault belongs to a different stick
    WrongPassphrase,                    // authentication failed; NEVER says which field
    BelowFloor { m: u32, t: u32 },      // G1 — possible downgrade
    AboveCeiling { m: u32, t: u32 },    // G3 — capability limit, NOT a security refusal
    CorruptHeader,                      // damaged, distinct from the two above
    CorruptBody,                        // authenticated decrypt failed on the body
    Io,
    UnsupportedVersion(u16),
}
```

**API-completeness check** (run before review, and again in CI):

```sh
for t in Vault VaultEntry EntryKind VaultError; do grep -c "struct $t\|enum $t" src/vault/mod.rs; done
```
Any zero is a defect in this document.

**Operations:** `create`, `unlock`, `list`, `get` (reveal one), `put`, `rename`, `delete`, `rotate`,
`export`. **`get` returns `Secret<Vec<u8>>`** — the plaintext never crosses the API as `String`.

## 4. File format — versioned, self-describing, bounds-checked before use

```
magic        b"TKGVAULT"             8 bytes
version      u16                     format version; unknown => UnsupportedVersion
kdf          u8                      1 = Argon2id (only value defined)
m_kib        u32                     memory
t            u32                     iterations
p            u32                     parallelism
salt         [u8; 32]                from getrandom
nonce_header [u8; 12]                AES-256-GCM nonce for the header
nonce_body   [u8; 12]                fresh per write
factor_flags u8                      bit0 = passphrase, bit1 = device
export_ack   u8                      0 = normal, 1 = "weak passphrase acknowledged"
body_len     u64
```
followed by: `ciphertext(header) || tag`, then `ciphertext(body) || tag`.

**Rules the reader MUST enforce, in this order, before any allocation:**

1. `magic` and `version` — else `UnsupportedVersion` / `CorruptHeader`.
2. **Bounds check `m_kib` and `t` against the compiled-in floor AND ceiling** → `BelowFloor` /
   `AboveCeiling` (G1, G3). **This happens before allocating a single byte.**
3. `factor_flags` — if `device` is not set, this is an export and must be labelled as such.
4. Decrypt the header; a tag failure is `WrongPassphrase` or `DeviceMismatch`, **never** distinguished to
   the user (see §8).
5. Decrypt the body; `CorruptBody` if it fails.

**The two refusals are deliberately different types** so a downgrade cannot hide behind a capability message
(Grace's G3).

## 5. Key derivation

```
K1        = Argon2id(passphrase, salt, m, t, p)                    // 32 bytes
kdf_salt  = HKDF-SHA256(K1, b"", "tokengen-vault-kdf-salt")       // 32 bytes — B4
K2        = HKDF-SHA256(device_secret, kdf_salt, "tokengen-vault-device")
K         = HKDF-SHA256(K1 ‖ K2, kdf_salt, "tokengen-vault-key")  // vault key, 32 bytes
```

* **`device_secret`** is derived from the bound `DeviceIdentity` (uuid ‖ serial) — **not** from the serial
  alone, so a drive whose fs UUID is rewritten is a different device.
* **B1 (Grace's review): the vault REFUSES to be created when `SerialSource` is `Enclosure`.** On such a drive
  the identity is the *USB enclosure's*, so slugging a different disk into the same enclosure would reproduce
  `device_secret` and open the vault. The session guard accepts that binding and tells the user; a vault must
  not, because it is the artifact users must never lose or leak. `VaultError::NotDiskBound` is a **security**
  refusal, kept distinguishable from the capability refusal (G3). The message names the reason and states the
  alternative: *use a drive that exposes its own serial.*
* **B4 (Grace's review): the HKDF salt is DERIVED, not reused.** Using the Argon2 `salt` directly in HKDF would
  probably be sound, but "probably" is not a review answer; deriving `kdf_salt` from K1 makes the two domains
  obviously separate at the cost of one hash.
* **Two factors are required for a vault.** If `device` is absent from `factor_flags`, the file is an
  **export**, and the CLI must have said so when creating it.
* **No fallback path.** A missing device factor is `DeviceMismatch`, never "continue with K1 only"
  (G3 applied to the vault).

## 6. KDF policy — measured at creation, floored per dimension, bounded above

**At creation:** run a calibration (the same measurement as `tests/argon2_calibration.rs`) to find the largest
`m` whose `t=3` run fits **~1 s** on this machine. Record it.

**Floor (security property, per dimension, NEVER the product — Grace G1):**
`m ≥ 64 MiB` **AND** `t ≥ 3` **AND** `p ≥ 1`. Reject below.

**Ceiling (capability property, G3):** `m ≤ m_max` and `t ≤ t_max`, compiled in from what this build will
allocate. Refuse **before** allocating.

**Export:** target **3 s** on the creating machine, and **record the estimated cost on the reference slow
device** (the 2-core Celeron N4020) in the header comment block, so recovery cost is known before reliance
(Grace G2b).

**Reference measurements** (`probes/vault_kdf_calibration.md`, real hardware):
`64MiB t=3` = 0.375 s · `256MiB t=2` = 1.09 s · `1GiB t=1` = 2.60 s.

## 7. Storage — atomic, corruption-detecting, never silent

**Write sequence (S1), every mutation — CORRECTED for B2 (Grace's review).**

The first draft renamed `vault.tmp → vault.prev` before the temp file existed. On a brand-new vault that
produces an **empty `vault.prev`**, and a subsequent failure leaves no vault and an unopenable backup:
**first-write data loss.** A stale `vault.tmp` from an earlier crash could likewise overwrite a good `prev`.

```
1. if vault exists:
     copy vault -> vault.prev.tmp      (a COPY of the authenticated current vault)
     fsync vault.prev.tmp
     rename vault.prev.tmp -> vault.prev
     fsync parent dir
   else:
     skip — there is nothing to preserve; NEVER create an empty prev
2. write  vault.tmp          (full encrypted image)
3. fsync  vault.tmp
4. fsync  parent dir
5. rename vault.tmp -> vault (atomic)
6. fsync  parent dir
7. remove any stale vault.tmp / vault.prev.tmp
```

**The invariant:** after step 4 the vault is still the old, complete one; after step 6 it is the new, complete
one. **There is no step at which no complete vault exists.**

**Probe B2 measured `ntfs3` supporting steps 5–8** (`fsync` + directory `fsync` + atomic `rename`).
**On a filesystem where any step cannot be confirmed, the vault REFUSES to write** rather than writing and
hoping. This is checked at open, not assumed.

**B3 (Grace's review) — a randomness failure ABORTS the whole operation.** `getrandom` failing during any vault
operation is an immediate abort: **no retry, no fallback, no reuse of a previous buffer, no write.** A reused
AES-GCM nonce leaks the XOR of plaintexts and enables forgery, and the distance between the failure and that
consequence is exactly what makes it easy to miss. Tested by injecting `getrandom` failure and asserting **no
file is created or modified.**

**Corruption detection (S2):** the body is AEAD-authenticated; a mismatch is `CorruptBody` and the CLI offers
`vault.prev`. **Never decrypt garbage and present it as a secret.**

## 8. Failure modes and their messages

| Situation | Exit | Message | Security or capability? |
|---|---|---|---|
| wrong passphrase | 3 | "vault could not be opened" | security |
| wrong device | 3 | "vault could not be opened" | security |
| below floor | 3 | "created with parameters weaker than this build accepts" | **security** |
| above ceiling | 4 | "needs more memory than this build will allocate" | capability |
| corrupt header | 5 | "vault header is damaged" | data |
| corrupt body | 5 | "vault is damaged; last good copy is vault.prev" | data |

**`WrongPassphrase` and `DeviceMismatch` produce the SAME user-facing message** — telling an attacker they have
the right stick but the wrong passphrase is an oracle. The distinction exists in the type for testing and
logging; it must never reach the terminal.

## 9. The export — a different artifact with a different claim

* Bound to the **passphrase only**, by construction.
* **Refuses a weak passphrase** (G2a): below a stated minimum it requires `--i-accept-weak-export-passphrase`,
  and the acknowledgement is **recorded in the header** (`export_ack = 1`), so nobody later believes it was
  strong.
* **Records estimated unlock cost on the reference slow device** (G2b).
* The file's own plaintext header says, in words: *"This file is protected by your passphrase alone."*

## 10. Threat-model obligations

| Threat | Mitigation | Test |
|---|---|---|
| A1 thief with stick | passphrase + device, both required | unlock with correct pass, wrong device → fail |
| A2 malware on host | offline file theft yields nothing without the passphrase; **keystroke capture is not defeated** — stated in README | — |
| A3 corruption | AEAD + `vault.prev` + atomic sequence | kill mid-write, reopen: old vault intact |
| A4 user error | encrypted export | export → import on a second stick |
| A5 supply chain | 5 pinned crates, recorded in `shipped-deps.txt`, `cargo deny` before ship | dependency_check.sh |
| A6 shoulder surf | reveal shows one entry, never the vault; no scrollback by default | — |
| A7 hardware | **out of scope, stated** | — |

## 11. Where the code lives

`src/vault/{mod,format,crypto,store,calibrate}.rs` — all inside the main crate, so `#![forbid(unsafe_code)]`
covers it. **No `unsafe` is expected anywhere in the vault.** If any is needed, it belongs in `tokengen-sys`
behind the existing rule.

New dependencies, **all in the shipped graph**, pinned and recorded:

| Crate | Why | Alternative rejected |
|---|---|---|
| `argon2 0.5.3` | Argon2id. **0.6 requires rustc 1.87; we pin 1.85** (V5) | raising MSRV excludes Debian 13 |
| `aes-gcm` | AEAD body/header | `chacha20poly1305` acceptable; pick one, document |
| `hkdf` + `sha2` | key derivation | — |
| `subtle` | constant-time comparisons | never `==` on tags |

## 12. Tests — every one must fail if the mitigation is removed

1. `m=4GiB t=1` is **rejected** (G1: per-dimension floor, not product).
2. Below-floor vault is rejected with a **security** message; above-ceiling with a **capability** message;
   corrupt with a **damage** message — three distinguishable outcomes.
3. A header claiming `m = 4 GiB` fails **before allocating** (assert no large allocation occurs).
4. Wrong passphrase and wrong device produce **identical** user-facing text.
5. Kill the process between steps 4 and 7 of the write sequence → reopening yields the **previous** vault.
6. Flip one byte in the body → `CorruptBody`, and `vault.prev` is offered.
7. Export with a 4-character passphrase is **refused** without the acknowledgement flag; accepted with it, and
   the header records the acknowledgement.
8. Vault created on machine A opens on machine B (parameters travel in the header).
9. Two drives on one controller (the DEFECT-012 condition) produce **different** `device_secret`s.
10. A vault created with a passphrase **only** (no device factor) is refused by the vault reader.
11. Generated entries inside the vault are distinguishable from each other and from the master salt.
12. `vault.plaintext` never appears in a core dump, a temp file, or a log (F3.6-style behavioural check).
13. **B1:** creating a vault on an `Enclosure`-bound device is refused with `NotDiskBound`, and the message is
    distinguishable from `AboveCeiling`. *(Testable with the mock reader — no hardware needed.)*
14. **B2, the first-write case:** create a vault on an empty directory, kill before step 5, reopen → either a
    complete vault or no vault, **never an empty `prev` and no vault**.
15. **B2, every boundary:** kill at **each** step of the corrected sequence in turn, reopen, and assert a
    complete, decryptable vault exists every time. One kill point would have missed the original defect.
16. **B3:** inject a `getrandom` failure during `put`; assert the operation fails **and the vault file's bytes
    are unchanged** (no write, no partial write).
17. **B4:** two different passphrases with the same `salt` produce different `kdf_salt` (i.e. `kdf_salt` is
    derived from K1, not from `salt` directly).

## 13. Probes and evidence

| Claim | Evidence | Class |
|---|---|---|
| Argon2id cost on real hardware | `probes/vault_kdf_calibration.md` | **measured** |
| `ntfs3` supports atomic rename + dir fsync | same probe, steps 1–4 | **measured** |
| Weak export passphrases die in minutes | Grace's review G2a, computed | **reasoned** — needs a real crack test? Not required |
| FAT32/exFAT atomicity | **NOT MEASURED** | **stated limitation** |

## 14. Open questions for review

1. **`aes-gcm` or `chacha20poly1305`?** Both fine; AES-GCM has hardware acceleration, ChaCha is constant-time
   in software. **Recommendation:** `chacha20poly1305` — no timing dependence on the CPU, and the vault is not
   throughput-bound.
2. **Reveal timeout** — how long a secret stays on screen. Recommend: never automatic; require a keypress to
   clear, and never write to scrollback.
3. **`vault.prev` retention** — one previous copy, or none? Recommend one.

## 15. Freeze criteria

Not freezable until: all 12 tests pass and **fail when the mitigation is removed**; `cargo deny` configured;
B2 re-probed on every filesystem we claim to support; Grace has verified; Bruce has re-reviewed the format
against the threat model.

**This blueprint is a draft. Grace reviews it before any implementation.**
