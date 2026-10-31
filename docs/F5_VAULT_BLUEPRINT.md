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
`export`, **`import`**, **`preflight`**. **`get` returns `Secret<Vec<u8>>`** — the plaintext never crosses the API
as `String`.

* **`import` (R2, Grace's re-review):** reads an export, prompts for its passphrase, **re-keys onto the current
  device**, and writes a normal vault through the **same corrected write sequence**. Without this, an export is a
  file written once and read by nobody — the appearance of a backup, which is worse than none.
* **`preflight` (R1):** reports, for the current directory, the binding level and **whether a vault may be
  created here**. No vault, no passphrase, no commitment. It exists so a user whose stick is enclosure-bound
  learns this **before** trying, and the refusal message points to it.

  **S3 — information boundary:** `preflight` and `status` **never print `uuid` or `serial`.** The device identity
  is one of the two inputs to `device_secret`; a stranger who picks up the stick must get no free readout of it.
  They print only the **binding level** and the **capability verdict**, and a test asserts those strings are
  **absent** from the output.

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
body_len     u64
```
followed by: `ciphertext(header) || tag_header`, then `ciphertext(body) || tag_body`.

**Inside the encrypted header** (not visible to a stranger holding the file): `export_ack` (S2), the entry
table, timestamps, and the parameter claims.

### 4.0 The body plaintext — the full format (T3, Grace's fourth review)

**The earlier draft specified the body's ciphertext and never its plaintext**, leaving `list`, `get` and the
splice test unimplementable and inviting an implementer to improvise the real format. Specified:

```
body_plaintext :=
    entry_count : u32                      // number of entries that follow
    entry*                                          // exactly entry_count of them

entry :=
    name_len    : u16                      // 1..=255
    name        : [u8; name_len]           // UTF-8, validated
    kind        : u8                       // 0 = Secret, 1 = Passphrase
    created     : u64                      // unix seconds
    updated     : u64
    secret_len  : u32                      // 1..=65536
    secret      : [u8; secret_len]
```

**Validation rules the reader MUST apply, in order:**

1. `entry_count` is read and **must not exceed `MAX_ENTRIES`** (compiled in) — checked **before** any allocation,
   for the same reason as T4.
2. Each `name_len` and `secret_len` is bounded by its type's maximum **and** by the bytes remaining; a length
   that exceeds the remainder is `CorruptBody`, **never a partial parse**.
3. The body must be **exactly consumed** — trailing bytes after `entry_count` entries are `CorruptBody`. A
   format that tolerates trailing data cannot detect appended garbage.
4. Names must be **unique**; a duplicate is `CorruptBody`.

**Why this is safe:** every inner length lives **inside the ciphertext**, so it is covered by `tag_body` and
cannot be altered without detection. The framing is authenticated *because* the AEAD is applied to the whole
body, not per entry.

**Test:** a body whose inner `entry_count` exceeds the bytes present is rejected, not partially parsed.

### 4.1 Which fields are plaintext, and why (S2, Grace's third review)

| Field | Plaintext? | Why |
|---|---|---|
| `magic`, `version` | yes | required to identify the file before any key exists |
| `kdf`, `m`, `t`, `p`, `salt` | yes | the reader needs them to derive the key; they cannot be secret |
| `nonce_header`, `nonce_body` | yes | AEAD nonces; hiding them is meaningless |
| `factor_flags` | yes | inherent in the file — an attacker learns it by trying to open without a device factor. Stated deliberately, not by oversight |
| **`export_ack`** | **NO — encrypted** | it announced *"weak passphrase accepted."* That is **target selection** for an attacker. It must remain recorded and undeniable — inside the header, not on the cover |

### 4.2 AEAD binding — `ciphertext(body)` is bound to `ciphertext(header)` (S1)

**Without AAD, the two ciphertexts are independent and can be spliced**: a header from vault A with a body from
vault B both decrypt, producing a file whose metadata says one thing and whose contents are another.

**MUST — every AEAD call carries AAD:**

| Ciphertext | AAD |
|---|---|
| header | `magic ‖ version ‖ kdf ‖ m ‖ t ‖ p ‖ salt ‖ factor_flags ‖ body_len` — everything outside the ciphertext, so tampering with any header field invalidates `tag_header` |
| body | **`tag_header`** — the authenticated header tag, so a body from any other file cannot be attached |

**T1 — the AEAD nonces are deliberately NOT in the AAD.** Modifying `nonce_header` or `nonce_body` causes an
**authentication failure**, not a successful decryption — a denial of service, which an adversary with write
access to the stick could achieve by deleting the file anyway. **Accepted, and stated rather than omitted**,
because a reader cannot otherwise tell whether the gap was deliberate.

**Test (S1):** construct a spliced file — header of A, body of B — and assert it **fails** with `CorruptBody`.
**Every other test in this blueprint opens one file against itself; this is the only one that uses two.**

**Rules the reader MUST enforce, in this order, before any allocation:**

1. `magic` and `version` — else `UnsupportedVersion` / `CorruptHeader`.
2. **Bounds check `m_kib` and `t` against the compiled-in floor AND ceiling** → `BelowFloor` /
   `AboveCeiling` (G1, G3). **This happens before allocating a single byte.**
3. `factor_flags` — if `device` is not set, this is an export and must be labelled as such.
4. Decrypt the header; a tag failure is `WrongPassphrase` or `DeviceMismatch`, **never** distinguished to
   the user (see §8).
5. Decrypt the body; `CorruptBody` if it fails.

**T4 (Grace's fourth review) — `body_len` is bounded BEFORE ANY ALLOCATION.** `body_len` is authenticated, **but
authentication requires the key and allocation happens before decryption.** A file claiming `body_len = 2⁶³` with
a well-formed header would make the reader attempt a gigantic allocation before checking any tag — **the same
class as G3, which this blueprint already closed for `m` and `t`, and the pattern was not applied here.**

**MUST, in this order, before allocating for the body:**

1. **`body_len` must equal `file_size − plaintext_header_size − tag_header_size − tag_body_size`.** The file size
   is a fact the reader has with no key at all.
2. **`body_len` must not exceed a compiled-in maximum** for this build, for the same reason `m` is bounded.
3. A mismatch or an excess is `CorruptHeader`, **before** allocation.

**Test:** a file whose `body_len` disagrees with its actual size, and one whose `body_len` exceeds the maximum,
are both rejected **with no allocation of the claimed size**.

**The two refusals are deliberately different types** so a downgrade cannot hide behind a capability message
(Grace's G3).

## 5. Key derivation

```
K1        = Argon2id(passphrase, salt, m, t, p)                    // 32 bytes
kdf_salt  = HKDF-SHA256(K1, b"", "tokengen-vault-kdf-salt")       // 32 bytes — B4
          // EMPTY salt is correct: RFC 5869 permits it because K1 is ALREADY a uniform 32-byte
          // value — the salt's job of separating weak inputs was done by Argon2. Deriving two
          // independent values from K1 is exactly what HKDF is for.
K2        = HKDF-SHA256(device_secret, kdf_salt, "tokengen-vault-device")
K         = HKDF-SHA256(K1 ‖ K2, kdf_salt, "tokengen-vault-key")  // master, never used directly
K_header  = HKDF-SHA256(K, kdf_salt, "tokengen-vault-header")     // T2: per-purpose keys
K_body    = HKDF-SHA256(K, kdf_salt, "tokengen-vault-body")

// T2 (Grace's fourth review): the header and body are encrypted under DIFFERENT keys. With one
// key, a nonce collision ACROSS the two contexts would be fatal; with separate keys it cannot
// happen by construction. Costs two hash calls and removes an entire class of reasoning.
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

**Cost, stated (R3, Grace's re-review):** copying the current vault doubles write volume per mutation — a 1 MiB
vault makes every `put` a 2 MiB write on a slow stick. **Accepted**, because the alternative (a generation-pair
`vault.1`/`vault.2` rotated alternately) avoids the copy but complicates recovery-path selection. Recorded so the
trade is visible if it ever matters.

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

## 8a. `import` — R2

* Reads an export, verifies `factor_flags` says **no device factor**, prompts for the passphrase.
* **Re-keys onto the CURRENT device**: the imported vault becomes a normal two-factor vault bound to the stick
  it now lives on. It does **not** remain passphrase-only.
* Writes through the **same corrected sequence** as any mutation — importing must not be the one code path that
  can lose data.
* **If the target already holds a vault, `import` REFUSES** unless explicitly given `--replace` or `--merge`.
  It never silently overwrites.
* If the current device is **enclosure-bound**, `import` refuses for the same reason `create` does (B1) — the
  user cannot recover *onto* a weaker drive than the vault demands.
* **Test:** export → import on a second stick → every entry byte-identical; the new vault binds to the **new**
  device; the original stick cannot open the new vault.

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
18. **R1 preflight:** reports refusal for an enclosure-bound drive **without creating anything**, and the
    refusal message names the preflight command.
19. **R2 import:** export from stick A → import on stick B → all entries byte-identical, the new vault binds to
    B, and **A cannot open the imported vault**.
20. **R2 safety:** `import` onto a directory that already holds a vault **refuses** without an explicit flag.
21. **R2 container:** importing is refused when the target drive is enclosure-bound (B1 applied to recovery).
22. **S1 splice:** header of vault A + body of vault B → **fails with `CorruptBody`**. The only test that uses
    two files; without it, "we use AES-GCM" is not a specification.
23. **S2 leak:** `export_ack` is **not readable** in the first 64 bytes of the file, and after opening an
    acknowledged export the value **is** 1. Proves it is recorded *and* hidden.
24. **S3 absence:** `preflight` and `status` output contains **neither the device UUID nor the serial**, asserted
    as an absence over the whole output.
25. **T2 keys:** the header and body are encrypted under **different** keys — decryption of one with the other's
    key fails.
26. **T3 framing:** a body with `entry_count` larger than the bytes present is rejected; trailing bytes after the
    last entry are rejected; a duplicate name is rejected.
27. **T4 before allocation:** `body_len` disagreeing with the file size, and `body_len` above the maximum, are
    both rejected **before** allocating, asserted by the same no-large-allocation check as test 3.

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
