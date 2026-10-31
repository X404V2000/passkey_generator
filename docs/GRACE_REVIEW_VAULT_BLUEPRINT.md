# Grace — Review of the Vault Blueprint

**Subject:** `docs/F5_VAULT_BLUEPRINT.md`, anchor `c85466b`.
**Method:** attacked the blueprint as a specification, before any code exists — which is the point of reviewing it
now rather than after.
**Verdict: CHANGES REQUIRED. Four findings. One is data loss in the write sequence; one is a security
downgrade inherited silently from F3.5.**

---

## B1 — The vault silently inherits F3.5's enclosure-level weakness. **Blocking.**

**Planted:** §5 derives `device_secret` from `DeviceIdentity` as **`uuid ‖ serial`**.

**Problem.** AM-008 established that on a drive with **no disk serial** the guard binds to the **USB
enclosure's** serial, and records that fact as `SerialSource::Enclosure`. The blueprint ignores `serial_source`
entirely.

**The attack:** a vault created on an enclosure-bound stick derives `device_secret` from the **enclosure**. Slug
**a different disk** into the same enclosure → **identical `device_secret`** → combined with the passphrase, the
vault opens. The "device factor" is then a property of *a piece of plastic the user may own two of*, not of the
medium.

F3.5 documented this honestly as its L3/W7 limitation and made the user **aware** of it. **The vault would
inherit the same weakening and not mention it**, which is a strictly worse position than F3.5's.

**Required change:** one of —

1. **Refuse to create a vault on an `Enclosure`-bound device**, with a message naming the reason; or
2. **Record `serial_source` in the vault header** and surface it on every unlock ("this vault is bound to the
   enclosure, not the disk") — inheriting the limitation *visibly*.

**My recommendation: (1).** A vault is the artifact users must not lose and must not leak. For that artifact,
losing the disk-binding strength silently is not acceptable, and a two-drive user on generic sticks is a normal
case, not an edge case. (2) is acceptable only if the header also marks the vault as **restricted**.

**Either way this is a blueprint change, not an implementation detail.**

---

## B2 — The write sequence is wrong, and the first write loses data. **Blocking.**

**Planted:** §7.

```
3. rename vault.tmp -> vault.prev        (keep last good)
```

**Problem 1 — the first write destroys `vault.prev` with an empty file.** On a brand-new vault, `vault.tmp` has
not been written at step 3. Renaming it produces an **empty `vault.prev`**. If step 7 then fails, the state is:
*no vault*, and a `vault.prev` that is empty and unopenable. **First-write data loss.**

**Problem 2 — a stale `vault.tmp` from a crash can overwrite a good `vault.prev`.** The rename is
unconditional; nothing checks that the source is a complete, authenticated vault.

**Required change — the ordering must be: copy the CURRENT good vault to `prev`, never rename an unwritten
temp into it.**

```
1. if vault exists:  copy  vault -> vault.prev.new ; fsync ; rename -> vault.prev ; fsync dir
2. if vault absent:  skip (there is nothing to preserve yet) — do NOT create an empty prev
3. write  vault.tmp  (full encrypted image)
4. fsync  vault.tmp
5. fsync  parent dir
6. rename vault.tmp -> vault
7. fsync  parent dir
8. delete any stale vault.tmp
```

**And a test that proves it:** kill the process at **each** step boundary in turn, reopen, and assert a
**complete, decryptable** vault exists every time — including from a state with no prior vault. A test that
kills at only one point would have missed this.

---

## B3 — Nonce generation on failure is unspecified. **Blocking (small).**

**Planted:** §4 records `nonce_body` as "fresh per write", and §2 names `getrandom` as the source.

**Problem.** The blueprint does not say what happens when `getrandom` **fails mid-write**. There is a natural,
wrong implementation: retry with the previous buffer, or "fall back" to a counter seeded at startup. **A reused
GCM nonce is a catastrophic break** — it leaks the XOR of plaintexts and, with a known plaintext, enables
forgery.

The distance between the failure and the consequence is exactly what makes it easy to miss in review.

**Required change, stated in the blueprint:** a `getrandom` failure during any vault operation is an
**immediate abort of the whole operation**, never a retry and never a fallback. The temp file is deleted and the
previous vault is left untouched. One sentence, but it must be there, and there must be a test that injects
`getrandom` failure and asserts **no write occurs**.

---

## B4 — The same salt serves two different KDFs. **Non-blocking, but must be stated.**

**Planted:** §5 uses `salt` as input to **Argon2id** *and* to two **HKDF** invocations.

**Assessment:** this is very likely safe — the two constructions are structurally different and the HKDF calls
carry distinct `info` strings. **But "very likely safe" is not a review answer**, and the blueprint currently
says nothing about why it is acceptable.

**Required change:** either (a) derive a distinct `hkdf_salt` from the Argon2 output, making the domains
obviously separate; or (b) state explicitly that `salt` is reused and why that is sound. **I prefer (a)** — it
costs one line and removes the question entirely.

---

## What held up

* **Per-dimension floor** with three distinguishable refusals — correctly carried through from my earlier review.
* **The upper bound refused before allocation** — correctly placed.
* **`WrongPassphrase` and `DeviceMismatch` producing identical user-facing text** — the right call; it closes an
  oracle.
* **Export refusing weak passphrases with a recorded acknowledgement** — the acknowledgement in the header is
  the important part; it means a later reader cannot believe it was strong.
* **`get` returning `Secret<Vec<u8>>`, never `String`** — right.
* **Test 3** ("fails before allocating; assert no large allocation occurs") — unusually good; most blueprints
  would stop at "it is rejected".

---

## Verdict

**CHANGES REQUIRED.**

| # | Change | Blocking |
|---|---|---|
| **B1** | Enclosure-bound devices: refuse to create a vault, or record and surface the restriction | **yes** |
| **B2** | Write sequence must copy the current vault to `prev`; never rename an unwritten temp; never create an empty `prev` | **yes** |
| **B3** | `getrandom` failure aborts the whole operation — no retry, no fallback — with a test | **yes** |
| **B4** | Separate the HKDF salt from the Argon2 salt (preferred), or justify the reuse | no, but must be addressed |

**B2 is the one I would have expected to reach production.** It is a correct-looking sequence, it uses the right
primitives, and it loses data on the very first write. That is exactly the class of defect that only exists
until someone traces the failure windows — which is why the blueprint is reviewed before it is built.

**No implementation until B1–B3 are closed.**
