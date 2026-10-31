# Grace — Fourth Review of the Vault Blueprint

**Subject:** `docs/F5_VAULT_BLUEPRINT.md` at `a99c06b`.
**Scope:** confirm S1–S3 closed; find what this revision introduced.
**Verdict: CHANGES REQUIRED — three findings. One is an out-of-memory vector of the very class I closed last
round; one is that a third of the file format does not exist.**

**S1–S3 are closed.** The AAD chain is correct: `body_len` binds into the header AAD, which binds into
`tag_header`, which is the body's AAD. **I traced that chain rather than accepting it.** Moving `export_ack`
inside the header is right, and §4.1 now makes the plaintext boundary a decision rather than an accident.

---

## T1 — The AAD does not cover the nonces. **Non-blocking, must be stated.**

I checked whether the AAD covers every plaintext field. It covers everything **except `nonce_header` and
`nonce_body`**.

**Assessment:** a modified nonce produces a **tag failure**, not a successful decryption. That is a **denial of
service, not a splice**, and an attacker with write access to the stick can already delete the file. **Acceptable**
— but the blueprint must **say it accepted that**, because a reader cannot tell whether the omission was
deliberate.

**Required change:** one sentence: *"the AEAD nonces are not in the AAD; modification causes an authentication
failure (denial of service), which the adversary can achieve by deleting the file anyway. Accepted."*

## T2 — One key encrypts two ciphertexts. **Non-blocking, must be stated.**

`K` encrypts both the header and the body, with two independently random 96-bit nonces. Two random nonces under
one key collide with probability ≈2⁻⁹⁶ per pair; the vault is rewritten perhaps tens of thousands of times.

**Assessment: safe.** But the standard mitigation — **`K_header = HKDF(K, "header")`, `K_body = HKDF(K, "body")`** —
costs two hash calls and makes a nonce collision across the two contexts *harmless* rather than fatal.

**Required change:** either adopt per-purpose keys (my preference — it costs nothing and removes a class of
reasoning), or state why one key is safe with the collision bound written down. **"It is fine because nonces are
random" is not sufficient for a file format that will be implemented by someone else.**

## T3 — The body format does not exist. **Blocking.**

**Planted:** §4 says the file is `ciphertext(header) ‖ tag_header ‖ ciphertext(body) ‖ tag_body`.

**The blueprint never says what the body's plaintext is.** Not the entry encoding, not the length framing, not
how `list` and `get` locate an entry.

**This is not a spec — it is a placeholder.** An implementer cannot write `list` or `get` from this document; they
would **improvise a format**, and the improvisation would be the real specification, reviewed by nobody.

**It also invalidates a claim I made earlier:** S1's splice test asserts that a spliced file *fails*. With no body
format, that test cannot be written either.

**Required change:** specify the body plaintext completely:

* framing (length-prefixed entries, or a map with a declared count);
* the byte layout of one entry (name, secret, timestamps);
* **whether inner lengths are inside the ciphertext** — they are, and therefore authenticated, which is what makes
  the framing safe; say so;
* validation rules: what the reader does with a count that disagrees with the bytes present.

**And a test:** a body whose inner count exceeds the bytes present is rejected, not partially parsed.

## T4 — `body_len` is an out-of-memory vector. **Blocking.**

**Planted:** `body_len u64` is in the header, and the header is *authenticated* — but **authentication requires
the key, and allocation happens before decryption**.

A file claiming `body_len = 2⁶³` with a well-formed plaintext header makes the reader **attempt a gigantic
allocation before any tag is checked**. That is the same class as **G3**, which this blueprint already closed for
`m` and `t` — and the pattern was **not applied here.**

**Required change:** before allocating anything for the body:

1. **`body_len` must equal the actual remaining file size minus the trailing tag.** The file size is a fact the
   reader has without any key.
2. **`body_len` must not exceed a compiled-in maximum** for this build, for the same reason `m` is bounded.
3. A mismatch or an excess is `CorruptHeader` — **before** allocation, with the same "before" discipline as the
   KDF bounds.

**Test:** a file whose `body_len` disagrees with its actual size, and a file whose `body_len` exceeds the maximum,
are both rejected **with no allocation of the claimed size**.

---

## What held up

* **The AAD chain.** `body_len` → header AAD → `tag_header` → body AAD is correctly composed. I traced it; it
  binds.
* **§4.1's plaintext/encrypted table.** Explaining *why* `factor_flags` is plaintext ("an attacker learns it by
  trying") is the right level of rigour, and it is the sentence that makes `export_ack`'s move legible.
* **Test 23 asserting `export_ack` is unreadable in the first 64 bytes** — proving the leak is gone, not merely
  that the field moved.
* **Test 24 asserting an absence** over the whole output.

---

## Verdict

| # | Change | Blocking |
|---|---|---|
| **T1** | State that nonces are deliberately outside the AAD (DoS, accepted) | no |
| **T2** | Per-purpose keys `K_header`/`K_body`, or write down the collision bound | no |
| **T3** | **Specify the body format completely** — framing, entry layout, validation | **yes** |
| **T4** | **`body_len` checked against actual file size and a maximum, before allocation** | **yes** |

**T4 is mine as much as Ada's**: I closed the allocation ceiling for the KDF and did not ask whether the *body*
had the same problem. The pattern was in the document; I did not apply it to the field that is literally about
size.

**T3 is the reason this review exists.** Without it, the format half-specified here gets finished by whoever
writes the code, and the real specification becomes a side effect of an implementation. That is how the vault's
format would come to be documented by a code review that never happened.

**No implementation until T3 and T4 are closed.**
