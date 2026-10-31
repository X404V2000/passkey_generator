# Grace — Third Review of the Vault Blueprint

**Subject:** `docs/F5_VAULT_BLUEPRINT.md` at `974934a`.
**Scope:** confirm R1–R4 closed; find what *this* revision introduced.
**Verdict: CHANGES REQUIRED — three findings. One is a splice attack; one is a hint to attackers; one is a
missing constraint.**

**R1–R4 are closed.** `import` and `preflight` exist with real semantics; the copy cost and the empty HKDF salt
are both explained. **The revisions introduced three new problems, and two of them are in the file format.**

---

## Part 1 — R1–R4

| # | Finding | State |
|---|---|---|
| R1 | B1's refusal had no escape hatch | **CLOSED** — `preflight` exists; refusal points to it; test 18 |
| R2 | Export could not be restored | **CLOSED** — `import` added, re-keys to the new device, same write sequence, refuses non-empty target; tests 19–21 |
| R3 | Copy-to-prev cost unstated | **CLOSED** |
| R4 | Empty HKDF salt unexplained | **CLOSED** |

**`import` is the right shape.** Re-keying onto the current device, and refusing an enclosure-bound target, are
both correct — and refusing a non-empty target without a flag is the decision I would have asked for.

---

## S1 — The two ciphertexts are not bound together. **Blocking.**

**Planted:** §4 has `nonce_header` guarding `ciphertext(header)` and `nonce_body` guarding `ciphertext(body)`.

**The blueprint specifies no AAD for either.** Two independent AEAD ciphertexts, no binding between them.

**The attack.** An attacker with write access to the stick (A3's adversary, and anyone who copies the file) can
**splice**:

* take the header and `nonce_header` from vault **A**,
* take the body and `nonce_body` from vault **B**.

**Both halves decrypt and authenticate individually.** Nothing fails. The result is a vault whose *metadata*
says one thing and whose *contents* are another:

* entry count, timestamps and **parameter claims** come from A,
* the actual secrets come from B.

An attacker who holds two vaults — their own and the victim's — can present a well-formed, verifying file whose
body was substituted. The attacker does not learn the victim's passphrase, but they can **control what an
importing or listing user sees**, and can **downgrade the header claims** while the body remains valid.

**Required change:** both ciphertexts carry **AAD**, and the body's AAD **binds it to the header**.

* Header AAD: `magic ‖ version ‖ kdf ‖ m ‖ t ‖ p ‖ salt ‖ factor_flags ‖ body_len` (everything outside the
  ciphertext, so tampering with any of it invalidates the header tag).
* Body AAD: **the authenticated header tag** (`tag_header`), so a body from another file cannot be attached.

**Test:** construct a spliced file (header of A, body of B) and assert it **fails to open** with `CorruptBody`.
A blueprint that does not name this test has not specified AEAD usage — it has specified "we call AES-GCM".

---

## S2 — `export_ack` in the plaintext header is a hint to an attacker. **Blocking.**

**Planted:** `export_ack u8 — 0 = normal, 1 = "weak passphrase acknowledged"` is in the **plaintext** header,
readable by anyone holding the file.

**Problem.** It tells an attacker, in the clear: **"this export was created with a passphrase the user was warned
about and accepted anyway."** That is a **target-selection signal** — precisely the file worth spending a
cracking rig on.

The acknowledgment exists so *a future reader of the file cannot believe it was strong*. That purpose is served
by putting it **inside the authenticated header**, where it is readable by the tool (after decryption) and
**not** by a stranger with the file.

**Required change:** move `export_ack` into the encrypted header. It remains recorded and remains
un-deniable — it simply stops being an advertisement.

**Same question applies to `factor_flags`.** That a file is passphrase-only is **inherent in the file** (an
attacker can tell by trying to open it without a device factor), so leaving it in plaintext is acceptable — but
the blueprint should **say so explicitly** rather than leave the reader to infer which fields are plaintext
deliberately and which by oversight.

---

## S3 — `preflight` has no stated information boundary. **Blocking (small).**

**Planted:** `preflight` reports the binding level and whether a vault may be created. **It has no stated rule
about what it must NOT print.**

The existing `status` command happens to print only the level, never the UUID or serial — but that is
**incidental to that command**, not a rule carried into the blueprint.

**Problem.** A stranger who picks up the stick can run `preflight`. If it ever prints the serial or filesystem
UUID, they get a free readout of the device identity — which is one of the two inputs to `device_secret`. It does
not open the vault without the passphrase, but it is free reconnaissance that costs nothing to withhold.

**Required change:** state the rule. `preflight` and `status` **never print `uuid` or `serial`** — only the
binding level and the capability verdict. And a test that asserts those strings are absent from output.

---

## What held up

* **`import` refusing a non-empty target** — the single most likely way to lose data through the new feature,
  closed before it was written.
* **`import` refusing an enclosure-bound target** — B1 applied consistently to the recovery path, not only to
  creation. That consistency is exactly what I expected to be missed.
* **Test 19's third assertion** — *"A cannot open the imported vault"* — proves the re-keying actually happened
  rather than only that B can open it. Proving the **negative** is the harder assertion and it is present.
* **R3/R4 addressed as asked**, not argued with.

---

## Verdict

| # | Change | Blocking |
|---|---|---|
| **S1** | AAD on both ciphertexts; body AAD binds to the header tag; splice test | **yes** |
| **S2** | `export_ack` moves inside the encrypted header; state which fields are deliberately plaintext | **yes** |
| **S3** | `preflight`/`status` never print `uuid`/`serial`; test the absence | **yes** |

**I found nothing wrong with the reasoning of R1–R4.** Every new problem is in the **file format and the
observable surface**, which is where a blueprint stops being prose and becomes a specification that someone
implements literally.

**S1 is the one I would lose sleep over.** Two ciphertexts with no binding is a correct-looking use of AES-GCM
that permits a body substitution. It is not caught by any test in the current list, because every current test
tests one file against itself. **A specification must be attacked with two files, not one.**
