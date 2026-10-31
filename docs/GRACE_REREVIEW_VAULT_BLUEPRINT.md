# Grace — Re-review of the Revised Vault Blueprint

**Subject:** `docs/F5_VAULT_BLUEPRINT.md` as revised at `46770b7`.
**Scope:** confirm B1–B4 are genuinely closed, then look for what the *revisions introduced*.
**Verdict: CHANGES REQUIRED — two new findings, both consequences of the fixes themselves.**

---

## Part 1 — Are the four closed?

### B2 — closed, and I traced it rather than reading it

I walked **every crash point** of the corrected sequence:

| Crash point | State left behind | Result |
|---|---|---|
| after copy → `prev.tmp`, before rename | vault, old prev, new copy | recoverable |
| after rename → `prev` | vault, prev (identical to old) | recoverable |
| **mid-copy** (partial `prev.tmp`) | vault, old prev, partial temp | recoverable |
| after write tmp, before fsync | vault, old prev, partial tmp | recoverable |
| after fsync, before rename | vault, old prev, complete tmp | recoverable |
| after rename tmp → vault | new vault, old prev | recoverable |
| **first write**, before commit | nothing | **no vault — but nothing was ever committed** |

**The last row is not data loss. It is a failed creation**, and it is acceptable **provided the API reports it**
rather than returning success. The blueprint's claim — *"no step exists at which no complete vault exists"* —
holds, because a first write has no vault to lose.

**B2: CLOSED.**

### B1 — closed, but see R1 below

§5 now refuses `SerialSource::Enclosure` and `VaultError::NotDiskBound` exists as a distinct security refusal.
The change is real. **Its consequence is R1.**

### B3 — closed

`getrandom` failure aborts the whole operation with no write, and test 16 asserts the file is byte-unchanged.
That is the right test — it proves the *absence* of a write, not merely the presence of an error.

### B4 — closed, soundly, but the reasoning is missing

`kdf_salt = HKDF(K1, b"", info)`. HKDF with an empty salt is permitted by RFC 5869 **because K1 is already a
uniform 32-byte value** — the salt's job (separating weak inputs) has already been done by Argon2. Deriving two
independent values from K1 is exactly what HKDF is for.

**Sound. But the reasoning is not in the document**, and a future reader will ask why the salt is empty.
**Add one sentence.**

---

## R1 — B1 creates a dead end for some users. **Blocking.**

**Planted:** the vault refuses to be *created* on an enclosure-bound drive.

**Problem.** The export is the **recovery** mechanism. **Recovery requires a vault to have existed.** A user
whose only stick is enclosure-bound — including the maintainer's own 125 GB drive — cannot create a vault, so
cannot create an export, so has **no path to a vault at all**.

The refusal message says *"use a drive that exposes its own serial."* **A user cannot tell which sticks those
are before buying one**, and the tool gives them no way to check without first attempting — and failing — a
vault creation.

**This is a usability dead end created by a security fix.** The security decision is right; the escape hatch is
missing.

**Required change — a preflight that answers the question before commitment:**

* `tokengen vault status` (or equivalent) reports, for the current drive: **binding level**, and explicitly
  whether **a vault may be created here**. No vault, no passphrase, no commitment.
* The refusal message tells the user **that they can check a drive this way**, so the dead end has a signpost.

**And a second obligation:** the refusal must be **testable against a real enclosure-bound drive**, which the
maintainer has. A mock can prove the branch; only hardware proves the message reaches a user who needs it.

**R1 is blocking because "you cannot start" is a worse failure than "you started and were warned" — and the
Founder's stated requirement is that users must not lose their passkeys.** A user who can never create a vault
has nothing to lose, but also nothing to use.

---

## R2 — The export cannot be restored. **Blocking, and this is the serious one.**

**Planted:** the operations are `create, unlock, list, get, put, rename, delete, rotate, export`.

**There is no `import`.**

An export exists that **nothing can open back into a vault.** The threat model's A4 mitigation row says
*"encrypted export → export → import on a second stick"* — the blueprint implements **half of the mitigation**.

**Consequence:** every claim that the user does not lose their passkeys **rests on a mechanism that does not
exist.** The export is a file that, today, is written once and read by nobody. That is worse than having no
export, because it creates the belief of a backup.

**Required change:**

* Add **`import`** to the API: read an export, prompt for its passphrase, re-key onto **the current device**, and
  write a normal vault — **through the same corrected write sequence**, so importing cannot lose data either.
* Add the test: **export → import on a second stick → every entry is byte-identical, and the imported vault
  binds to the NEW device** (not the original).
* State what `import` does when the target already has a vault: **refuse**, unless explicitly told to merge or
  replace — never silently overwrite.

**This is the single most important finding in this review.** Without it the blueprint builds the appearance of
recovery, which is the failure the Founder named: *"generating a passkey with nowhere to save it"* has a
sibling — *"offering a backup that cannot be restored."*

---

## R3 — The copy-to-prev cost is unstated. **Non-blocking.**

Copying the current vault on every mutation doubles write volume. On a slow USB stick, a 1 MiB vault makes every
`put` a 2 MiB write. **Not a correctness defect**, but the blueprint presents the sequence as free.

**Required change:** state the cost, and state the alternative considered (link/copy-on-write, or a
generation-numbered pair `vault.1`/`vault.2` rotated alternately, which avoids the copy). **I am not asking for a
change of design — only that the cost be visible so it can be weighed later.**

---

## What held up on revision

* **The write invariant is now stated explicitly** — *"no step exists at which no complete vault exists"* — which
  is the sentence that made me able to trace it. A blueprint without that sentence could not be verified.
* **Test 15 kills at every step boundary.** That is the correct test. A single kill point would have passed the
  original, broken sequence.
* **Test 16 asserts the file is unchanged** after a randomness failure — proving an absence, which is much harder
  and much more valuable than proving an error was returned.
* **`NotDiskBound` kept separate from `AboveCeiling`** — so a capability message can never conceal a security
  refusal.

---

## Verdict

| # | Change | Blocking |
|---|---|---|
| **R1** | Preflight reporting whether a vault may be created here; refusal message points to it | **yes** |
| **R2** | **`import`** — the export must be restorable, re-keying to the new device, through the same write sequence, with tests | **yes** |
| **R3** | State the copy-to-prev cost and the alternative considered | no |
| **R4** | One sentence on why HKDF's salt is empty | no |

**B1–B4 are genuinely closed.** I traced B2 rather than trusting the revision, and the sequence is correct.

**Two new blockers, both created by the fixes:** B1's refusal has no escape hatch (R1), and the export has no
restore path (R2). **R2 is the one that matters most** — it is the difference between a backup and the
appearance of one.
