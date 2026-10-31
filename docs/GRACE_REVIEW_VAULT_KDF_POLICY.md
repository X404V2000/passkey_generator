# Grace — Review of the Vault Threat Model §4.3 (KDF policy)

**Subject:** `docs/VAULT_THREAT_MODEL.md` §4.3 as amended 2026-10-31.
**Method:** attacked the two targets Bruce was asked to defend, then looked for what neither named.
**Verdict:** **CHANGES REQUIRED before the blueprint is written.** Three findings, one of them a denial-of-service
vector the model does not name.

I could have signed this off. The policy is well-reasoned and the floor/target distinction is correct. I am not
signing it off because the reasoning is right and the **boundaries are underspecified**, and boundaries are
where this project's defects keep coming from.

---

## G1 — The floor is ambiguous, and its ambiguity is exploitable

**Planted:** §4.3 requires the reader to reject any vault whose "recorded cost is below `m = 64 MiB, t = 3`".

**Problem:** Argon2id's cost is the **product** `m · t`, but tradeoff resistance comes mostly from **`t`**. The
sentence does not say which dimension it floors.

| Vault | `m · t` | Iterations | Passes a product floor? | Actually resistant? |
|---|---|---|---|---|
| `64 MiB, t=3` | 0.20 GB·it | 3 | yes | yes |
| `256 MiB, t=2` (proposal) | 0.54 GB·it | 2 | yes | yes |
| **`4 GiB, t=1`** | **4.29 GB·it** | **1** | **yes, easily** | **no** |

**`m=4 GiB, t=1` passes any product-based floor while having the weakest possible iteration resistance** —
exactly the shape an attacker with memory bandwidth prefers. A floor on the product would **certify the weak
configuration as strong.**

**Required change:** the floor is a **minimum on each dimension independently**, not on the product:

> `m ≥ 64 MiB` **AND** `t ≥ 3` **AND** `p ≥ 1`.

**Verified against the measurements:** at `m=64 MiB`, `t=3` measured 0.375 s on the reference host — inside the
budget, so the floor is achievable, not aspirational.

---

## G2 — The export can become the weakest link, and the model only asks that it "explains"

**Planted:** the export is bound to the **passphrase alone**, at a higher cost target (3 s).

**Problem 1 — a weak passphrase defeats the cost entirely.** At 3 s per guess with 16 cores:

| Passphrase | Space | Time to exhaust |
|---|---|---|
| 4-digit PIN | 10,000 | **minutes** |
| 6-char lowercase | 3.1 × 10⁸ | ~1.8 years |
| 8-char lowercase | 2.1 × 10¹¹ | ~1,240 years |

**The Argon2 cost is irrelevant if the passphrase is a PIN.** §4.2 says the export "explains the tradeoff".
**Explaining is not enforcing.** Nothing in the model stops `tokengen vault export` with a 4-character
passphrase, and an export is precisely the artifact an attacker takes away.

**Required change:** the export **refuses** to be created with a passphrase below a stated minimum strength,
or requires an explicit, recorded acknowledgement naming the specific risk. The vault itself (two factors) may
set a lower bar than the export; the export is the solo-factor artifact and must be held to a higher one.

**Problem 2 — portability has a cost the model does not price.** An export calibrated to 3 s on a modern laptop
opens in **12–30 s** on the reference low-end device. The ceiling "warns rather than refuses", which is right
for the vault — but a **recovery** export taking 30 s to open, under stress, possibly on a borrowed machine, is
**an availability failure wearing a warning**. Recovery happening is the whole point of the export.

**Required change:** the export's parameters must be calibrated against a **stated maximum device**, not the
creating machine — or the export must record both its parameters and an **estimated cost on a reference slow
device**, so the user is told *before they rely on it* what recovery will cost.

---

## G3 — The header is attacker-controlled, and only the FLOOR is bounded

**Neither Bruce's target.** Found while checking G1.

**Planted:** the reader acts on parameters recorded in the file. §4.3 bounds them from **below** (the floor).

**Problem:** nothing bounds them from **above**. A vault — or a corrupted or malicious file — recording
`m = 4 GiB` on a device with 1 GiB free causes the reader to attempt a 4 GiB allocation.

* The process dies, **or** the OOM killer takes something else.
* If this happens **mid-write**, it interacts with the atomic-write requirement (S1) and could turn a
  **denial of service into data loss** — the exact failure the Founder ranks worst.

**A pending "warn above ~3 s" is not a bound.** A warning fires *after* the resources are committed.

**Required change:** a **compiled-in UPPER bound** on `m` (and on `t`) — a hard refusal before any allocation,
with a clear message. "Refuse to attempt what this device cannot allocate" is not the same decision as "refuse
to open a valid vault": the former protects the user's other work; the latter would be a denial of service.
**Both bounds must exist, and the failure modes must be distinguishable.**

---

## What held up

* The **floor/target distinction** is correct and well stated. The floor is a security property; the target is
  usability. Keeping them separate is the right call.
* **Warning rather than refusing** on a valid vault is right for availability, subject to G3.
* **Recording `p` honestly** is right — `p=4` measured identically to `p=2` here, so recording 4 would be a
  false claim in the format itself.
* **Exports getting a higher target** is the correct direction, though G2 shows the target is not the lever.

---

## Verdict

**CHANGES REQUIRED.** The amendment is sound in substance and underspecified at the boundaries.

| # | Change | Blocking? |
|---|---|---|
| **G1** | Floor is a minimum on **each** of `m` and `t`, not on the product | **Blocking** |
| **G2a** | Export **refuses** weak passphrases (or requires a recorded acknowledgement) | **Blocking** |
| **G2b** | Export calibrated against a stated **slow** reference device, cost stated before reliance | **Blocking** |
| **G3** | Compiled-in **upper** bound on `m`/`t`, refused before allocation, distinguishable from "invalid vault" | **Blocking** |

**On the blueprint:** with these four closed, §4.3 is attackable-and-surviving. Without them, the blueprint
would be built on a floor that certifies `4 GiB t=1` as strong, an export that accepts a PIN, and a header that
can OOM the reader. **I would reject the blueprint if it inherited any of the three.**
