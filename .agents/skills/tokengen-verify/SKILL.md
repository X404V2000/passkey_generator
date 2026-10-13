---
name: tokengen-verify
description: Independently verify TokenGen claims, adversarially review code or blueprints, and gate a feature freeze. Use when reviewing another agent's work, checking whether a claim is true, validating a completion report, auditing for security or threat-model gaps, deciding whether a feature may be frozen, investigating a suspected defect, or when asked to "verify", "review", "audit", "check", "confirm", or "approve" anything in this repository. Covers reproduction-over-reading, the freeze contract, the negative criteria, and how to report a defect without overstating or understating it.
---

# TokenGen Independent Verification & Adversarial Review

Your value is that you **do not accept claims**. In this project the most serious defects were not in the code
— they were in artifacts that *looked* verified: a test that passed against its own defect, a gate that passed
without running, a review of a document that did not exist, a "verified" claim resting on a credential nobody
checked. **Your job is to be the layer that catches those.**

**Prerequisite:** read `tokengen-method` and `plan/reports/README.md` (the clauses and the recorded-failures
table). If your intended review resembles a recorded failure, you are about to repeat it.

## 1. The prime directive: reproduce, do not read

**Reading is not verifying.** Every recorded failure in this project was made by someone who had the artifact
in front of them. So:

- **Run the command yourself.** Do not accept a transcript; produce your own output.
- **Read your own output.** Producing an observation and consuming it are separate acts.
- **Check provenance first.** Before reviewing a document, confirm it exists at the path claimed, at the
  commit claimed: `git log -1 -- <path>` / `git show <sha>:<path>`. **A review that does not name the path and
  commit it read is invalid.** Chat-supplied text is a *directive*, not a review target.
- **State the environment.** Credentials present, network reachable, platform, locale — a result is only as
  good as its preconditions. Neutralise any precondition that could make the result pass for the wrong reason
  (e.g. unset `credential.helper` before an "anonymous" clone).

## 2. Verify by class of claim

| Claim | How to verify | Fail it if… |
|---|---|---|
| "X is guaranteed" | Introduce the defect; observe the test **fail**; revert | It passes with the defect |
| "Gates pass at SHA Y" | `git archive Y` → extract → run the gate yourself | Result came from the working tree; no cold build visible |
| "The fix is published" | Query the remote (`git ls-remote`); extract the **published** commit | Asserted from a local ref |
| "N commits local" | `git rev-list --count origin/main..HEAD` | A number recalled instead of run |
| "Platform mechanism M works" | Run the probe; check the mechanism matches | Label missing (probed/cited/stated) |
| "File F says X" | `git show <sha>:<path>` | Read from memory or from a summary |
| "No unsafe in src/" | `grep -rn "allow(unsafe_code)" src/` **and** the `E0453` probe | The criterion's *meaning* silently changed |
| "Behaviour preserved" | Compare **test counts** before/after, not just "it compiles" | Only compilation was checked |

**Always look for the negative case.** A check that only tests one direction (listed-module-disappears but not
unlisted-module-appears; lock but not unlock; `Send` but not `Sync`) is not a check.

**Always ask: "what would make this pass wrongly?"** That question has found a real defect every time it has
been asked here.

## 3. Reviewing a completion report / gating a freeze

A feature may be frozen only when **all** hold:

1. **Blueprint's acceptance criteria all pass**, including the **negative criterion** (the one mechanical check
   that distinguishes the chosen design from the rejected one).
2. **Gates run by the standard**, anchored to a commit SHA, from an extracted copy, forced rebuild, toolchain
   recorded. Clippy, fmt, test, and `scripts/cfg_check.sh`.
3. **Every discrimination claim has evidence** — mutation applied, test observed to fail, reverted.
4. **Frozen artifacts unchanged** — `git diff <prior-freeze-sha> -- <frozen files>` empty.
5. **Invariants restated** G1–G18 with compliance or inherited status.
6. **Limitations recorded, not buried** — stated limitations and W-items present; the "cannot do" surface
   updated.
7. **Provenance intact** — every source named with path+commit; directives labelled.
8. **The summary does not contradict the body** (check the metadata block and acceptance table against the
   prose — they drift first).

**If any fails, do not freeze.** Say what remains. Do not "approve with a note" a criterion that is unmet —
either it holds or the feature is not frozen.

**Local-only anchoring:** if the freeze cannot be externally verified (unpushed, private repo), the report must
say so and must not imply otherwise. State exactly what can be verified from where.

## 4. Security & threat-model review

Beyond process, review for the security substance:

- **Fail-closed:** every error path that leaves a binding, a check, or a verification unsatisfied must abort.
  Look for any path that returns `Ok` where it cannot truly confirm.
- **Secret hygiene:** no `Debug`/`Clone`/`Copy`/`Display`/`PartialEq` on secret types; no secret in logs,
  errors, or filenames; wipe-before-unlock ordering; whole-allocation locking (capacity, not `len`).
- **Information disclosure:** error messages, timing, or diagnostics that leak secret or identity material;
  a "redacting by construction" claim that is actually a hand-written `Debug`.
- **Invariant erosion:** a change that quietly weakens G1 (env input), G2/G11 (writes), G3 (fail closed),
  G7 (host-utility dependence), or the `forbid(unsafe_code)` boundary.
- **The false-assurance class:** a status `Present`/`Locked`/`Verified` that can be returned on a path where
  it is not actually true. This is the defect the project considers worst.
- **Unstated limits:** a new capability whose inability is not added to "What This Tool Cannot Do".

## 5. Reporting a defect — calibrated, not overstated

- **Say what is established and what is not.** Prefer "unverifiable" over "false" when you cannot distinguish.
  (A private repo returning 404 is *unverifiable*, not *broken*.)
- **Separate** the finding, the evidence (command + output), and the recommended remedy.
- **Distinguish severity:** a defect that would ship vs a record defect vs a style matter. Label them.
- **Do not soften to be agreeable, and do not overstate to be safe.** Both damage the record.
- **Reproduce before you accuse** — and if you cannot reproduce, say so and ask.
- **Report your own errors too.** If you made a claim earlier that a probe now contradicts, correct it in
  place and record the correction; the reasoning is the artifact of value.

## 6. Output format

Structured as: **what's good → risks/concerns → specific required changes → verdict**
(`APPROVED` / `APPROVED WITH FIXES` / `REVISE` / `REJECTED`), plus a **verification log** naming, for each
claim: the method, the observation, and the **path+commit** read. Every required change must be concrete enough
to execute without ambiguity.

## 7. Blocking checklist

- [ ] Provenance checked: every artifact exists at the claimed path and commit.
- [ ] Every claim reproduced, not read; every result read, not just run.
- [ ] Environment preconditions stated and neutralised where they could mislead.
- [ ] Discrimination checked by mutation; negative cases sought.
- [ ] "What would make this pass wrongly?" asked, and answered.
- [ ] Frozen artifacts verified unchanged by `git diff` against their freeze SHA.
- [ ] Summary checked against body; metadata and acceptance table checked.
- [ ] Security review done: fail-closed, secret hygiene, false-assurance, invariant erosion.
- [ ] Limitations present and unsoftened; verdict calibrated to evidence.
