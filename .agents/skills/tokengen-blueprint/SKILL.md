---
name: tokengen-blueprint
description: Author or review a TokenGen feature blueprint before implementation. Use when starting a new feature (F3.5, F4-F10, F3.9), writing a design document, creating plan/reports/F<id>/*.md, answering or asking the open design questions for a feature, defining a public API for a new module, or reviewing someone else's blueprint against the TokenGen structure. Covers the 15-section blueprint shape, the mandatory Probes and Evidence section, API-completeness checks, and the requirement that every acceptance criterion mechanically fail the rejected design.
---

# TokenGen Blueprint Authoring & Review

A **blueprint** is the specification a feature is implemented from. In this project a blueprint is not a
proposal — it is the artifact an implementer works from, so **an imprecise blueprint produces a wrong
implementation that satisfies its own criteria**. That has happened here. This skill prevents it.

**Prerequisite:** read `tokengen-method` and the source-of-truth artifacts it names. **No implementation code
until the blueprint is approved by the architect.**

## 1. When this applies

- Starting any feature F3.5, F3.9, F4–F10.
- Writing or revising a design document under `plan/reports/<feature>/`.
- Reviewing a blueprint another agent produced.
- Answering the "open questions" section of a draft blueprint.
- Defining any public API (`pub fn` / `pub struct` / `pub trait` / `pub enum`) for a new module.

## 2. Required structure — 15 sections

A TokenGen blueprint has these sections, in order. (Not every section is long; every section is present.)

| # | Section | Must contain |
|---|---|---|
| 1 | **Provenance** | Every source named with **path + commit**. Any chat-supplied text labelled a **Directive** (advises; not a review; no approval flows from it) |
| 2 | **Purpose & threat model** | What it defends against **and an explicit list of what it does NOT defend against** |
| 3 | **Public API** | Every type and signature, **fully defined** (see §4). Frozen once approved |
| 4 | **Behavioural contract** | Numbered invariants B1…Bn, each testable |
| 5 | **Algorithm / mechanism** | The actual steps, with the platform-specific paths named |
| 6 | **Platform layer** | Where FFI lives (`tokengen-sys`), and the mechanism per OS |
| 7 | **Compilation-target axis** | Every `cfg` branch, and which gate compiles it |
| 8 | **Test plan** | Each test labelled with **what it proves and what it runs against** (real reader vs mock) |
| 9 | **Timing / budget arithmetic** | Any latency guarantee, written out with its arithmetic and the boundary of responsibility |
| 10 | **Limitations & open items** | Stated limitations (frozen with the feature) and W-items (deferred) |
| 11 | **Feature flags** | e.g. `dev-mode`, `test-hooks`: opt-in, never in `default`, never in a release build |
| 12 | **Invariant restatement** | G1–G18 with compliance status — inheriting from earlier features where applicable |
| 13 | **Probes and Evidence** | **Mandatory.** See §3 |
| 14 | **Acceptance criteria** | Checkbox list; see §5 |
| 15 | **Deliverable order** | The commit sequence the implementer follows |

## 3. Probes and Evidence — mandatory, before approval

**This section must exist and be filled BEFORE the blueprint is approved**, not written afterwards. Four
platform defects in this project were caught only when a claim was probed; three of them would have been
caught by this section had it preceded the writing.

For every design-bearing claim, record **the command and its output**, and label it:

- **probed** — you ran it on the actual host; the artifact is committed under `probes/`.
- **cited** — you cannot probe here; cite the authoritative source.
- **stated-limitation** — it cannot be probed and cannot be cited confidently; it becomes a W-item.

| Claim type | Required artifact |
|---|---|
| Signature or trait bound compiles | a probe using the type as specified + recorded compiler output |
| Type property (auto-trait, variance, `Copy`) | a compile probe **with the inverse case** proving it discriminates |
| Platform semantic | a probe, or a citation labelled as such |
| Numeric / coverage / timing property | a measurement with its method |

**Also list the compilation targets and `cfg` branches**, each to be compiled by `scripts/cfg_check.sh`.
**A claim is only as executable as its least-compiled branch.**

An unlabelled assertion is not acceptable in this section.

## 4. API completeness — check before submitting

The API section must define **every type it references**. A defect class this project has hit: a trait using a
type that is never declared — unbuildable as written.

Before submitting, verify each type referenced in a signature is defined in the same section:

```bash
# For every type named in the API block, confirm it is defined:
for t in TypeA TypeB TraitC; do
  grep -c "struct $t\|enum $t\|trait $t" plan/reports/<feature>/<blueprint>.md
done    # any zero is a defect
```

**API rules learned here:**

- **`#[must_use]` on a tuple return does not prevent `let (x, _) = f();`.** Prefer returning `Result` and
  failing closed over returning a status the caller can silently drop. If a tuple is unavoidable, pin the
  boundary with a passing compile-fail test and document the limitation — do not present the attribute as a
  guarantee it does not provide.
- **Opaque handles over exposed internals.** Prefer `pub struct H { /* private */ }` threaded between
  functions over exposing platform-specific fields. Keeps the representation free to differ per OS.
- **Error types:** `#[non_exhaustive]`; `Copy` where it reinforces redaction (a future owned-secret variant
  becomes a compile error at the definition); carry no secret material by construction, not by a hand-written
  `Debug`.
- **Sealed traits** for closed sets of implementors.
- **`!Send`/`!Sync`** where a handle must not cross threads — via `PhantomData<*const ()>`, the only stable
  mechanism; state this, since `impl !Send` is unstable.

## 5. Acceptance criteria that actually discriminate

Criteria must be phrased so that the **rejected design fails them**. A criterion satisfied by both the right
and the wrong implementation proves nothing.

- State the **negative criterion**: the single mechanical check that distinguishes the chosen design from the
  rejected one (e.g. *"no `#[allow(unsafe_code)]` appears anywhere in `src/`"*).
- Every criterion must be **checkable by a command or a test**, not by reading.
- Where a guarantee is split between features (e.g. detection vs exit), state the boundary and which feature's
  tests assert which half.

## 6. Reviewing a blueprint

When reviewing (architect role), check and report:

1. **Every section present**, in order.
2. **API completeness** — run the §4 check; a zero is a blocking defect.
3. **Probes and Evidence filled** — every platform claim labelled; every `cfg` branch assigned a gate.
4. **Criteria discriminate** — the rejected design must fail them.
5. **Invariants** — none weakened; inheritance from earlier features stated.
6. **Honest limits** — the non-defences are explicit; no "what this cannot do" softened.
7. **Provenance** — sources named with path+commit; directives labelled as directives.

Report as: **what's good → risks/concerns → specific required changes** → **verdict**
(approved / approved-with-fixes / revise). Name required changes concretely enough to execute without
ambiguity.

## 7. Anti-patterns (all have occurred here)

| Anti-pattern | Why it is fatal |
|---|---|
| A platform table that reads authoritative but is not probed | Class-A defect: implementer builds the wrong thing and satisfies the spec |
| A blueprint anchored to a commit that does not contain the measured code | The anchor must name the **code** under test |
| Presenting an unmeasured number as established | State it as arithmetic and make measurement an acceptance criterion |
| Criteria satisfiable by the rejected design | The spec would direct the wrong implementation |
| Softening a limitation to make the feature look complete | The honesty is the product |
| Treating chat-supplied text as a repository artifact | Provenance failure; a review name a path+commit |

## 8. Output format

When authoring: produce the 15-section document at `plan/reports/<feature>/<Feature>_<Name>.md`, then state in
the conversation message the **path and commit** it was written at.
When reviewing: produce a review message with a disposition table, point-by-point findings, a verification
log naming path+commit, and a verdict with required changes.

## 9. Requirements

- Read `tokengen-method` first.
- `scripts/cfg_check.sh` exists and must be extended for any new `cfg` branch.
- Platform probes are committed under `probes/`.
- No implementation code until approval.
