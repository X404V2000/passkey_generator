---
name: tokengen-method
description: Enforce the TokenGen security engineering method on every change to this repository. Use when working on any TokenGen feature (F1-F10, F3.5, F3.9), before writing or reviewing code, when authoring a blueprint, when running gates, when writing a completion report, or whenever a claim about the system, a commit, a remote, a platform, or a document is made. Covers the frozen invariants G1-G18, the blocking enforcement clauses and corollaries, must-probe discipline for platform/FFI claims, anchored gate runs, and the two-role review protocol.
---

# TokenGen Method (Constitution)

**Read this before any work on this repository.** TokenGen is a security tool: a USB-resident, offline,
fail-closed secret and passkey generator. Incorrect claims in its record are worse than absent ones, because
users rely on them. Every rule below exists because a real defect reached the record. The rules are
**blocking** — an agent that skips a gate is in violation, not merely suboptimal.

## 0. What this repository is

| | |
|---|---|
| Product | TokenGen — portable, offline, fail-closed token/passkey generator, runs from a USB drive |
| Language | **Rust.** The Python tree lives under `legacy/python/` and is **legacy, unsupported, and not installed by any packaging path** (F3.9) — never add to it, never present it as a security-equivalent implementation, and never restore a `pip`/console entry point for it |
| Crates | `tokengen` (main, `#![forbid(unsafe_code)]`) + `tokengen-sys` (the **only** crate permitted `unsafe`, behind a safe public API) |
| Security posture | Assume hostile host. Fail closed: on any CSPRNG, identity, or verification error, refuse — never retry, never fall back to a weaker path, never return partial data |
| Honesty | The README contains **"What This Tool Cannot Do"**. It is a feature. Never soften it under pressure |

## 1. Source-of-truth artifacts — read these, do not duplicate them

This skill states the *method*. The *content* lives in the repository. Read the actual files; never trust a
summary of them, including a summary in a conversation message.

| Artifact | Read it for | When |
|---|---|---|
| `plan/reports/understanding_of_this_software.md` | Product scope, the invariant table **G1–G18**, locked decisions **D1–D5**, feature list F1–F10 | Before any feature work |
| `plan/reports/README.md` | **The enforcement clauses, corollaries, the recorded-failures table, the gate-run standard, and the report status vocabulary** | Before writing any claim, report, or gate result |
| `plan/ROADMAP.md` | Which features are frozen, in flight, or recorded; their anchor SHAs | Before starting or resuming work |
| `docs/LANGUAGE_DECISION.md` | Why Rust; why Python is out of the trust path; the disclosure and `SECURITY.md` obligations | Before touching language, packaging, or distribution |
| `plan/mailroom/threads/` | The decision record and review exchanges | Before responding to a review or a design question |
| `plan/reports/F<id>/` | The feature's blueprint, amendments, and completion report | Before working on that feature |
| `probes/`, `scripts/cfg_check.sh` | The mechanical enforcement: platform probes and cfg-branch compilation | Before making a platform claim or running gates |

**Rule — provenance.** If a rule, decision, or claim is needed, read it from its file and cite the **path and
commit**. Text supplied in a chat message is a **directive** (advice), never a review or an approval. A review
that does not name the path+commit it read is invalid.

## 2. Invariants G1–G18 — non-negotiable

Read the live table in `plan/reports/understanding_of_this_software.md` §5. A feature that cannot satisfy an
invariant **does not ship**. If a task appears to require weakening one, stop and escalate — do not weaken it
quietly, and do not delete it from the documented contract.

The ones most often at risk in day-to-day work:

- **G1 — no environment input.** Do not read env vars, cwd-only assumptions, or ambient config to change
  security behaviour. A guard disableable by ambient configuration is not a guard. (Compile-time features are
  acceptable; runtime env switches are not.)
- **G2/G11/G12/G13 — write nothing.** No key material to disk; no files outside the USB mount; no registry /
  plist / dconf; no MRU or recent-files integration.
- **G3 — fail closed.** Any error path that could leave a session unverified must abort, not continue.
- **G4 — zeroize on drop.** Secrets live in `Secret<T>` (F3) and are wiped before unlock on drop.
- **G7 — single portable binary.** No dependence on host utilities (`blkid`, `udevadm`, …). If a mechanism
  needs an external program, it is the wrong mechanism.
- **G9 — constant-time comparisons** for secret material. Non-secret comparisons (e.g. device identity) do not
  require it, but say so explicitly rather than by omission.
- **G16/G17 — session guard.** Exit within 1 s of USB removal; device identity bound at startup and
  re-checked. The split (who detects, who exits) is recorded per feature.

## 3. Enforcement clauses — from `plan/reports/README.md`

These are the constitution's teeth. **Read the live text; it is the authority.** Summary of obligations:

- **Clause 1 — Enforcement.** Every guarantee must be enforced by the compiler, a test, or CI. Where it is a
  test or probe, it must be shown **discriminating by mutation against the real implementation**: introduce
  the defect, observe the test **fail**, revert. Testing the mechanism is not testing the system.
- **Clause 2 — Anchor.** Every pass/fail claim names the **commit SHA** it was produced against. Evidence that
  exists only in a working tree is not a gate result.
- **Clause 2 extended — World-state claims.** Every claim about the world (a commit, a remote ref, a count, a
  platform, an environment, **a document's existence or content**) must name the **observation that produced
  it**. Run the command; **read its output** — producing an observation and consuming it are separate acts,
  and only the second is verification.
- **Corollary — environment is coverage.** Where a result depends on the environment (credentials, network,
  platform, locale), that precondition is part of the coverage; state it and neutralise it where it could
  invalidate the result. An "anonymous" clone with a cached credential proves nothing about strangers.
- **Corollary — compilation targets are coverage.** Every `cfg`-gated branch must be **compiled by a gate**.
  A host's default `cargo build` type-checks only that host's branches. Use `scripts/cfg_check.sh`. A claim
  is only as executable as its least-compiled branch.
- **Corollary — a verification mechanism is itself subject to clause 1.** A gate must be shown to **fail when
  it should**, including when it cannot perform its own check. A gate that reports success without running is
  worse than no gate, because it is trusted.
- **Corollary — editing a report invalidates its summary.** Any edit after the summary is written requires
  re-reading the summary. Summary sections drift first and are read first.

**The recorded-failures table in `plan/reports/README.md` lists the real defects these clauses prevent. Read
it. If your intended action resembles one of those rows, you are about to repeat it.**

## 4. The gate-run standard (mandatory)

Produce gate results **from an extracted copy of the commit, never from the development tree**:

```bash
git archive HEAD | tar -x -C /tmp/fresh && cd /tmp/fresh
touch src/lib.rs tokengen-sys/src/lib.rs   # force a clean rebuild (no cached no-op)
cargo clippy --all-targets --features test-hooks -- -D warnings
cargo fmt --check
cargo test --release --locked --features test-hooks
./scripts/cfg_check.sh                      # compile every cfg branch
```

Record: the **commit SHA**, the **toolchain versions**, and the fact that the rebuild was forced. A cold build
must be visible in the output (`Compiling …`). `git archive` cannot read the working tree — that is the point.

**`cargo audit` / `cargo deny`** are not packaged on this host; when a gate cannot be run, say **NOT RUN** —
never "approximated" or "substituted".

## 5. Must-probe discipline (platform / FFI claims)

This project has produced **four** class-A defects — a specification that reads as authoritative but cannot be
executed as written — all in platform code. Before any claim about a syscall, a path, a device class, a
permission, or a platform behaviour:

1. **Probe it on the actual host.** Run the command. Record the command **and its output**.
2. **Label every platform claim** as one of: **probed** (with the artifact), **cited** (with the source), or
   **stated-limitation** (with the reason it cannot be probed here). *A citation is acceptable where a probe
   is impossible; an unlabelled assertion is not.*
3. **Probe the failure mode too.** Not only "does the happy path work", but "what happens when the component
   is missing, empty, unreadable, or different".
4. Commit the probe under `probes/` so it is re-runnable.

Known findings already established (do not re-derive, do extend):
`blkid` is absent and unusable under G7; `/sys/block/*/serial` does not exist — the real path is
`/sys/block/<dev>/device/serial`; mount→device resolution requires `stat`→`st_dev`→`/sys/dev/block/<maj:min>`;
`/dev/disk/by-uuid` is indexed **uuid→device** so device→uuid needs a reverse traversal. See `probes/README.md`.

## 6. The two-role protocol

Work alternates between roles, recorded as numbered thread files in `plan/mailroom/threads/`:

- **System Design & Architectural Engineer** (architect): owns architecture, blueprints, the invariant
  framework, review, and enforcement. Writes `system_design_and_achitectural_engineer*.md`.
- **Senior Software Engineer** (implementer): owns implementation, probes, verification, and reporting.
  Writes `senior_engineer_*.md`.

**No implementation code until the feature's blueprint is approved by the architect.** Every message is
self-contained: a `From/To/Re` header, a disposition table, point-by-point responses, a **verification log**
(how each factual claim was checked, labelled *measured* vs *reasoned*), and requested actions.

## 7. Status vocabulary

A report's status must be exactly one of, and justified by recorded gate output
(full definitions in `plan/reports/README.md`): `IMPLEMENTED`, `FROZEN`, `SUPERSEDED`, `AMENDED`.
`FROZEN` requires an **anchored commit**; it may not be claimed while any gate is unrun, substituted, or
anchored to a working tree. A freeze that is only locally anchored must say so and must not imply external
verifiability.

## 8. Blocking checklist — apply to every task

- [ ] Read the source-of-truth artifacts in §1 — the files, not a summary.
- [ ] Confirmed the invariants that apply, and that none is weakened.
- [ ] Blueprint approved before any code (for feature work).
- [ ] Every platform/FFI claim probed or explicitly labelled cited/stated-limitation.
- [ ] Every `cfg` branch compiled by `scripts/cfg_check.sh`.
- [ ] Every test claim shown **discriminating by mutation** against the real implementation.
- [ ] Gates run via the gate-run standard, anchored to a **commit SHA**.
- [ ] Every world-state claim names its observation; nothing asserted from memory.
- [ ] Honest limitations recorded; the "cannot do" surface updated, never softened.
- [ ] No new dependency without written justification; none added for unbuilt code.

## 9. When in doubt

Ask: **would a security professional trust this?** If no, the decision is wrong. Prefer refusing to act over
making an unverifiable claim. Escalate rather than guess. When a rule here conflicts with speed, the rule wins.
