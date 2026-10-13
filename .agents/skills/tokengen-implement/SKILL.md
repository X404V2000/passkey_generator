---
name: tokengen-implement
description: Implement an approved TokenGen blueprint in Rust with probes, cfg-coverage, and discriminating tests. Use when writing or modifying Rust code in this repository (src/, tokengen-sys/, tests/), adding a module or public API, implementing a feature from a blueprint, fixing a defect, adding unsafe FFI, adding a dependency, or adding tests. Covers the forbid(unsafe_code) boundary, the sub-crate FFI rule, must-probe for platform code, mutation-based discrimination, and the anchored gate run required before any completion claim.
---

# TokenGen Implementation

You are implementing a **security tool**. A subtle correctness error is a vulnerability; a false claim is
worse than no claim. Implement exactly the approved blueprint, and prove the claims rather than asserting them.

**Prerequisites:** read `tokengen-method`. **No code until the blueprint is approved.** Read the blueprint at
`plan/reports/<feature>/` — implement *it*, not a recollection of it.

## 1. The two hard structural rules

### 1.1 `unsafe` lives in `tokengen-sys` only

- The main crate (`src/`) carries `#![forbid(unsafe_code)]`. **`forbid` cannot be relaxed by any module or
  `#[allow]`** — attempting it is `error[E0453]`. Do not attempt to convert it to `deny`.
- All FFI (syscalls, platform APIs) lives in `tokengen-sys`, behind a **safe public API**.
- Inside `tokengen-sys`, `unsafe` is confined to enumerated `#[allow(unsafe_code)] mod platform` modules in
  named files (currently `memory.rs`, `coredump.rs`; F3.5 adds `device.rs`). **Every `unsafe` block carries a
  `// SAFETY:` comment** stating why the call is sound.
- **Adding a module containing `unsafe` is a structural change.** It requires a recorded amendment (see AM-002
  as the template) and must state the new count of `unsafe`-bearing modules explicitly.
- **Never move page arithmetic, pointer derivation, or platform reasoning into the main crate.** Safe
  signatures (`&mut [u8]`, `(usize, usize)`) belong in `tokengen-sys`; the caller passes an address, not a
  pointer it dereferences.

### 1.2 Secrets use the F3 machinery

- Wrap secret buffers in `Secret<T>` (zeroizes on drop, locks the whole allocation). Do not return raw
  `Vec<u8>`/`String` copies of secret material to callers.
- Never implement `Debug`, `Display`, `Clone`, `Copy`, or `PartialEq` on a secret-bearing type.
- Do not log, print, or format secrets. (The workspace denies `print_stdout`, `print_stderr`, `unwrap_used`,
  `expect_used`, `panic`.)

## 2. Must-probe before you write platform code

Before implementing anything that touches the OS — a path, a syscall, a device property, a permission:

1. **Probe it on this host.** Run the command; capture the output.
2. **Probe the failure cases too** — missing, empty, unreadable, different.
3. **Commit the probe** under `probes/` and reference it from the blueprint's Probes and Evidence section.
4. **Implement the probed mechanism**, not a plausible one. If the probe shows the blueprint's mechanism does
   not work, **stop and report it** — do not silently substitute. (This has happened: a blueprint's UUID route
   was wrong; the probe corrected it before implementation.)
5. **No external binaries.** Shelling out to `blkid`, `udevadm`, etc. violates G7 (portable binary). Use
   `libc`/`std::fs` only.

## 3. Cover every `cfg` branch

A branch that is never compiled can drift from its callers silently — this has happened (`error[E0061]` in a
non-Unix stub the Unix gates never saw).

1. Add every new `cfg`-gated file/branch to `scripts/cfg_check.sh`'s `EXPECTED` map.
2. Run `./scripts/cfg_check.sh`. It inverts the gates and compiles the deferred branch on any host.
3. **It fails loudly** if an anchor moves OR if a gated module is missing from `EXPECTED`. If it reports
   `FATAL`, fix the source or the map — never disable the check.
4. **Platforms with no backend fail closed:** return an explicit `NotSupported` error, never `Ok` with a
   plausible value. A stub that reports success makes the caller's status a lie.

## 4. Tests must be shown discriminating

A test that passes against the defect it exists to catch proves nothing. For every claim of the form
"X is guaranteed":

1. **Write the test.**
2. **Introduce the defect** — reverse the ordering, remove the marker, use the wrong value.
3. **Observe the test FAIL.** If it still passes, the test is not discriminating.
4. **Revert the defect** and confirm green.
5. **Record the mutation** (ideally as a script; otherwise in the report with the exact change and output).

Where a guarantee is symmetric, test **both directions** (e.g. lock *and* unlock, zeroize *and* no-unlock).
Where a test's outcome depends on the environment (parallelism, credentials, platform), state the
precondition — it is part of the coverage.

**Compile-fail tests** (trybuild): keep the passing inverse case that pins the boundary (e.g. that a
documented `#[must_use]` limitation is real). `unused_must_use` is a warning — carry `#![deny(unused_must_use)]`
in the case file.

## 5. The gate run — mandatory before any completion claim

Run from an **extracted copy of the commit**, never the working tree:

```bash
git archive HEAD | tar -x -C /tmp/fresh && cd /tmp/fresh
touch src/lib.rs tokengen-sys/src/lib.rs            # force a clean rebuild
cargo clippy --all-targets --features test-hooks -- -D warnings
cargo fmt --check
cargo test --release --locked --features test-hooks
./scripts/cfg_check.sh
grep -rn "allow(unsafe_code)" src/                  # must be empty
grep -rln "unsafe {" src/ tokengen-sys/src/         # only the enumerated platform files
git diff <previous-freeze-sha> -- src/entropy.rs src/generator.rs   # frozen artifacts unchanged
```

Record the **commit SHA**, the **toolchain versions**, and that the rebuild was forced. A cold build must show
`Compiling …`. Gates that cannot run are **NOT RUN**, never "approximated".

## 6. Dependencies

- **No new dependency without written justification** in the blueprint.
- **No dependency for unbuilt code.** If a platform backend is deferred, its dependency (e.g. `windows-sys`)
  stays out until the backend is real.
- Lints are centralized in `[workspace.lints]`; `tokengen-sys` opts out of `unsafe_code = "forbid"` explicitly
  (its manifest declares all lints locally — Cargo rejects inheriting and overriding in the same manifest).

## 7. Reporting (the implementer writes `senior_engineer_*.md`)

Every message: `From/To/Re` header, a **disposition table**, point-by-point responses, a **verification log**
(how each factual claim was checked — labelled *measured* vs *reasoned*), and requested actions. Per
`tokengen-method`: every pass/fail claim names its **commit SHA**; every world-state claim names its
**observation**; a count comes from a command, never memory.

**Findings are reported even when inconvenient.** If you discover a defect — in the code, the blueprint, the
gates, or the architect's directive — report it with evidence. Do not silently fix a record; report and then
fix, so the record shows both the defect and its resolution.

## 8. Blocking checklist

- [ ] Blueprint read (path+commit) and approved; implementing it, not a paraphrase.
- [ ] `unsafe` confined to enumerated `tokengen-sys` files; `src/` clean; every block has `// SAFETY:`.
- [ ] Secrets wrapped in `Secret<T>`; no `Debug`/`Clone`/`Copy`/`PartialEq` on secret types.
- [ ] Platform claims probed; mechanism matches the probe.
- [ ] Every `cfg` branch in `EXPECTED`; `cfg_check.sh` passes.
- [ ] Every guarantee shown discriminating **by mutation**.
- [ ] Gates run via the standard, anchored to a SHA, forced rebuild.
- [ ] Frozen artifacts unchanged (verified by `git diff` against their freeze SHA).
- [ ] No unjustified dependency; none for unbuilt code.

## 9. When the blueprint and reality disagree

**Reality wins, and you report it.** If a probe, a compiler error, or a test contradicts the blueprint, do not
bend the code to fit the document and do not bend the document silently. Report the contradiction with the
observation, propose the correction, and let the architect approve the amendment. An implementation that
satisfies a wrong specification is the exact failure this project exists to prevent.
