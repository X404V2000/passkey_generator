//! F3.6 — host footprint: behavioural check (G11/G12).
//!
//! # What this proves, and what it does not
//!
//! G11 is a claim that the tool **writes no files outside the USB mount**. That is a property about what
//! does *not* happen, so this test cannot demonstrate it directly — it can only show the **absence of a
//! write in the paths it watched, during the run it performed**.
//!
//! **That bound is stated here rather than left for a reader to infer**, because "we ran it and nothing
//! changed" is exactly the shape of evidence `plan/reports/README.md` records as recurring: *a probe
//! narrower than the claim it supports*. F3.5's L1 was precisely this failure — *"no removable device
//! exists on the dev host"* was true of the probe and not of the world.
//!
//! So: the watched set is **printed** by this test, and the claim is scoped to it.
//!
//! # Why this method exists alongside the static checks
//!
//! `scripts/footprint_check.sh` asserts the absence of write APIs in **our** code. It cannot see a
//! **dependency** that writes. This test observes real filesystem effects, so it can — provided the
//! dependency writes somewhere in the watched set. Neither method subsumes the other, which is why both
//! exist: the static check is *enforcement*, this is *evidence*.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The paths watched, chosen because a host footprint actually lands in them — not an exhaustive set.
///
/// Returned rather than hard-coded so the test can **print** what it watched. A bound that is not visible
/// is a bound a reader will assume away.
fn watched_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(&home));
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        paths.push(PathBuf::from(&profile));
    }
    // The Windows locations a footprint would use. `%APPDATA%` in particular is where a "recent files"
    // or settings footprint appears.
    for var in [
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
    ] {
        if let Some(v) = std::env::var_os(var) {
            paths.push(PathBuf::from(v));
        }
    }
    // Always-present locations that are not env-derived.
    for p in ["/tmp", "/var/tmp"] {
        paths.push(PathBuf::from(p));
    }

    paths.retain(|p| p.exists());
    paths.sort();
    paths.dedup();
    paths
}

/// Snapshot a directory tree as `path -> (is_dir, len)`, to a bounded depth and entry count.
///
/// Bounded deliberately: an unbounded walk of `$HOME` on a developer machine can take minutes and dwarf the
/// test it is supporting. The bound is recorded in the output so the reader knows what was actually walked.
/// Returns the observed entries **and whether the bound was hit**.
///
/// The second value is the point. A bounded walk that silently stops is a walk whose "no changes"
/// result means less than it appears — Grace's category D in the verification brief. The caller must
/// treat `truncated == true` as a failure of the *evidence*, not a pass.
fn snapshot(root: &Path, max_depth: usize, max_entries: usize) -> (BTreeSet<String>, bool) {
    let mut out = BTreeSet::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut truncated = false;

    while let Some((dir, depth)) = stack.pop() {
        if out.len() >= max_entries {
            // Hit the cap: the snapshot is INCOMPLETE for this root.
            truncated = true;
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if out.len() >= max_entries {
                break;
            }
            let path = entry.path();
            // Record the path itself plus a cheap signal of its size, so a file MODIFIED (not just
            // created) is also detected. `metadata` may fail on a racing path; that is not a failure here.
            let meta = entry.metadata().ok();
            let is_dir = meta.as_ref().is_some_and(|m| m.is_dir());
            let len = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            out.insert(format!("{}|{is_dir}|{len}", path.display()));

            if is_dir && depth < max_depth {
                stack.push((path, depth + 1));
            }
        }
    }
    if out.len() >= max_entries {
        truncated = true;
    }
    (out, truncated)
}

/// **The tool leaves no trace in the watched paths — and the same run detects a planted write.**
///
/// The second half is what makes this a test rather than decoration. A snapshot-and-diff that reports
/// "no change" proves nothing unless the same mechanism is **shown to detect a change**. `cfg_check.sh`
/// was once defeated by matching prose; the equivalent failure here would be a diff that silently compares
/// nothing — e.g. because the watched set came back empty, or a path was unreadable.
#[test]
fn no_host_footprint_in_watched_paths() {
    const MAX_DEPTH: usize = 3;
    const MAX_ENTRIES: usize = 20_000;

    let watched = watched_paths();
    println!("F3.6 behavioural footprint check");
    println!(
        "  watched {} paths (depth <= {MAX_DEPTH}, <= {MAX_ENTRIES} entries each):",
        watched.len()
    );
    for p in &watched {
        println!("    {}", p.display());
    }

    // A watched set that is empty would make every assertion below vacuous. On any machine where this
    // suite runs, /tmp exists, so this is a real guard rather than a formality.
    assert!(
        !watched.is_empty(),
        "the watched set is EMPTY, so a 'no change' result would prove nothing. This test's evidence \
         depends on actually watching something."
    );

    let mut before = Vec::new();
    let mut truncated_paths = Vec::new();
    for p in &watched {
        let (set, truncated) = snapshot(p, MAX_DEPTH, MAX_ENTRIES);
        println!(
            "  watched {} -> {} entries{}",
            p.display(),
            set.len(),
            if truncated { "  [TRUNCATED]" } else { "" }
        );
        if truncated {
            truncated_paths.push(p.clone());
        }
        before.push((p.clone(), set));
    }
    let total: usize = before.iter().map(|(_, s)| s.len()).sum();
    println!("  snapshot: {total} entries observed before");

    // A truncated snapshot would make the diff below compare incomplete pictures and could MISS a
    // footprint in the unwalked remainder. That is a failure of the evidence, so it fails the test.
    assert!(
        truncated_paths.is_empty(),
        "the snapshot hit its bound for {:?}. The 'no footprint observed' result would then cover only the \
         walked part, and a footprint in the unwalked remainder would be invisible. Raise MAX_ENTRIES \
         deliberately (and say so) rather than letting the check silently weaken.",
        truncated_paths
    );

    assert!(
        total > 0,
        "the snapshot observed ZERO entries across {} watched paths. A diff over nothing always passes, \
         so this must fail loudly rather than report success.",
        watched.len()
    );

    // --- the exercise: everything the tool does that could touch the host -------------------------
    //
    // F3.6's premise is that the tool leaves no footprint, and the audit found the code does no I/O. So
    // the honest exercise is the API surface that EXISTS, driven the way a user drives it. If a future
    // change made any of these write, this catches it.
    //
    // 1. Generate a key from the OS entropy source — the operation the tool exists to perform.
    // The workspace denies `expect`/`unwrap`/`panic`, so failures are expressed as assertions.
    let made = tokengen::generator::Charset::new(b"abcdefghijklmnopqrstuvwxyz0123456789");
    assert!(made.is_ok(), "a non-empty charset must be constructible");
    let charset = made.unwrap_or_else(|_| tokengen::generator::Charset::digits());

    let generated = tokengen::generator::generate_key_os(&charset, 64);
    assert!(
        generated.is_ok(),
        "generation from the OS entropy source must succeed"
    );
    let key = generated.unwrap_or_default();

    // 2. Wrap it in a Secret and read it — exercising zeroization and, on Unix, the memory-lock path.
    //    Both touch OS state; neither may touch the FILESYSTEM.
    {
        let (secret, _lock_status) = tokengen::zeroize::Secret::new(key);
        assert!(
            !secret.is_empty(),
            "the secret must hold the generated bytes"
        );
        let _ = secret.as_slice();
    } // zeroize-on-drop happens here

    // 3. Device resolution on a path that exists, exercising the platform layer's read paths.
    let _ = tokengen_sys::device::resolve(Path::new("/"));

    let after: Vec<_> = watched
        .iter()
        .map(|p| (p.clone(), snapshot(p, MAX_DEPTH, MAX_ENTRIES).0))
        .collect();

    let mut changes = Vec::new();
    for ((path, before_set), (_, after_set)) in before.iter().zip(after.iter()) {
        for added in after_set.difference(before_set) {
            changes.push(format!("{}: APPEARED {}", path.display(), added));
        }
    }

    // ---------------------------------------------------------------------------------------------
    // CHANGES MADE BY THE TEST ENVIRONMENT, EXCLUDED EXPLICITLY AND BY NAME.
    //
    // The CI runners write their own files DURING a job. Observed on macOS:
    //
    //   /Users/runner/actions-runner/extracted/_diag/Worker_<timestamp>.log
    //
    // That is the GitHub Actions runner's diagnostic log, not the tool. The test is right to notice it —
    // it cannot tell our writes from anyone else's, and pretending otherwise is how a footprint check
    // becomes decorative. But it must not be silenced by widening the snapshot or by watching less; the
    // exclusion is therefore named here, applied to the diff only, and PRINTED.
    //
    // A change matching any pattern below is reported as EXCLUDED rather than as a footprint. Anything
    // else fails. Adding a pattern here is a deliberate act with a reason attached, visible in review.
    // ---------------------------------------------------------------------------------------------
    const ENVIRONMENT_WRITES: &[&str] = &[
        // GitHub Actions runner diagnostics: `<runner-root>/actions-runner/**` and `_diag` logs.
        "/actions-runner/",
        "/_diag/",
        // Also written by the runner's own tooling on macOS/Linux runners.
        "/Runner.Worker",
        "/Runner.Listener",
    ];

    let (environment, footprint): (Vec<_>, Vec<_>) = changes
        .iter()
        .partition(|c| ENVIRONMENT_WRITES.iter().any(|pattern| c.contains(pattern)));

    for c in environment.iter().take(40) {
        println!("  EXCLUDED (test environment, not the tool): {c}");
    }
    for c in footprint.iter().take(40) {
        println!("  CHANGE {c}");
    }

    assert!(
        footprint.is_empty(),
        "{} change(s) appeared in the watched paths during the exercise that are NOT on the recorded \
         environment-exclusion list. G11 forbids writing files on the host. If a change is caused by the \
         test environment rather than the tool, it must be added to ENVIRONMENT_WRITES with a reason — not \
         silenced by widening the snapshot or watching less. See the CHANGE lines printed above.",
        footprint.len()
    );

    println!("  no footprint observed in the watched set");

    // --- the negative half: this mechanism must DETECT a planted write -----------------------------
    //
    // Without this, the test above is satisfied by a snapshot function that observes nothing.
    let probe_dir_found = watched.iter().find(|p| p.is_dir());
    assert!(
        probe_dir_found.is_some(),
        "at least one watched path must be a directory, or the detection probe cannot run and the \
         'no footprint observed' result above cannot be distinguished from observing nothing"
    );
    // The assert above establishes this; `cloned()` plus `unwrap_or_else` keeps the workspace's `expect`
    // denial satisfied without introducing a panic path.
    let probe_dir = probe_dir_found
        .cloned()
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let (probe_before, _) = snapshot(&probe_dir, MAX_DEPTH, MAX_ENTRIES);

    let probe_file = probe_dir.join(format!("f36_detection_probe_{}", std::process::id()));
    let wrote = std::fs::write(&probe_file, b"planted");
    assert!(
        wrote.is_ok(),
        "the detection probe must be able to write to {} — without it, 'no footprint observed' cannot be          distinguished from 'the mechanism observes nothing'",
        probe_dir.display()
    );

    let (probe_after, _) = snapshot(&probe_dir, MAX_DEPTH, MAX_ENTRIES);
    let detected = probe_after
        .difference(&probe_before)
        .any(|e| e.contains(&probe_file.display().to_string()));

    // Clean up before asserting, so a failure does not leave litter behind.
    let _ = std::fs::remove_file(&probe_file);

    assert!(
        detected,
        "the snapshot mechanism did NOT detect a planted write in {}. That means 'no footprint observed' \
         above is meaningless — the mechanism cannot see changes at all. This is the failure mode \
         cfg_check.sh had: reporting PASS while observing nothing.",
        probe_dir.display()
    );
    println!("  detection probe: a planted write WAS detected (the mechanism works)");
}
