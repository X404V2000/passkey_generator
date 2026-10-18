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
/// The paths watched, each with the depth that makes watching it *meaningful*.
///
/// # Why depth is per-path, and why that is the honest fix
///
/// An earlier version deep-walked the real `$HOME` on every platform. On CI that is **measurably the wrong
/// instrument**: a runner's `$HOME` is a live system account, and the OS writes into it continuously. Two
/// different, unrelated writes were caught on consecutive runs —
/// `~/actions-runner/**/_diag/Worker_*.log` and `~/Library/IdentityServices` — neither caused by the tool.
///
/// The tempting fix is an exclusion list. **That is a check going hollow in slow motion**: every new
/// OS-created path becomes another entry, added in a hurry, and the list ends by excusing exactly the writes
/// it exists to catch. The test's own failure message warns against it.
///
/// **The claim is about the TOOL's footprint, not about the machine being quiet.** The tool is a process; its
/// footprint is what *that process* causes. Deep-walking a profile shared with the entire OS attributes
/// every other process's writes to us.
///
/// So depth is chosen by what a footprint could plausibly look like:
///
/// * **temp directories — full walk.** This is where a careless implementation writes: a temp file, a
///   socket, a lock. The whole tree matters, and nothing else busy lives there.
/// * **`$HOME` and its config/cache roots — depth 1 only.** A settings or MRU footprint appears as a *new
///   entry directly in* `~/.config`, `~/.cache`, `%APPDATA%`, or as a new top-level file in `$HOME`. Walking
///   deeper measures the desktop environment, not the tool — and the tool cannot even *name* a deep path
///   inside `$HOME` without reading `$HOME`, which F3.6's static check forbids.
///
/// **What this gives up, stated rather than implied:** a write buried deep inside an existing `$HOME`
/// subtree would not be seen. That is a genuine narrowing of the behavioural claim — and it is the correct
/// trade, because the alternative was a claim that could only be sustained by excusing real paths.
fn watched_paths() -> Vec<(PathBuf, usize, &'static str)> {
    let mut paths: Vec<(PathBuf, usize, &'static str)> = Vec::new();

    // Temp directories: walked fully. A footprint from a careless implementation lands here.
    for var in ["TMPDIR"] {
        if let Some(v) = std::env::var_os(var) {
            paths.push((PathBuf::from(v), FULL_DEPTH, "temporary directory"));
        }
    }
    for p in ["/tmp", "/var/tmp"] {
        paths.push((PathBuf::from(p), FULL_DEPTH, "temporary directory"));
    }

    // User-configuration roots: depth 1. A settings/MRU footprint is a NEW ENTRY here.
    for var in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
    ] {
        if let Some(v) = std::env::var_os(var) {
            paths.push((
                PathBuf::from(v),
                1,
                "user-configuration root (depth 1: a new entry, not its contents)",
            ));
        }
    }

    // A path that exists but does not exist yet on disk (e.g. /var/tmp on a minimal container) is not
    // watchable; dropping it is safe because it cannot contain a footprint we would miss elsewhere.
    paths.retain(|(p, _, _)| p.exists());
    paths.sort_by(|a, b| a.0.cmp(&b.0));
    paths.dedup_by(|a, b| a.0 == b.0);
    paths
}

/// Depth used for locations that deserve a complete walk (temp directories).
const FULL_DEPTH: usize = 8;

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
    const MAX_ENTRIES: usize = 20_000;

    let watched = watched_paths();
    println!("F3.6 behavioural footprint check");
    println!(
        "  watched {} locations (<= {MAX_ENTRIES} entries each):",
        watched.len()
    );
    for (p, depth, why) in &watched {
        println!("    {} (depth {depth}) — {why}", p.display());
    }

    assert!(
        !watched.is_empty(),
        "the watched set is EMPTY, so a 'no change' result would prove nothing. This test's evidence \
         depends on actually watching something."
    );

    let mut before = Vec::new();
    let mut truncated_paths = Vec::new();
    for (p, depth, _) in &watched {
        let (set, truncated) = snapshot(p, *depth, MAX_ENTRIES);
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

    assert!(
        truncated_paths.is_empty(),
        "the snapshot hit its bound for {:?}. The 'no footprint observed' result would then cover only the \
         walked part, and a footprint in the unwalked remainder would be invisible. Raise MAX_ENTRIES \
         deliberately (and say so) rather than letting the check silently weaken.",
        truncated_paths
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
        .map(|(p, depth, _)| (p.clone(), snapshot(p, *depth, MAX_ENTRIES).0))
        .collect();

    let mut changes = Vec::new();
    for ((path, before_set), (_, after_set)) in before.iter().zip(after.iter()) {
        for added in after_set.difference(before_set) {
            changes.push(format!("{}: APPEARED {}", path.display(), added));
        }
    }

    // CHANGES ARE NOT EXCUSED HERE.
    //
    // An earlier revision carried an ENVIRONMENT_WRITES list naming CI-runner paths, because deep-walking a
    // live `$HOME` caught the OS writing to itself. That list was the wrong shape of fix: it grows forever
    // and ends by excusing exactly the writes it exists to catch. The root cause is fixed instead — depth is
    // now per location (see `watched_paths`), so the OS's own activity in a shared profile is not watched in
    // the first place, and anything this test DOES observe is attributed to the exercise without excuses.
    for c in changes.iter().take(40) {
        println!("  CHANGE {c}");
    }
    assert!(
        changes.is_empty(),
        "{} change(s) appeared in the watched paths during the exercise. G11 forbids writing files on the \
         host. If a change is caused by the test environment rather than the tool, the fix is to narrow \
         WHAT IS WATCHED and say so — not to add an exception for it. See the CHANGE lines above.",
        changes.len()
    );

    println!("  no footprint observed in the watched set");

    // --- the negative half: this mechanism must DETECT a planted write -----------------------------
    //
    // Without this, the test above is satisfied by a snapshot function that observes nothing.
    // The probe needs a directory it is allowed to write into, and it must be one whose depth is FULL so a
    // new file at its top level is observed. Prefer a temporary directory: writing there is what the probe
    // is for, and it is already on the watched list.
    let probe_dir_found = watched
        .iter()
        .find(|(p, _, why)| p.is_dir() && why.contains("temporary"));
    assert!(
        probe_dir_found.is_some(),
        "no temporary directory is watched, so the detection probe has nowhere to plant a write and the \
         'no footprint observed' result above cannot be distinguished from observing nothing"
    );
    let probe_dir = probe_dir_found
        .map(|(p, _, _)| p.clone())
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let (probe_before, _) = snapshot(&probe_dir, FULL_DEPTH, MAX_ENTRIES);

    let probe_file = probe_dir.join(format!("f36_detection_probe_{}", std::process::id()));
    let wrote = std::fs::write(&probe_file, b"planted");
    assert!(
        wrote.is_ok(),
        "the detection probe must be able to write to {} — without it, 'no footprint observed' cannot be          distinguished from 'the mechanism observes nothing'",
        probe_dir.display()
    );

    let (probe_after, _) = snapshot(&probe_dir, FULL_DEPTH, MAX_ENTRIES);
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
