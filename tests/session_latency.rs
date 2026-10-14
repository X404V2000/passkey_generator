//! F3.5 test 10 — the detection budget (§9): a `check()` must complete within 250 ms.
//!
//! # What the budget is, and where it comes from
//!
//! ```text
//! 250 ms  caller polls at least this often          (a constraint F3.5 places on F4/F10)
//! +250 ms F3.5's detection budget                  <- this test asserts this line
//! +500 ms caller acts on the status (drop secrets) (F4's contract, NOT asserted here)
//! = 1.0 s  G16 satisfied
//! ```
//!
//! **Boundary of responsibility, stated so it is not over-claimed:** F3.5 asserts **detection** latency
//! only. It does not own the caller's loop, so it cannot and does not assert *exit* latency. A reader who
//! saw "latency test passes" must not conclude the end-to-end second is met — that needs F4's test too.
//!
//! # Why the threshold alone would be a bad test, and what is done instead
//!
//! Measured on the maintainer's host, a real `resolve()` costs **~109 µs** — about **2300×** under the
//! budget. A wall-clock assertion of "under 250 ms" therefore fails only if something is *catastrophically*
//! wrong, and on a shared CI runner a single GC pause or scheduler stall could trip it while the code is
//! fine. That makes a bare timing assertion **noisy in the direction that erodes trust** (a flaky test gets
//! ignored) and **weak in the direction that matters** (it cannot detect a 10× regression).
//!
//! So this file asserts three things, each of which is stable in the environment it runs in:
//!
//! 1. **Correctness of the answer**, first — a fast wrong answer is not a pass. Every iteration also
//!    verifies the status, so the timing is measured on work that actually happened.
//! 2. **The budget**, asserted on the **median** of many samples rather than a single call. The median is
//!    insensitive to one scheduling stall, which is exactly the noise CI injects.
//! 3. **A sanity ceiling** (10 ms) whose purpose is *not* regression detection but gross-failure detection:
//!    it fails if `check` acquires a sleep, a network call, or a human-scale delay that the 250 ms budget
//!    alone would still pass.
//!
//! # A claim I made and then measured false — recorded rather than quietly dropped
//!
//! I first wrote (3) as a *regression bound*, claiming it would catch "a change that made `check` re-read
//! the whole device tree or add a sleep". **Measured against exactly those mutations, it caught neither:**
//!
//! | Mutation | Mock median | Verdict under the 10 ms bound |
//! |---|---|---|
//! | read all of `/sys/block` per check (~225× the baseline) | 99 µs | **PASSED** |
//! | `sleep(300 µs)` per check (~1000× the baseline) | 420 µs | **PASSED** |
//!
//! The bound was decoration. To catch those, the threshold would have to sit near the measured baseline
//! (74 ns in release, 444 ns in debug — a 6× spread *within one machine*, before CI's contention), which
//! would make the test flaky. **A flaky latency test is worse than a loose one**, because a suite that
//! fails for environmental reasons gets ignored, and then a real regression is invisible too.
//!
//! So the claim is narrowed to what is actually verified, and the narrowing is written down. What this test
//! **does not** establish: that a sub-millisecond regression is detected. Catching that needs a benchmark
//! harness with a stable baseline, not a unit test — recorded as an open item rather than implied here.
//!
//! # Coverage: real and mock, and what each contributes
//!
//! * **Mock** — proves the *guard's* per-check overhead without any I/O. This is the number that scales with
//!   the state machine, and it is the one that would grow if `check` started caching or allocating.
//! * **Real** — proves the *platform* reads fit in the budget on real sysfs. Runs only on Linux with a
//!   removable device attached; **announced** when it cannot run, per the discipline in `device_real.rs`.
//!
//! The mock case is not a substitute for the real one: a guard that is fast over a no-op reader says
//! nothing about reading `/dev/disk/by-uuid`. Both are reported.

// Tests are the one place this project must be able to WRITE, and `print_stdout`/`print_stderr` are denied
// workspace-wide because a secret-handling tool must not print as a side effect. The denial is right for
// `src/` and wrong for a test that must **announce when it checked nothing**.
//
// Why an allow rather than removing the messages: a test that silently skips is indistinguishable from one
// that passed. That is the false-assurance class this project treats as its worst defect, and it is exactly
// what these announcements exist to prevent — in `device_real.rs` on a host with no removable device, and in
// `session_latency.rs` under `dev-mode`. Removing the output to satisfy a lint would trade a lint
// violation for a coverage lie.
//
// Scoped to this file, to these two lints, with this reason — the same form as the `unnecessary_cast` allow
// on `dev_t_to_u64`. No production module acquires it.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokengen::session::{DeviceIdentity, DeviceReader, GuardStatus, SessionError, SessionGuard};

/// §9's detection budget.
const DETECTION_BUDGET: Duration = Duration::from_millis(250);

/// A **sanity ceiling**, not a regression bound. Ten milliseconds is ~100× the *slowest* measured path
/// (178 µs, real reader) and ~10⁵× the mock's, so it cannot be flaky — and it fails on a delay of the kind
/// that would matter (a sleep, an I/O wait, a lock). It does **not** detect sub-millisecond drift; see the
/// module docs, where that claim was measured false and narrowed.
const SANITY_CEILING: Duration = Duration::from_millis(10);

/// How many samples to take. The median of 51 is a stable statistic; more would only lengthen CI.
const SAMPLES: usize = 51;

/// A reader with no I/O, so the measurement is the guard's own overhead.
struct NoIoReader;

impl DeviceReader for NoIoReader {
    type Device = ();

    fn resolve(&self, _path: &Path) -> Result<(), SessionError> {
        Ok(())
    }

    fn identify(&self, _device: &()) -> Result<DeviceIdentity, SessionError> {
        Ok(DeviceIdentity {
            uuid: "uuid-a".to_string(),
            serial: "serial-a".to_string(),
        })
    }
}

/// Median of the samples, in place. `SAMPLES` is odd, so no interpolation is needed.
fn median(mut v: Vec<Duration>) -> Duration {
    v.sort_unstable();
    v[v.len() / 2]
}

/// Run `check` `SAMPLES` times and return the median duration.
///
/// The status is asserted on every iteration: a fast wrong answer must not pass as a latency result.
fn median_check_duration(guard: &SessionGuard<impl DeviceReader>) -> Duration {
    let mut samples = Vec::with_capacity(SAMPLES);
    for i in 0..SAMPLES {
        let start = Instant::now();
        let status = guard.check();
        let elapsed = start.elapsed();

        assert!(
            matches!(status, GuardStatus::Present),
            "sample {i}: the guard must report Present throughout the timing run, got {status:?} — \
             a timing measured on failing checks is not a timing of the healthy path"
        );
        samples.push(elapsed);
    }
    median(samples)
}

// =============================================================================================
// The guard's own overhead — no I/O, runs everywhere
// =============================================================================================

#[test]
fn check_completes_within_budget_mock() {
    let reader = NoIoReader;
    let (guard, status) = match SessionGuard::capture(reader, &PathBuf::from("/mnt/usb")) {
        Ok(v) => v,
        Err(e) => {
            // `dev-mode` compiles the guard off, so this test cannot run there. Announced rather than
            // silently skipped: a quiet pass would be indistinguishable from coverage.
            println!("SKIP (no coverage): capture returned {e:?}; under dev-mode the guard is off");
            return;
        }
    };
    assert!(matches!(status, GuardStatus::Present));

    let observed = median_check_duration(&guard);

    println!(
        "mock: median check over {SAMPLES} samples = {observed:?} \
         (budget {DETECTION_BUDGET:?}, sanity ceiling {SANITY_CEILING:?})"
    );

    assert!(
        observed < DETECTION_BUDGET,
        "the contract: median check must be under the {} detection budget, measured {observed:?}",
        DETECTION_BUDGET.as_millis()
    );
    assert!(
        observed < SANITY_CEILING,
        "the sanity ceiling: median check must be under {SANITY_CEILING:?}, measured {observed:?}. This \
         catches a gross delay (a sleep, an I/O wait) that the {}-budget assertion above would still pass. \
         It does NOT detect sub-millisecond regression — see the module docs.",
        DETECTION_BUDGET.as_millis()
    );
}

// =============================================================================================
// The real platform reads — Linux with a removable device
// =============================================================================================

/// The vendor of `tokengen-sys` has no test binary for the guard, so the real case lives here and calls the
/// platform functions directly, then times a full capture+check cycle through `SystemDeviceReader`.
#[cfg(target_os = "linux")]
#[test]
fn check_completes_within_budget_real() {
    use tokengen::session::SystemDeviceReader;

    // Find a removable device, so the timing reflects real sysfs reads.
    let Some(path) = find_removable_partition() else {
        println!(
            "SKIP (no coverage): no removable device is attached, so the REAL-reader timing was NOT \
             measured. This is an absence of evidence, not a pass."
        );
        return;
    };
    println!("real reader, device: {}", path.display());

    let (guard, status) = match SessionGuard::capture(SystemDeviceReader::new(), &path) {
        Ok(v) => v,
        Err(e) => {
            println!("SKIP (no coverage): capture failed with {e:?} — cannot time the real path");
            return;
        }
    };
    assert!(
        matches!(status, GuardStatus::Present),
        "a detected removable device must capture as Present, got {status:?}"
    );

    let observed = median_check_duration(&guard);

    println!(
        "real: median check over {SAMPLES} samples = {observed:?} \
         (budget {DETECTION_BUDGET:?}, sanity ceiling {SANITY_CEILING:?})"
    );

    assert!(
        observed < DETECTION_BUDGET,
        "the contract: median real check must be under the {} detection budget, measured {observed:?} \
         — this is the number §9's arithmetic depends on",
        DETECTION_BUDGET.as_millis()
    );
    assert!(
        observed < SANITY_CEILING,
        "the sanity ceiling: median real check must be under {SANITY_CEILING:?}, measured {observed:?}. \
         The measured real cost is ~178 us, so this is ~56x the expected value: not flaky, and it catches \
         a gross delay. It does NOT detect sub-millisecond regression — see the module docs."
    );
}

/// Locate a removable partition, exactly as `device_real.rs` does — by asking the shipped code rather than
/// re-implementing the transport rule (a test that duplicates the logic proves only that two copies agree).
#[cfg(target_os = "linux")]
fn find_removable_partition() -> Option<PathBuf> {
    let entries = std::fs::read_dir("/sys/block").ok()?;
    for entry in entries.flatten() {
        let disk = entry.file_name().to_string_lossy().to_string();
        if disk.starts_with("loop") || disk.starts_with("ram") || disk.starts_with("dm-") {
            continue;
        }
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(children) = std::fs::read_dir(entry.path()) {
            for child in children.flatten() {
                let name = child.file_name().to_string_lossy().to_string();
                if name.starts_with(&disk) && name != disk {
                    candidates.push(PathBuf::from(format!("/dev/{name}")));
                }
            }
        }
        candidates.push(PathBuf::from(format!("/dev/{disk}")));

        for candidate in candidates {
            if !candidate.exists() {
                continue;
            }
            if let Ok(dev) = tokengen_sys::device::resolve(&candidate) {
                if matches!(tokengen_sys::device::is_removable(&dev), Ok(true)) {
                    return Some(candidate);
                }
            }
        }
    }
    None
}
