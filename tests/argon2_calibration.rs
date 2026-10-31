//! **B1 calibration probe** — measure Argon2id cost on this hardware (T-0004 phase 0).
//!
//! Bruce's threat model makes this a blocker: the vault format may not be frozen until the KDF cost is
//! **measured**, not guessed. The earlier `rust-version = "1.75"` claim in this project was false for months
//! because nobody measured it; this probe exists so the same mistake is not repeated with vault parameters.
//!
//! # Why the numbers matter here specifically
//!
//! This host is a **2-core Celeron N4020**. RFC 9106's first recommendation is `m = 2 GiB, p = 4`:
//!
//! * `p = 4` is **impossible** — there are two cores.
//! * 2 GiB is not reliably allocatable.
//!
//! So the naive "use the RFC" answer is unimplementable, and the naive "use what feels fast on my machine"
//! answer is either useless against an attacker or unusable for a user. **Parameters must be chosen for the
//! weakest device we support.** This probe produces the data to do that.
//!
//! # How to run
//!
//! ```text
//! cargo test --release --locked -p tokengen --test argon2_calibration -- --nocapture --ignored
//! ```
//!
//! It is `#[ignore]`d so it never runs in the normal gate: a calibration probe that runs on every CI job
//! would be measuring the CI runner, not the target hardware.

// A calibration probe's entire output is its measurements; printing is the point, and this is a test binary
// that ships nothing. Scoped allow, following the house pattern in the other integration tests.
#![allow(clippy::print_stdout)]

use argon2::{Algorithm, Argon2, Params, Version};
use std::time::{Duration, Instant};

/// A realistic passphrase length. Argon2id's cost is dominated by memory and iterations, not by a few bytes
/// of input, but the figure is stated so nobody assumes otherwise.
const PASSPHRASE: &[u8] = b"correct horse battery staple";
const SALT: [u8; 16] = *b"saltsaltsaltsalt";
const OUT_LEN: usize = 32;

/// One candidate parameter set.
struct Candidate {
    label: &'static str,
    m_kib: u32,
    t: u32,
    p: u32,
}

/// Run one configuration `runs` times and return the median.
fn measure(c: &Candidate, runs: usize) -> Option<(Duration, u32)> {
    let params = Params::new(c.m_kib, c.t, c.p, Some(OUT_LEN)).ok()?;
    let alg = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut times = Vec::with_capacity(runs);
    let mut out = [0u8; OUT_LEN];

    for _ in 0..runs {
        let start = Instant::now();
        alg.hash_password_into(PASSPHRASE, &SALT, &mut out).ok()?;
        times.push(start.elapsed());
    }

    times.sort_unstable();
    let median = times[times.len() / 2];

    // Cheapest remembered: the work factor is m*t. Report it so two rows with very different shapes can be
    // compared rather than read as "bigger memory = better" unconditionally.
    Some((median, c.m_kib.saturating_mul(c.t)))
}

#[test]
#[ignore = "calibration probe — run deliberately against the target hardware, not in the normal gate"]
fn argon2id_cost_on_this_hardware() {
    // The candidate space, deliberately spanning the RFC's two recommendations and the shapes that are
    // actually implementable on two cores.
    let candidates = [
        // RFC 9106 SECOND recommendation, exact.
        Candidate {
            label: "RFC-9106 #2 (m=64MiB t=3 p=4)",
            m_kib: 64 * 1024,
            t: 3,
            p: 4,
        },
        // Same work, but p limited to the cores this machine has.
        Candidate {
            label: "64MiB t=3 p=2",
            m_kib: 64 * 1024,
            t: 3,
            p: 2,
        },
        Candidate {
            label: "64MiB t=1 p=2",
            m_kib: 64 * 1024,
            t: 1,
            p: 2,
        },
        Candidate {
            label: "128MiB t=3 p=2",
            m_kib: 128 * 1024,
            t: 3,
            p: 2,
        },
        Candidate {
            label: "256MiB t=1 p=2",
            m_kib: 256 * 1024,
            t: 1,
            p: 2,
        },
        Candidate {
            label: "256MiB t=2 p=2",
            m_kib: 256 * 1024,
            t: 2,
            p: 2,
        },
        Candidate {
            label: "512MiB t=1 p=2",
            m_kib: 512 * 1024,
            t: 1,
            p: 2,
        },
        // RFC 9106 FIRST recommendation, p reduced. Expected to fail or be very slow here.
        Candidate {
            label: "RFC-9106 #1 (m=1GiB t=1 p=2)",
            m_kib: 1024 * 1024,
            t: 1,
            p: 2,
        },
    ];

    println!();
    println!("Argon2id calibration — tokengen vault (B1)");
    println!(
        "  host cores / threads: {}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0)
    );
    println!(
        "  passphrase length: {} bytes; salt: {} bytes; out: {} bytes",
        PASSPHRASE.len(),
        SALT.len(),
        OUT_LEN
    );
    println!();
    println!(
        "  {:<32} {:>12} {:>12}",
        "configuration", "median", "work (KiB*t)"
    );
    println!("  {:-<32} {:-<12} {:-<12}", "", "", "");

    let mut results: Vec<(String, Duration, u32)> = Vec::new();

    for c in &candidates {
        // 3 runs, median. Enough to damp scheduling noise without making the probe take a minute.
        match measure(c, 3) {
            Some((d, work)) => {
                println!("  {:<32} {:>10.3}s {:>12}", c.label, d.as_secs_f64(), work);
                results.push((c.label.to_string(), d, work));
            }
            None => {
                println!("  {:<32} {:>12}", c.label, "FAILED");
            }
        }
    }

    println!();

    // What the numbers mean. These thresholds are stated so a reader can disagree with them, rather than
    // hidden inside a comparison.
    const TARGET_MIN: Duration = Duration::from_millis(250); // below this, suspect too cheap
    const TARGET_MAX: Duration = Duration::from_millis(2000); // above this, users resent it

    let acceptable: Vec<_> = results
        .iter()
        .filter(|(_, d, _)| *d >= TARGET_MIN && *d <= TARGET_MAX)
        .collect();

    println!("  acceptable window: {:?} .. {:?}", TARGET_MIN, TARGET_MAX);
    if acceptable.is_empty() {
        println!("  RESULT: no candidate falls in the acceptable window on THIS hardware.");
    } else {
        println!("  candidates in window:");
        for (label, d, work) in &acceptable {
            println!("    {label:<32} {:.3}s (work {work})", d.as_secs_f64());
        }
        // Recommend the one with the most work inside the window — the most expensive an attacker must pay
        // while a user still waits an acceptable time.
        // The branch above already established this is non-empty; expressed without `unwrap` because the
        // workspace denies it.
        if let Some(best) = acceptable.iter().max_by_key(|(_, _, work)| *work) {
            println!();
            println!(
                "  MOST WORK WITHIN BUDGET: {} — {:.3}s",
                best.0,
                best.1.as_secs_f64()
            );
        }
    }

    // The probe always reports; it fails only if NOTHING ran, which would mean the measurement is invalid.
    assert!(
        !results.is_empty(),
        "no Argon2id configuration could be measured; the calibration is invalid"
    );
}
