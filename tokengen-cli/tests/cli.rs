//! F4 acceptance tests — the CLI's behaviour as a **real process**.
//!
//! # Why subprocesses
//!
//! Bruce's contract for F4 is about **exit codes**, and exit codes live in `main`. An in-process test with a
//! mock `DeviceReader` would test a *rearranged* program, not the one a user runs. So these tests execute
//! the built binary and inspect its actual exit status, stdout and stderr.
//!
//! Cargo sets `CARGO_BIN_EXE_tokengen` to the binary under test, so this runs the real thing.
//!
//! # What these tests can and cannot do
//!
//! On a machine whose working directory is on the **internal disk** (which is where CI runs, and where a
//! developer's checkout lives), the guard *correctly refuses*. So the tests that matter most here —
//! "a refusal exits non-zero and prints **no secret**" — are exactly reproducible, and are the ones F3.5
//! said F4 owes.
//!
//! The **success** path needs a removable device, which CI does not have. That test is **announced as
//! skipped**, never silently passed — the F3.5 discipline.

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::process::Command;

/// Run the CLI and return `(exit_code, stdout, stderr)`.
fn cli(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_tokengen"))
        .args(args)
        // A stable, non-removable cwd for the refusal tests: the manifest directory is inside the checkout,
        // which lives on the internal disk in every CI job and on a developer machine.
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output();

    match out {
        Ok(o) => (
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout).to_string(),
            String::from_utf8_lossy(&o.stderr).to_string(),
        ),
        Err(e) => {
            // A binary that cannot even be executed is a failure of the test setup, not a result.
            println!("could not run the CLI: {e}");
            (-1, String::new(), String::new())
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The contract that matters: a refusal must exit non-zero AND print nothing secret.
// ---------------------------------------------------------------------------------------------

/// **The guard refuses from a non-removable working directory, and no secret reaches stdout.**
///
/// This is the user-outcome form of the library's fail-closed property. In the library it is a test
/// assertion; here it is what a person actually experiences.
#[test]
fn refusal_exits_nonzero_and_prints_no_secret() {
    let (code, stdout, stderr) = cli(&["generate", "-l", "32"]);

    assert_eq!(
        code, 3,
        "a guard refusal must exit with the SECURITY code (3), distinct from a usage error (2). Got {code}. \
         stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.is_empty(),
        "SECURITY: the guard refused but stdout was not empty. A secret must never reach stdout on a \
         refusal. Got: {stdout:?}"
    );
    assert!(
        !stderr.is_empty(),
        "a refusal must explain itself on stderr rather than failing silently"
    );
}

/// **No exit path other than success may write to stdout.**
///
/// Checked across the whole set of failures a user can provoke, because the dangerous case is not the one
/// you tested — it is the error branch someone adds later that prints a partial result.
#[test]
fn no_failure_path_writes_to_stdout() {
    let cases: &[&[&str]] = &[
        &["generate", "-l", "0"],          // usage: zero length
        &["generate", "-c", "nope"],       // usage: unknown charset
        &["generate", "--bogus"],          // usage: unknown flag
        &["not-a-command"],                // usage: unknown command
        &[],                               // usage: no command
        &["generate", "-l", "notanumber"], // usage: unparseable length
    ];

    for args in cases {
        let (code, stdout, stderr) = cli(args);
        assert_ne!(code, 0, "{args:?} must not exit 0");
        assert!(
            stdout.is_empty(),
            "{args:?} wrote to stdout despite failing: {stdout:?}"
        );
        assert!(
            !stderr.is_empty(),
            "{args:?} failed without an explanation on stderr"
        );
    }
}

/// **Usage errors and security refusals are distinguishable by exit code.**
///
/// A caller scripting this tool must be able to tell "I passed a bad flag" from "the drive is gone": the
/// first is the caller's bug, the second is a security outcome that may need a different response.
#[test]
fn usage_and_security_errors_have_distinct_exit_codes() {
    let (usage_code, _, _) = cli(&["generate", "-c", "nope"]);
    let (security_code, _, _) = cli(&["generate"]);

    assert_eq!(usage_code, 2, "a usage error must exit 2");
    assert_eq!(security_code, 3, "a guard refusal must exit 3");
    assert!(
        usage_code != security_code,
        "usage and security outcomes must not share an exit code"
    );
}

// ---------------------------------------------------------------------------------------------
// Help and version must work without a guard.
// ---------------------------------------------------------------------------------------------

/// **`help` and `version` succeed everywhere, including where the guard refuses.**
///
/// A tool that cannot explain itself on a machine it refuses to run on is a tool that leaves the user
/// stuck. And neither command prints a secret, so neither needs the guard.
#[test]
fn help_and_version_work_without_a_guard() {
    for args in [&["help"][..], &["--help"], &["version"], &["--version"]] {
        let (code, stdout, _stderr) = cli(args);
        assert_eq!(
            code, 0,
            "{args:?} must succeed even where the guard refuses"
        );
        assert!(!stdout.is_empty(), "{args:?} produced no output");
    }

    let (_, help, _) = cli(&["help"]);
    assert!(
        help.contains("EXIT CODES"),
        "help must document the exit codes"
    );
    assert!(
        help.contains("COMMANDS"),
        "help must list commands, because the interface is subcommand-based"
    );
}

/// **`status` explains a refusal instead of requiring one to succeed.**
///
/// The point of `status` is to answer "why does it not run" — so it must work in exactly the situation it
/// describes. It prints no secret.
#[test]
fn status_reports_without_generating() {
    let (code, stdout, _) = cli(&["status"]);
    // Either the guard is fine (0) or it refuses (3); both are legitimate outcomes here. What must not
    // happen is exit 1 (crash) or a secret on stdout.
    assert!(
        code == 0 || code == 3 || code == 4,
        "`status` must report a guard outcome, not crash; got exit {code}"
    );
    assert!(!stdout.is_empty(), "`status` must say something");
    // A generated secret would be free of spaces; `status` output is prose. This is a weak but honest
    // check: status output contains words, a secret does not.
    assert!(
        stdout.contains("guard") || stdout.contains("tokengen"),
        "`status` must report on the guard, got: {stdout:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// The success path — needs a removable device.
// ---------------------------------------------------------------------------------------------

/// **Generation succeeds from a removable device.** Requires hardware CI does not have.
///
/// Announced as skipped rather than silently passed. The F3.5 discipline: a quiet pass is
/// indistinguishable from coverage.
#[test]
fn generation_succeeds_from_a_removable_device_if_present() {
    let workdir = std::env::var("TOKENGEN_USB_WORKDIR").ok();

    let Some(dir) = workdir else {
        println!(
            "SKIP (no coverage): TOKENGEN_USB_WORKDIR is not set. The success path needs a working \
             directory on a removable device, which CI does not have. Set the variable to a directory on a \
             USB drive to exercise it."
        );
        return;
    };

    let out = Command::new(env!("CARGO_BIN_EXE_tokengen"))
        .args(["generate", "-l", "32"])
        .current_dir(&dir)
        .output();

    let Ok(o) = out else {
        println!("SKIP (no coverage): could not run the CLI in {dir}");
        return;
    };

    assert_eq!(
        o.status.code(),
        Some(0),
        "generation from a removable device must succeed; stderr={}",
        String::from_utf8_lossy(&o.stderr)
    );
    let secret = String::from_utf8_lossy(&o.stdout);
    assert_eq!(
        secret.trim().chars().count(),
        32,
        "the secret must be exactly the requested length"
    );
    assert!(
        secret.chars().all(|c| c.is_ascii_alphanumeric()),
        "with the default charset the secret must be alphanumeric"
    );
}
