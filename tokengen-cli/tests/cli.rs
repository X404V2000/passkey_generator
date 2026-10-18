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

/// The exit codes that legitimately mean "the guard will not permit a session here".
///
/// **This is not a relaxation — it is the claim made honest.** It took two corrections to get here, and the
/// second one was exposed by the FREEZE PROCEDURE, not by CI:
///
/// 1. **DEFECT-007 (platform).** The first version asserted exit 3 everywhere. On macOS and Windows there is
///    no device backend (F3.7), so capture fails with `NotSupported` → **4**. Asserting only 3 encoded
///    "every platform has a backend", which is false.
/// 2. **This correction (filesystem).** The second version asserted 3 on Linux. But AM-007 added a second
///    legitimate Linux outcome: a working directory with **no block device at all** (tmpfs, overlay, network
///    mount) is `NoBlockDevice` → **4**, because there is no device to have been swapped. So on Linux the code
///    depends on **which filesystem the checkout sits on**:
///    - a real disk that is fixed → `NotOnRemovableDevice` → **3**
///    - a tmpfs / overlay → `NoBlockDevice` → **4**
///
///    CI checks out onto a real disk and saw 3. The anchored freeze run extracts to `/tmp` — a tmpfs — and
///    saw 4. **Both are correct; the test was asserting WHERE IT RAN.**
///
/// **The invariant that holds everywhere** is asserted below and is the one that carries the weight: the
/// exit is non-zero, distinguishable from a usage error (2), and stdout is empty.
fn is_guard_refusal(code: i32) -> bool {
    code == 3 || code == 4
}

/// **The guard refuses from a non-removable working directory, and no secret reaches stdout.**
///
/// This is the user-outcome form of the library's fail-closed property. In the library it is a test
/// assertion; here it is what a person actually experiences.
#[test]
fn refusal_exits_nonzero_and_prints_no_secret() {
    let (code, stdout, stderr) = cli(&["generate", "-l", "32"]);

    assert!(
        is_guard_refusal(code),
        "a guard refusal must exit 3 (a real device that is not removable) or 4 (no device backend, or no \
         block device at all). Got {code}. It must never share a code with a usage error (2), and must never \
         be 0 or 1. stdout={stdout:?} stderr={stderr:?}"
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

    assert_eq!(usage_code, 2, "a usage error must exit 2 on every platform");
    assert!(
        is_guard_refusal(security_code),
        "a guard refusal must exit 3 or 4 depending on the platform AND the filesystem; got {security_code}"
    );
    // The property that matters and holds everywhere: the two are DISTINGUISHABLE by a script.
    assert_ne!(
        usage_code, security_code,
        "usage and security outcomes must not share an exit code, or a caller cannot tell a bad flag from \
         a missing device"
    );
    assert_ne!(security_code, 0, "a refusal must never exit 0");
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

/// **The rule, with no exceptions: a non-zero exit leaves stdout EMPTY.**
///
/// Grace found the original violation: `status` exited 3 on a guard refusal while writing its report to
/// stdout. Nothing secret was involved — `status` prints device state, not a secret — so it was not a leak.
/// But it was an **exemption nobody had written down**, and an undocumented exemption is where the next leak
/// starts.
///
/// The fix was to remove the exemption rather than document it: `status` **succeeded at its job** (reporting
/// the guard's state), so it exits 0 and the state lives in its output. A caller that wants the guard's
/// verdict runs `generate`, whose exit code is the verdict.
///
/// This test enforces the single rule across **every command and every failure mode**, so no future
/// subcommand can quietly reintroduce an exception.
#[test]
fn non_zero_exit_always_leaves_stdout_empty() {
    // Failing invocations: guard refusals, usage errors, and malformed arguments.
    let failing: &[&[&str]] = &[
        &["generate"],
        &["generate", "-l", "0"],
        &["generate", "-c", "nope"],
        &["generate", "--bogus"],
        &["generate", "-l"],
        &["generate", "-c"],
        &["not-a-command"],
        &[],
    ];

    for args in failing {
        let (code, stdout, stderr) = cli(args);
        assert_ne!(code, 0, "{args:?} was expected to fail; if it now succeeds, add it to the succeeding list instead");
        assert!(
            stdout.is_empty(),
            "RULE VIOLATED: {args:?} exited {code} but wrote to stdout: {stdout:?}. A non-zero exit must \
             leave stdout empty, with no exceptions — an exemption is where the next leak starts."
        );
        assert!(
            !stderr.is_empty(),
            "{args:?} failed without an explanation on stderr"
        );
    }

    // Succeeding invocations: they must NOT be silent on stdout, or the rule would be satisfiable by a
    // command that simply never reports.
    let succeeding: &[&[&str]] = &[&["status"], &["help"], &["version"]];
    for args in succeeding {
        let (code, stdout, _) = cli(args);
        assert_eq!(
            code, 0,
            "{args:?} must exit 0: it reports, and reporting is its job"
        );
        assert!(!stdout.is_empty(), "{args:?} exited 0 but said nothing");
    }
}
