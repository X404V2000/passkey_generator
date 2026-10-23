//! F3.9 acceptance criteria — the trust-path and disclosure requirements.
//!
//! These are checked here rather than asserted in prose, because the whole content of R7 is that
//! **documentation does not prevent a user installing the wrong tool**. Criterion 4 in particular is the
//! mechanical form of "out of the trust path": if a `passkey-gen` console entry point ever reappears, this
//! fails.
//!
//! The checks read the repository's own files. They do not need network, a Python environment, or a
//! toolchain, so they run in every CI job on every platform.

use std::fs;
use std::path::Path;

/// Root of the workspace, from the manifest directory cargo sets for integration tests.
fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = root().join(rel);
    match fs::read_to_string(&p) {
        Ok(text) => text,
        Err(e) => {
            // A required repository file that cannot be read is a failure of this test's precondition, not
            // an incidental error to be swallowed: every criterion below reads one of these files.
            // Expressed as an equality assertion rather than `panic!`, which the workspace lint denies.
            let missing = format!("{} could not be read: {e}", p.display());
            assert_eq!(
                missing,
                String::new(),
                "a required repository file is unreadable"
            );
            String::new()
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Criterion 4 (load-bearing): no runnable command is installed.
// ---------------------------------------------------------------------------------------------

/// **`pip install .` must create no console script.**
///
/// The entry point `passkey-gen = "passkey_gen.cli:main"` bound the installed command to the legacy Python
/// implementation, which **degrades silently where G3 requires a refusal** (see `legacy/python/README.md`).
/// That is risk R7: a user running `pip install .` received a tool that cannot honour this project's first
/// invariant.
///
/// The fix is not a warning in the README — it is the absence of the entry point. This test is what makes
/// that absence enforced rather than intended.
#[test]
fn no_console_script_entry_point_is_declared() {
    let manifest = read("pyproject.toml");

    // `[project.scripts]` is the PEP 621 table that produces console commands on install.
    //
    // Matched on DIRECTIVES, not on the whole file: the manifest carries a comment explaining why the table
    // is absent, and that comment necessarily contains the string. A whole-file `contains` would fail on its
    // own explanation — the same blunt-match mistake that let cfg_check.sh invert prose (DEFECT-002's
    // family), so it is not repeated here.
    let declares_entry_points = manifest.lines().any(|line| {
        let directive = line.trim();
        !directive.starts_with('#') && directive.starts_with("[project.scripts]")
    });
    assert!(
        !declares_entry_points,
        "pyproject.toml declares [project.scripts]. Any entry point here installs a runnable command, and \
         the only implementation that could back one today is the legacy Python, which violates G3. The \
         Rust CLI does not exist yet (F4); installing NO command is honest, installing the wrong one is not. \
         See F3.9 and D-P12."
    );

    // And the specific legacy binding must not reappear under any other spelling. Directive lines only —
    // the explanation comment names it too.
    let binds_legacy = manifest.lines().any(|line| {
        let directive = line.trim();
        !directive.starts_with('#') && directive.contains("passkey_gen.cli")
    });
    assert!(
        !binds_legacy,
        "pyproject.toml references the legacy `passkey_gen.cli`. That module is out of the trust path \
         (legacy/python/), and no packaging path may bind to it."
    );
}

/// **No packaging path may collect the legacy package.**
///
/// `[tool.setuptools.packages.find] where = ["src"]` is now safe *because* the legacy package no longer
/// lives under `src/`. If it were moved back — or `where` widened — the package would be installed again and
/// R7 would return in a form no notice would prevent.
#[test]
fn packaging_does_not_reach_the_legacy_package() {
    let manifest = read("pyproject.toml");

    assert!(
        manifest.contains("where = [\"src\"]"),
        "the package finder must keep `where = [\"src\"]`; a wider root could collect the legacy package"
    );
    for banned in ["legacy", "passkey_gen"] {
        // The finder block must not name the legacy tree. (The word appears in comments explaining its
        // removal, so this checks the directive lines rather than the whole file.)
        for line in manifest.lines() {
            let directive = line.trim();
            if directive.starts_with('#') {
                continue;
            }
            assert!(
                !(directive.contains("where =") && directive.contains(banned)),
                "the package finder directive must not include `{banned}`: {directive}"
            );
        }
    }

    // The legacy package is physically outside `src/`, which is what makes the finder safe.
    assert!(
        !root().join("src/passkey_gen").exists(),
        "src/passkey_gen still exists. The legacy implementation must live under legacy/python/ so that no \
         `src`-rooted packaging path can collect it. See F3.9 §4."
    );
    // AM-009: the directory stays — but only the REFERENCE files survive. Its presence is still asserted,
    // because the WebAuthn/CBOR encoding is the only end-to-end reference the Rust implementation will have.
    assert!(
        root().join("legacy/python/passkey_gen").exists(),
        "legacy/python/passkey_gen is missing. The WebAuthn/CBOR reference is kept deliberately (it is the \
         only end-to-end reference the Rust implementation will have), but it must be where it says it is."
    );

    // AM-009: the G3-violating RUNTIME must be gone. Asserting its absence is what makes this guard stronger
    // than it was — before AM-009 the test asserted the whole prototype was present, including the code that
    // swallowed `mlock` failures.
    for gone in [
        "legacy/python/passkey_gen/memory.py",
        "legacy/python/passkey_gen/cli.py",
        "legacy/python/passkey_gen/clipboard.py",
        "legacy/python/passkey_gen/display.py",
        "legacy/python/passkey_gen/process.py",
        "legacy/python/passkey_gen/generator.py",
    ] {
        assert!(
            !root().join(gone).exists(),
            "{gone} has reappeared. The Python RUNTIME was removed in AM-009 because it violated G3 \
             (swallowed `mlock` failures, false assurance). Only the webauthn/charsets REFERENCE may exist \
             under legacy/python/."
        );
    }

    // The reference itself must still be present — otherwise this directory has no reason to exist and the
    // reference F4/F8 depends on has silently disappeared.
    assert!(
        root().join("legacy/python/passkey_gen/webauthn.py").exists(),
        "legacy/python/passkey_gen/webauthn.py is missing. It is the WebAuthn/CBOR reference the Rust \
         implementation is checked against (AM-009)."
    );
    assert!(
        root().join("legacy/python/README.md").exists(),
        "legacy/python/README.md is missing. The demotion must be documented where the code is, stating that \
         it is unmaintained and why it violates G3 — otherwise a reader finds unexplained Python."
    );
}

// ---------------------------------------------------------------------------------------------
// Criteria 1–3: SECURITY.md exists and says what it must
// ---------------------------------------------------------------------------------------------

/// **`SECURITY.md` exists and names a private route and a response window.**
///
/// A policy that says "contact us" without a private channel tells a researcher their finding will be
/// mishandled. A policy without a window tells them nothing about whether anyone is listening.
#[test]
fn security_policy_names_private_route_and_response_window() {
    assert!(
        root().join("SECURITY.md").exists(),
        "SECURITY.md must exist at the repository root (release-gate item)"
    );
    let policy = read("SECURITY.md");
    let lower = policy.to_lowercase();

    // A private channel, not merely "open an issue".
    assert!(
        lower.contains("private"),
        "SECURITY.md must name a PRIVATE reporting route; a public-only route exposes the vulnerability"
    );

    // A stated response window, in days.
    assert!(
        lower.contains("within 7 days") || lower.contains("7 days"),
        "SECURITY.md must state a response window, so a reporter knows anyone is listening"
    );

    // The pointer to the honest-limits surface, so a reporter can tell a defect from a documented limit.
    assert!(
        lower.contains("cannot do"),
        "SECURITY.md must point to README.md's \"What This Tool Cannot Do\", so a reporter can distinguish \
         a defect from a documented limitation"
    );

    // It must not promise payment it is not making.
    assert!(
        lower.contains("no bounty") || lower.contains("not be paid"),
        "SECURITY.md must state plainly that there is no bounty rather than leaving it ambiguous"
    );
}

/// **The policy must state the platform gap, so it is not reported as a vulnerability.**
///
/// Windows and macOS have no backend and refuse. That is known, recorded, and is F3.7 — but a tester who
/// finds "it does not work on macOS" will report it unless the policy says so first.
#[test]
fn security_policy_states_the_platform_gap() {
    let policy = read("SECURITY.md").to_lowercase();
    assert!(
        policy.contains("notsupported") || policy.contains("has been executed"),
        "SECURITY.md must state that Windows/macOS have no backend and have never been executed, so those \
         reports are recognised as known rather than treated as new findings"
    );
}

// ---------------------------------------------------------------------------------------------
// Criterion 7: one licence, named identically everywhere
// ---------------------------------------------------------------------------------------------

/// **All four locations name the same licence.**
///
/// Before F3.9 they disagreed: `LICENSE` said Apache-2.0, `pyproject.toml` said MIT, and both `Cargo.toml`s
/// said nothing. A consumer could not tell what terms applied. This is a legal inconsistency, not a
/// formatting one, and it is checked mechanically because it is exactly the kind of drift that reappears.
#[test]
fn licence_is_declared_consistently() {
    const EXPECTED: &str = "Apache-2.0";

    let pyproject = read("pyproject.toml");
    assert!(
        pyproject.contains(EXPECTED),
        "pyproject.toml must declare the licence as {EXPECTED}"
    );

    for manifest in ["Cargo.toml", "tokengen-sys/Cargo.toml"] {
        let text = read(manifest);
        let declared = text
            .lines()
            .find(|l| l.trim_start().starts_with("license"))
            .unwrap_or("");
        assert!(
            !declared.is_empty(),
            "{manifest} declares no licence; a consumer cannot tell what terms apply"
        );
        assert!(
            declared.contains(EXPECTED),
            "{manifest} declares `{declared}` but the project licence is {EXPECTED}; all four locations \
             must agree"
        );
    }

    // The LICENSE file itself must be the same licence as the manifests claim.
    let licence = read("LICENSE");
    assert!(
        licence.contains("Apache License"),
        "LICENSE must contain the Apache License text, matching the manifests"
    );

    // And the superseded claim must be gone.
    assert!(
        !pyproject.contains("MIT"),
        "pyproject.toml still mentions MIT. The licence contradiction is a legal defect, not a cosmetic \
         one: either every location agrees or a consumer cannot tell what terms apply."
    );
}

// ---------------------------------------------------------------------------------------------
// Criterion 8: the README presents no Python usage as supported
// ---------------------------------------------------------------------------------------------

/// **`README.md` must not tell a user to install or run the legacy Python.**
///
/// Before F3.9 the README was, from line 117 onward, the legacy tool's **usage guide**: `pip install -e .`,
/// then nine sections of `passkey-gen -l 64` examples. That is the most user-visible form of R7 — a reader
/// following the README got the tool that violates G3.
#[test]
fn readme_does_not_document_python_usage_as_supported() {
    let readme = read("README.md");

    // Every fenced/example invocation of the legacy CLI must be gone. The old README had many.
    for banned in [
        "./pass_/bin/passkey-gen",
        "passkey-gen -l ",
        "from passkey_gen import",
    ] {
        assert!(
            !readme.contains(banned),
            "README.md still shows `{banned}`. The legacy CLI is out of the trust path; documenting its use \
             is the most user-visible form of R7 — a reader following the README would install and run the \
             tool that violates G3."
        );
    }

    // `pip install` may appear ONLY in the explanation that it no longer installs a command. Checked by
    // requiring every occurrence to sit in a paragraph that also says it was removed, so the instruction
    // cannot creep back as an instruction.
    for line in readme.lines() {
        if line.contains("pip install") {
            let mentions_removal = line.contains("removed")
                || line.contains("no installable")
                || line.contains("used to");
            assert!(
                mentions_removal,
                "README.md mentions `pip install` without saying it no longer installs a command: {line}"
            );
        }
    }

    // And it must point a reader at the security policy and the honest limits.
    assert!(
        readme.contains("SECURITY.md"),
        "README.md must point to SECURITY.md so a reporter finds the disclosure route"
    );
}
