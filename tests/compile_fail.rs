//! Compile-fail harness for F3's type-level guarantees (blueprint tests 14–19).
//!
//! Run with `cargo test --test compile_fail`.
//!
//! # Two groups, deliberately
//!
//! Most cases must **fail** to compile, because the guarantee is that a particular
//! misuse is impossible. One case — `must_use_boundary_documented` — must
//! **compile**, because it pins the *boundary* of a guarantee: `#[must_use]` does
//! not catch destructuring, and a suite that only tested the catching direction
//! would leave that boundary unmeasured.
//!
//! Separating them matters. A single "these must fail" list cannot express a test
//! whose pass condition is successful compilation, and folding the inverse case
//! into a runtime test would lose the fact that the distinction is a *type-level*
//! one.
//!
//! # Why the two-test `!Send` split (tests 18 and 19)
//!
//! `handle_not_send_mechanism` proves the *language property* on local mirror
//! types: a `usize`-only struct is `Send`, and adding `PhantomData<*const ()>`
//! makes it not. `handle_not_send_real` asserts the property on the `LockHandle`
//! we actually ship.
//!
//! They are separate because they fail for different reasons and would go stale
//! differently. If `LockHandle` is refactored and loses the marker, only the
//! second should fail — and it should fail on its own. If they were one test, a
//! refactor of the mechanism would make it impossible to tell which property
//! broke. Either test alone is insufficient: the mechanism test alone does not
//! constrain the shipped type, and the real-type test alone would pass even if the
//! marker worked for some unrelated reason.

#[test]
fn compile_fail_guarantees() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/must_use_lock_status.rs");
    t.compile_fail("tests/compile-fail/secret_not_debug.rs");
    t.compile_fail("tests/compile-fail/secret_not_clone.rs");
    t.compile_fail("tests/compile-fail/handle_not_send_mechanism.rs");
    t.compile_fail("tests/compile-fail/handle_not_send_real.rs");
}

/// The inverse case: this file must COMPILE cleanly.
///
/// `trybuild::pass` compiles the file and asserts it succeeds *and* produces no
/// warnings — which is the assertion: `#[must_use]` does not fire for
/// `let (secret, _status) = Secret::new(buf);`.
#[test]
fn must_use_boundary_is_as_documented() {
    let t = trybuild::TestCases::new();
    t.pass("tests/compile-fail/must_use_boundary_documented.rs");
}
