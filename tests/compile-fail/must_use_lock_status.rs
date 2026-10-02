// Test 14 — `#[must_use]` fires when the whole result is discarded.
//
// Assertion: this file must FAIL to compile because the `(Secret, MemoryLockStatus)`
// tuple returned by `Secret::new` is dropped without being read.
#![deny(unused_must_use)]

// `unused_must_use` is a *warning* by default, so the deny attribute above is what
// turns it into the compile error this test asserts. That is not a workaround — it
// is the same setting the release build uses, where warnings are errors. Without
// it, trybuild reports "expected test case to fail to compile, but it succeeded"
// while the warning is plainly present. That is how this test first failed, and how
// the missing `#[must_use]` on `Secret::new` was discovered.
//
// The deny is scoped to this file and covers only `unused_must_use`; a broader
// `deny(warnings)` would make the test fragile against unrelated lints changing.
//
// What this test does NOT establish: it does not show that every discard is
// caught. See test 15, which asserts the inverse and pins the boundary.

use tokengen::zeroize::Secret;

fn main() {
    // ERROR: unused return value of `Secret::new` that must be used
    Secret::new(vec![0x41u8; 32]);
}
