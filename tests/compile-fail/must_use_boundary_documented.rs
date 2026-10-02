// Test 15 — the INVERSE of test 14: `#[must_use]` does NOT catch destructuring.
//
// Assertion: this file must COMPILE. It is a *passing* compile-fail case, which is
// unusual and deliberate.
//
// Why it exists. `#[must_use]` on the returned tuple warns when the whole value is
// discarded (test 14), but it does **not** warn when the tuple is destructured and
// one element is dropped. This file pins that boundary as a tested fact rather
// than a prose claim, because the prose version of this claim was wrong once
// already (failures-table entry 2: "Prose claim that #[must_use] catches all
// discards").
//
// A test that asserted only the test-14 direction would be non-discriminating in
// the way clause 1 forbids: it would leave the boundary unmeasured. Asserting the
// boundary is what makes the pair informative — the caller must read the status,
// and the type system will not force them to.

use tokengen::zeroize::Secret;

fn main() {
    // COMPILES, deliberately. The status is discarded and no warning is emitted.
    // This is the documented limitation (contract B6), not a defect.
    let (secret, _status) = Secret::new(vec![0x41u8; 32]);
    assert_eq!(secret.len(), 32);
}
