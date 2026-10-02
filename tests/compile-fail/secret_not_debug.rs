// Test 16 — `Secret` is not `Debug`.
//
// Assertion: this file must FAIL to compile. If it compiles, `Secret` has gained
// a `Debug` implementation, which would allow key material into logs, panics, and
// backtraces. See F3 blueprint test 16 and invariant G10.

use tokengen::zeroize::Secret;

fn main() {
    let (secret, _status) = Secret::new(vec![0x41u8; 32]);
    // ERROR: `Secret<Vec<u8>>` does not implement `Debug`
    let _ = format!("{secret:?}");
}
