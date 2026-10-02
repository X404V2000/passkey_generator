// Test 17 — `Secret` is not `Clone`.
//
// Assertion: this file must FAIL to compile. If it compiles, `Secret` has gained
// `Clone`, which would allow an unwipeable duplicate of key material — the copy
// would live outside the `Drop` that wipes the original. See F3 blueprint test 17.

use tokengen::zeroize::Secret;

fn main() {
    let (secret, _status) = Secret::new(vec![0x41u8; 32]);
    // ERROR: `Secret<Vec<u8>>` does not implement `Clone`
    let _copy = secret.clone();
}
