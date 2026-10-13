//! Ordering assertion for `Secret::drop`: zeroize must precede unlock.
//!
//! # Why this test is structured the way it is
//!
//! Contract B3 requires zeroization **before** unlocking — reversing the order
//! would release the swap protection at the moment the secret is most exposed,
//! which is the exact window `mlock` exists to close.
//!
//! **This test observes `Secret::drop` itself**, not the hook functions in
//! isolation. An earlier version drove `hooks::record_*` directly and asserted a
//! single overwritten tag; that version **passed against a deliberately reversed
//! `Secret::drop`** and was therefore not discriminating. The F2 rejection-proof
//! defect (F2 report §6) recurring. The mechanism was replaced with an ordered
//! two-symbol sequence recorded by the real drop path, and the mutation was
//! re-run to confirm this version fails against it.
//!
//! The hooks live behind the `test-hooks` Cargo feature on `tokengen-sys`,
//! enabled here only through `dev-dependencies`. `#[cfg(test)]` cannot be used
//! across a crate boundary: it is set only for the crate under test, so a
//! dependency's `cfg(test)` module is not compiled at all (`error[E0433]`).

#![cfg(feature = "test-hooks")]

use std::sync::{Mutex, MutexGuard, OnceLock};

use tokengen::zeroize::Secret;
use tokengen_sys::hooks::{self, TAG_NONE, TAG_UNLOCK, TAG_ZEROIZE};

/// Serializes the ordering tests.
///
/// The hook sequence is process-global state. Cargo runs a binary's tests on
/// multiple threads by default, so two ordering tests running concurrently would
/// interleave their events into the same sequence and produce a spurious
/// failure. This was observed during development: a test failed under default
/// parallelism and passed when run alone. The lock removes the flake at its
/// source rather than depending on `--test-threads=1`.
///
/// A poisoned lock is recovered rather than propagated — a panic in one test
/// must not turn the others into failures for an unrelated reason.
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let lock = LOCK.get_or_init(|| Mutex::new(()));
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The drop-path sequence expected **on this platform** (AM-004).
///
/// - On Unix a `Secret` locks successfully, so its drop must record zeroize **then** unlock:
///   `(TAG_ZEROIZE, TAG_UNLOCK)`. This proves the ordering — the actual B3 guarantee.
/// - On Windows there is no locking backend (`lock_range` returns `LockError::NotSupported`), so no
///   handle is held and no unlock is recorded: `(TAG_ZEROIZE, TAG_NONE)`.
///
/// **Stated limitation, not hidden:** on Windows this assertion proves that zeroization happens and that
/// no unlock is claimed — it does **not** prove ordering, because there is no lock to order against.
/// Zeroize-before-unlock is unprovable on Windows until F3.7 supplies a real locking backend; G14/G15
/// remain unmet there (F3 §14 W1). Do not cite this test as evidence that they hold.
#[cfg(unix)]
const EXPECTED_DROP_SEQUENCE: (usize, usize) = (TAG_ZEROIZE, TAG_UNLOCK);
#[cfg(not(unix))]
const EXPECTED_DROP_SEQUENCE: (usize, usize) = (TAG_ZEROIZE, TAG_NONE);

/// The real drop path must record zeroize **before** unlock.
///
/// This is the assertion that a reversed `Secret::drop` fails (on platforms that lock).
#[test]
fn drop_records_zeroize_before_unlock() {
    let _guard = serial();
    hooks::reset();
    {
        let (secret, _status) = Secret::new(vec![0x5Au8; 4096]);
        assert_eq!(secret.len(), 4096);
        // `secret` drops here, running the real `Drop::drop`.
    }

    let (first, second) = hooks::sequence();
    assert_eq!(
        (first, second),
        EXPECTED_DROP_SEQUENCE,
        "Secret::drop must zeroize (and, where a lock exists, unlock after); \
         recorded sequence was ({first}, {second})"
    );
    // Zeroization is asserted on every platform, unconditionally (G4).
    assert_eq!(
        first, TAG_ZEROIZE,
        "zeroization must always be recorded first"
    );
}

/// The negative case: a `Secret` that never locked must still zeroize, and must
/// not record an unlock.
///
/// Without this, a pass could not distinguish "zeroize happened, no lock" from
/// "the hooks never fired at all".
#[test]
fn unlocked_secret_records_zeroize_and_no_unlock() {
    let _guard = serial();
    hooks::reset();
    {
        // An empty buffer performs no lock syscall, so no handle is held.
        let (secret, _status) = Secret::new(Vec::new());
        assert!(secret.is_empty());
    }

    let (first, second) = hooks::sequence();
    assert_eq!(first, TAG_ZEROIZE, "zeroization must still be recorded");
    assert_eq!(second, TAG_NONE, "no unlock should be recorded");
}

/// A fixed-size array `Secret` follows the same ordering, on the same platform-dependent terms
/// as `drop_records_zeroize_before_unlock` (AM-004).
#[test]
fn array_secret_follows_the_same_ordering() {
    let _guard = serial();
    hooks::reset();
    {
        let (secret, _status) = Secret::new([0x11u8; 32]);
        assert_eq!(secret.len(), 32);
    }

    let (first, second) = hooks::sequence();
    assert_eq!(
        (first, second),
        EXPECTED_DROP_SEQUENCE,
        "array-backed Secret must follow the platform drop sequence; \
         recorded sequence was ({first}, {second})"
    );
    // Zeroization is asserted on every platform, unconditionally (G4).
    assert_eq!(
        first, TAG_ZEROIZE,
        "zeroization must always be recorded first"
    );
}

/// Demonstrates that the sequence encoding itself can distinguish the two
/// orderings. This asserts the *mechanism* is discriminating; the tests above
/// assert the *implementation* is correct. Both are needed.
#[test]
fn sequence_encoding_can_distinguish_both_orderings() {
    let _guard = serial();
    hooks::reset();
    hooks::record_zeroize();
    hooks::record_unlock();
    let correct = hooks::sequence();

    hooks::reset();
    hooks::record_unlock();
    hooks::record_zeroize();
    let reversed = hooks::sequence();

    assert_eq!(correct, (TAG_ZEROIZE, TAG_UNLOCK));
    assert_eq!(reversed, (TAG_UNLOCK, TAG_ZEROIZE));
    assert_ne!(
        correct, reversed,
        "the encoding must be able to tell the orderings apart, or the assertion above proves nothing"
    );
}
