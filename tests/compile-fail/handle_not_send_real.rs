// Test 19 — the REAL `LockHandle` is `!Send` and `!Sync`.
//
// This is the second half of the two-test split. Test 18 proves the language
// mechanism on mirror types; this file asserts the guarantee on the type we
// actually ship. It couples to `LockHandle` deliberately: if the type is
// refactored such that the marker is lost, this test is what catches it.
//
// Two independent assertions, each in its own function so that a failure names
// which of the two auto-traits broke.
//
// Assertion: this file must FAIL to compile, on BOTH the `Send` and `Sync` cases.

use tokengen::mlock::lock_allocation;
use tokengen_sys::LockHandle;
use std::marker::PhantomData;

// `tokengen::mlock::lock_allocation` returns `tokengen_sys::LockHandle`; this
// alias documents which type the assertions below are about.
type RealHandle = LockHandle;

fn assert_send<T: Send>(_: &T) {}
fn assert_sync<T: Sync>(_: &T) {}

fn main() {
    let handle: RealHandle =
        lock_allocation(0, 0).unwrap_or_else(|_| unreachable_for_typecheck());

    // ERROR: `LockHandle` is not `Send` (PhantomData<*const ()>).
    assert_send(&handle);

    // ERROR: `LockHandle` is not `Sync` (PhantomData<*const ()>).
    assert_sync(&handle);

    // Keep `PhantomData` referenced so the import is not unused in the case where
    // a compiler version reports the errors above without reaching this line.
    let _ = PhantomData::<*const ()>;
}

/// Never called. Present only so the file type-checks past the `lock_allocation`
/// call without needing a real allocation; the compile errors above are the test.
fn unreachable_for_typecheck() -> RealHandle {
    loop {}
}
