// Test 12 — the REAL `SessionGuard` is `!Send` and `!Sync`.
//
// Follows F3's two-test split (`handle_not_send_mechanism` / `handle_not_send_real`): the mechanism is
// proven on mirror types elsewhere; this file asserts the guarantee on the type we actually ship, so a
// refactor that drops the marker is caught here and not merely described.
//
// Why the guard must not be `Send` or `Sync`: it carries the reader, the bound path, and the identity the
// session is bound to. A guard that could be moved to another thread makes "the session is bound to this
// device" a property of a *copy* that another thread may check independently, and a guard that could be
// shared makes concurrent `check()` calls race on a decision that must be made once, in order. The type
// system is what enforces it; this file is what proves the type system is doing so.
//
// Two independent assertions, each in its own function, so a failure names which auto-trait broke.
//
// Assertion: this file must FAIL to compile, on BOTH the `Send` and `Sync` cases.

use std::path::Path;
use tokengen::session::{DeviceIdentity, DeviceReader, SessionError, SessionGuard};

/// A minimal reader, so the guard can be constructed without a platform.
///
/// The point of this file is the *guard's* auto-traits, not the reader's, so the reader is as simple as
/// the trait allows.
struct StubReader;

impl DeviceReader for StubReader {
    type Device = ();

    fn resolve(&self, _path: &Path) -> Result<(), SessionError> {
        Err(SessionError::NotSupported)
    }

    fn identify(&self, _device: &()) -> Result<DeviceIdentity, SessionError> {
        Err(SessionError::NotSupported)
    }
}

fn assert_send<T: Send>(_: &T) {}
fn assert_sync<T: Sync>(_: &T) {}

fn main() {
    // The guard is constructed with `capture`; the closure never runs, so no platform is touched.
    let guard: SessionGuard<StubReader> = match SessionGuard::capture(StubReader, Path::new("/")) {
        Ok((guard, _status)) => guard,
        Err(_) => loop {},
    };

    // ERROR: `SessionGuard` is not `Send` (PhantomData<*const ()>).
    assert_send(&guard);

    // ERROR: `SessionGuard` is not `Sync` (PhantomData<*const ()>).
    assert_sync(&guard);
}
