// Test 13a — discarding `capture`'s result is rejected.
//
// The blueprint's §3 settled that `capture` returns a tuple carrying the guard AND the status observed at
// capture, because `Disabled` (dev-mode) is a legitimate state of a successfully constructed guard rather
// than an error. `#[must_use]` on the function is what stops a caller throwing that status away.
//
// Assertion: this file must FAIL to compile with an `unused_must_use` warning promoted to an error.
//
// ---------------------------------------------------------------------------------------------
// What this test does and does NOT establish — the boundary matters
// ---------------------------------------------------------------------------------------------
//
// It proves the BLUNT discard is caught: `capture(r, p);` as a statement.
//
// It does NOT prove the status must be read. Test 13b (a *passing* case) pins the other side: binding the
// tuple and dropping the status compiles silently, because no `#[must_use]` sees through a binding pattern.
//
// A suite that tested only this direction would leave the escape hatch unmeasured and would let a later
// reader believe the attribute is total. The prose claim that `#[must_use]` catches all discards was wrong
// once already (failures-table entry 2), which is why both directions are pinned here rather than asserted.

// `unused_must_use` is a *warning* by default, so this deny is what turns it into the compile error the
// test asserts. That is not a workaround — it is the same setting the release build uses, where warnings
// are errors (CI sets RUSTFLAGS=-D warnings).
//
// Without it, trybuild reports "expected test case to fail to compile, but it succeeded" **while the
// warning is plainly present in its output**. That is exactly how this test first failed here, and it is
// the same trap `must_use_lock_status.rs` records from F3 — where it is how a missing `#[must_use]` was
// discovered. The convention already existed in this repository; following it rather than rediscovering it.
//
// The deny is scoped to this file and to this one lint; `deny(warnings)` would make the test brittle
// against unrelated lints changing.
#![deny(unused_must_use)]

use std::path::Path;
use tokengen::session::{DeviceIdentity, DeviceReader, SessionError, SessionGuard};

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

fn main() {
    // ERROR: unused `Result` that must be used — the status is discarded, so a caller could treat the
    // session as guarded without ever reading whether the guard is Present.
    SessionGuard::capture(StubReader, Path::new("/"));
}
