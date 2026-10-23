// Test 13b — the INVERSE of 13a: `#[must_use]` does NOT catch destructuring.
//
// Assertion: this file must COMPILE. It is a *passing* compile-fail case, which is unusual and deliberate.
//
// Why it exists. `#[must_use]` on `capture` warns when the result is discarded whole (13a), but it does
// **not** warn when the tuple is destructured and the status element is dropped. This file pins that
// boundary as a tested fact rather than a prose claim — because the prose version of exactly this claim was
// wrong once already (failures-table entry 2: "Prose claim that `#[must_use]` catches all discards"), and
// F3 records the same boundary for `Secret::new` in `must_use_boundary_documented.rs`.
//
// Why it is worth pinning rather than fixing. There IS no fix available in the language: no `#[must_use]`
// inspects binding patterns. So the honest position is that the attribute is a *partial* guard, and the
// partiality is measured in both directions. A reader who saw only 13a would believe the status must be
// read; a reader who saw only 13b would believe nothing stops a discard. Both tests together say what is
// actually true.
//
// The consequence for callers, stated where the escape hatch is: the status is returned rather than hidden
// inside the guard *so that* a caller can see it, and the API's contract — "only `Present` permits the
// session to continue" — is enforced by `check()` at runtime, not by the type system at capture.

use std::path::Path;
use tokengen::session::{DeviceIdentity, DeviceReader, SerialSource, SessionError, SessionGuard};

struct StubReader;

impl DeviceReader for StubReader {
    type Device = ();

    fn resolve(&self, _path: &Path) -> Result<(), SessionError> {
        Ok(())
    }

    fn identify(&self, _device: &()) -> Result<DeviceIdentity, SessionError> {
        Ok(DeviceIdentity {
            uuid: "uuid-a".to_string(),
            serial: "serial-a".to_string(),
            serial_source: SerialSource::Disk,
        })
    }
}

fn main() {
    // COMPILES, deliberately. The status is bound to `_status` and never inspected, and no warning is
    // emitted. This is the documented limitation of `#[must_use]`, not a defect — see the note above.
    let (_guard, _status) = match SessionGuard::capture(StubReader, Path::new("/mnt/usb")) {
        Ok(pair) => pair,
        Err(_) => return,
    };
}
