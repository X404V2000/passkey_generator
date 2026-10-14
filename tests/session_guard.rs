//! F3.5 session-guard tests — the mock-reader state machine (blueprint tests 2–7).
//!
//! # What these tests prove, and what they do not — stated, per clause 1
//!
//! They exercise a **mock** reader. They prove the *state machine* is correct **given** the platform
//! inputs it is handed. They do **not** prove the platform produces those inputs on a real device — that
//! is `tokengen-sys/src/device.rs`, covered by the real-sysfs tests (1, 8, 9) and the probes.
//!
//! The split is the "coverage must be stated" obligation. A reader who saw only "session tests pass"
//! would wrongly conclude the guard had been exercised against hardware.
//!
//! # Why the mock defines its own device token
//!
//! [`DeviceReader`] has an associated `Device` type, so a reader owns its resolution representation. The
//! real reader's token is `tokengen::session::ResolvedDevice` — opaque, and constructible only by a
//! successful `resolve` on a real device. A mock could not fabricate one without a public test-only
//! constructor, which would weaken exactly the property the opacity exists for.
//!
//! So [`MockReader`] defines a trivial token of its own. The shipped API is unchanged in spirit, no
//! test-only constructor exists, and these tests run against the **real** `SessionGuard`.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use tokengen::session::{
    DeviceIdentity, DeviceReader, GuardStatus, IdentityComponent, SessionError, SessionGuard,
};

/// What the mock does on the next call.
///
/// Not `Clone`: a test sets a behaviour and replaces it, never copies it. `SessionError` is deliberately
/// not `Clone` (a future variant may carry a `DeviceIdentity`), so requiring it here would force the
/// shipped error type to gain a bound it does not need.
enum Behaviour {
    /// Resolve and identify successfully with this identity.
    Ok(DeviceIdentity),
    /// `resolve` succeeds; `identify` fails naming this component.
    IdentifyFails(IdentityComponent),
    /// `resolve` itself fails.
    ResolveFails(SessionError),
}

/// The mock's own device token. Carries nothing: the mock has no platform behind it.
///
/// A real token holds a device path; this deliberately holds nothing, which is the point of the
/// associated type — a reader represents a device however it needs to.
#[derive(Clone, Copy)]
struct MockDevice;

/// A reader whose behaviour the test controls.
///
/// `RefCell` because `check(&self)` takes `&self`, and a test must be able to change the device out from
/// under a live guard — which is exactly the swap scenario the feature exists to detect.
struct MockReader {
    behaviour: RefCell<Behaviour>,
    resolves: RefCell<u32>,
}

impl MockReader {
    fn new(behaviour: Behaviour) -> Self {
        MockReader {
            behaviour: RefCell::new(behaviour),
            resolves: RefCell::new(0),
        }
    }

    /// Make the device look different from now on: a swap, an unplug, a read failure.
    fn now(&self, behaviour: Behaviour) {
        *self.behaviour.borrow_mut() = behaviour;
    }

    fn resolve_count(&self) -> u32 {
        *self.resolves.borrow()
    }
}

/// Rebuild an error by value.
///
/// `SessionError` is not `Clone` — deliberately, since a future variant may carry a `DeviceIdentity` —
/// so the mock reconstructs. An unrecognised variant becomes an error, never a success: the mock must not
/// be able to manufacture a passing case.
fn rebuild(e: &SessionError) -> SessionError {
    match e {
        SessionError::NotOnRemovableDevice => SessionError::NotOnRemovableDevice,
        SessionError::DeviceNotFound => SessionError::DeviceNotFound,
        SessionError::NotSupported => SessionError::NotSupported,
        SessionError::IdentityUnreadable { component } => SessionError::IdentityUnreadable {
            component: *component,
        },
        _ => SessionError::DeviceNotFound,
    }
}

impl DeviceReader for MockReader {
    type Device = MockDevice;

    fn resolve(&self, _path: &Path) -> Result<MockDevice, SessionError> {
        *self.resolves.borrow_mut() += 1;
        match &*self.behaviour.borrow() {
            Behaviour::ResolveFails(e) => Err(rebuild(e)),
            _ => Ok(MockDevice),
        }
    }

    fn identify(&self, _device: &MockDevice) -> Result<DeviceIdentity, SessionError> {
        match &*self.behaviour.borrow() {
            Behaviour::Ok(id) => Ok(id.clone()),
            Behaviour::IdentifyFails(component) => Err(SessionError::IdentityUnreadable {
                component: *component,
            }),
            // `resolve` would have failed first; keep the mock total rather than panicking.
            Behaviour::ResolveFails(_) => Err(SessionError::DeviceNotFound),
        }
    }
}

fn id(uuid: &str, serial: &str) -> DeviceIdentity {
    DeviceIdentity {
        uuid: uuid.to_string(),
        serial: serial.to_string(),
    }
}

fn path() -> PathBuf {
    PathBuf::from("/mnt/usb")
}

/// Capture a guard, returning the reader too so a test can change the device afterwards.
///
/// The reader is shared by `Rc` because `capture` consumes it by value — and the guard keeps it, so the
/// test needs its own handle. This is a test-side concern only; the shipped API is untouched.
fn captured(behaviour: Behaviour) -> (Rc<MockReader>, SessionGuard<Rc<MockReader>>, GuardStatus) {
    let reader = Rc::new(MockReader::new(behaviour));
    // `expect()` is denied workspace-wide (a panic in secret-handling code is a defect); the same
    // reason applies here, so the failure is stated rather than unwrapped. `unwrap_or_else` with a
    // controlled panic-free path is not possible because the helper must return the guard, so the
    // error is asserted on and the match is exhaustive without a fallback expression.
    let captured = SessionGuard::capture(Rc::clone(&reader), &path());
    assert!(
        captured.is_ok(),
        "capture should succeed in this scenario, got {:?}",
        captured.as_ref().err()
    );
    match captured {
        Ok((guard, status)) => (reader, guard, status),
        Err(_) => unreachable!("asserted ok above"),
    }
}

// ---------------------------------------------------------------------------------------------
// Test 2 — capture_succeeds_present
// ---------------------------------------------------------------------------------------------

#[test]
fn capture_succeeds_present() {
    let (_reader, guard, status) = captured(Behaviour::Ok(id("uuid-a", "serial-a")));
    assert!(
        matches!(status, GuardStatus::Present),
        "a resolvable, readable device must capture as Present"
    );
    assert_eq!(guard.identity().uuid, "uuid-a");
    assert_eq!(guard.identity().serial, "serial-a");
}

// ---------------------------------------------------------------------------------------------
// Test 3 — missing_after_removal
// ---------------------------------------------------------------------------------------------

#[test]
fn missing_after_removal() {
    let (reader, guard, _) = captured(Behaviour::Ok(id("uuid-a", "serial-a")));

    // Pull the drive: the path no longer resolves to a device.
    reader.now(Behaviour::ResolveFails(SessionError::DeviceNotFound));

    let observed = guard.check();
    assert!(
        matches!(observed, GuardStatus::Missing),
        "a device that no longer resolves must report Missing, got {observed:?}"
    );
    assert!(
        !observed.is_ok(),
        "Missing must not permit the session to continue (§5.2)"
    );
}

// ---------------------------------------------------------------------------------------------
// Test 4 — identity_mismatch_on_swap
// ---------------------------------------------------------------------------------------------

#[test]
fn identity_mismatch_on_swap() {
    let (reader, guard, _) = captured(Behaviour::Ok(id("uuid-a", "serial-a")));

    // A *different* drive at the same path — the attack this feature exists to detect.
    reader.now(Behaviour::Ok(id("uuid-b", "serial-b")));

    match guard.check() {
        GuardStatus::IdentityMismatch { expected, observed } => {
            assert_eq!(
                expected.uuid, "uuid-a",
                "`expected` must be the identity captured, not the one read now"
            );
            assert_eq!(
                observed.uuid, "uuid-b",
                "`observed` must be what is there now"
            );
        }
        other => assert!(
            matches!(other, GuardStatus::IdentityMismatch { .. }),
            "a swapped device must report IdentityMismatch, got {other:?}"
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// Test 5 — unverifiable_when_uuid_unreadable
// ---------------------------------------------------------------------------------------------

#[test]
fn unverifiable_when_uuid_unreadable() {
    let (reader, guard, _) = captured(Behaviour::Ok(id("uuid-a", "serial-a")));
    reader.now(Behaviour::IdentifyFails(IdentityComponent::FilesystemUuid));

    let observed = guard.check();
    // Match on a reference: `observed` is used again below, and `GuardStatus` is deliberately not `Copy`
    // (it carries two `String`s).
    match &observed {
        GuardStatus::Unverifiable { component } => assert_eq!(
            component,
            &IdentityComponent::FilesystemUuid,
            "the unreadable component must be named"
        ),
        other => assert!(
            matches!(other, GuardStatus::Unverifiable { .. }),
            "an unreadable UUID must report Unverifiable, got {other:?}"
        ),
    }
    // The distinction that matters: not a fabricated match, and not `Missing` — the device is there, we
    // simply cannot confirm *which* one.
    assert!(!observed.is_ok(), "Unverifiable must abort (G3)");
}

// ---------------------------------------------------------------------------------------------
// Test 6 — unverifiable_when_serial_unreadable
// ---------------------------------------------------------------------------------------------

#[test]
fn unverifiable_when_serial_unreadable() {
    let (reader, guard, _) = captured(Behaviour::Ok(id("uuid-a", "serial-a")));
    reader.now(Behaviour::IdentifyFails(IdentityComponent::HardwareSerial));

    match guard.check() {
        GuardStatus::Unverifiable { component } => {
            assert_eq!(component, IdentityComponent::HardwareSerial)
        }
        other => assert!(
            matches!(other, GuardStatus::Unverifiable { .. }),
            "an unreadable serial must report Unverifiable, got {other:?}"
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// Test 7 — every_non_present_status_aborts  (the §5.2 fail-closed rule)
// ---------------------------------------------------------------------------------------------

/// **The most important property in this file:** only `Present` passes `is_ok()`.
#[test]
fn every_non_present_status_aborts() {
    let cases: Vec<(&str, GuardStatus, bool)> = vec![
        ("Present", GuardStatus::Present, true),
        ("Missing", GuardStatus::Missing, false),
        (
            "IdentityMismatch",
            GuardStatus::IdentityMismatch {
                expected: id("uuid-a", "serial-a"),
                observed: id("uuid-b", "serial-b"),
            },
            false,
        ),
        (
            "Unverifiable",
            GuardStatus::Unverifiable {
                component: IdentityComponent::FilesystemUuid,
            },
            false,
        ),
        ("Disabled", GuardStatus::Disabled, false),
    ];

    for (name, status, expected_ok) in cases {
        assert_eq!(
            status.is_ok(),
            expected_ok,
            "{name}: is_ok() must be true only for Present (§5.2 fail-closed rule)"
        );
    }
}

/// The same rule driven through `check()`, so it is checked on the statuses the guard **produces** rather
/// than only on hand-built values.
#[test]
fn check_only_ever_reports_ok_for_present() {
    let (reader, guard, _) = captured(Behaviour::Ok(id("uuid-a", "serial-a")));
    assert!(
        guard.check().is_ok(),
        "an unchanged device must stay Present"
    );

    reader.now(Behaviour::Ok(id("uuid-b", "serial-a")));
    let swapped = guard.check();
    assert!(
        !swapped.is_ok(),
        "a swapped device must abort, got {swapped:?}"
    );

    reader.now(Behaviour::IdentifyFails(IdentityComponent::HardwareSerial));
    let unreadable = guard.check();
    assert!(
        !unreadable.is_ok(),
        "an unreadable identity must abort, got {unreadable:?}"
    );

    reader.now(Behaviour::ResolveFails(SessionError::DeviceNotFound));
    let gone = guard.check();
    assert!(!gone.is_ok(), "a missing device must abort, got {gone:?}");
}

// ---------------------------------------------------------------------------------------------
// Properties the blueprint implies but does not number
// ---------------------------------------------------------------------------------------------

/// `check` must **re-resolve** every time: a cached guard would report on the past.
///
/// "No cache" is a claim in `session.rs`'s documentation, and an unmeasured claim is what this project
/// has repeatedly had to retract — so it is measured here.
#[test]
fn check_re_resolves_every_call() {
    let (reader, guard, _) = captured(Behaviour::Ok(id("uuid-a", "serial-a")));
    let after_capture = reader.resolve_count();
    assert_eq!(after_capture, 1, "capture resolves exactly once");

    for _ in 0..3 {
        let _ = guard.check();
    }
    assert_eq!(
        reader.resolve_count(),
        after_capture + 3,
        "each check must resolve again; a cached check would report on the past"
    );
}

/// A guard is never captured over an identity that could not be read.
///
/// If it were, `check` would compare against a value the system never had — and the first real check
/// would report `Present` because the fabricated value matched itself.
#[test]
fn capture_refuses_when_identity_is_unreadable() {
    let reader = Rc::new(MockReader::new(Behaviour::IdentifyFails(
        IdentityComponent::HardwareSerial,
    )));
    assert!(
        SessionGuard::capture(reader, &path()).is_err(),
        "capture must fail closed when identity cannot be read"
    );
}

/// A non-removable backing device is refused at capture — test 1's property, exercised here on the mock
/// so the *guard's* response to it is covered as well as the platform's.
#[test]
fn capture_refuses_non_removable_device() {
    let reader = Rc::new(MockReader::new(Behaviour::ResolveFails(
        SessionError::NotOnRemovableDevice,
    )));
    match SessionGuard::capture(reader, &path()) {
        Err(SessionError::NotOnRemovableDevice) => {}
        // The guard is deliberately not `Debug` (it holds the reader and the bound identity), so the
        // whole `Result` cannot be formatted. Assert the error, which is what matters here.
        Err(other) => assert_eq!(
            other,
            SessionError::NotOnRemovableDevice,
            "a non-removable device must be refused with that specific error"
        ),
        Ok(_) => unreachable!("capture SUCCEEDED on a non-removable device"),
    }
}

/// A target with no backend fails closed rather than reporting a plausible success (W1/W2).
#[test]
fn capture_refuses_unsupported_target() {
    let reader = Rc::new(MockReader::new(Behaviour::ResolveFails(
        SessionError::NotSupported,
    )));
    match SessionGuard::capture(reader, &path()) {
        Err(SessionError::NotSupported) => {}
        Err(other) => assert_eq!(
            other,
            SessionError::NotSupported,
            "an unsupported target must fail closed with that specific error"
        ),
        Ok(_) => unreachable!("capture SUCCEEDED on an unsupported target"),
    }
}
