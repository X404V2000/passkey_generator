//! The USB session guard (F3.5).
//!
//! Binds a session to the identity of the device a working directory lives on, and reports when that
//! binding stops holding. **The caller exits; this module detects** — it owns no thread and no loop.
//!
//! # The model
//!
//! 1. [`SessionGuard::capture`] resolves `cwd` to its backing **device** (not the path — a path can be
//!    re-pointed at a different device, which is the attack this exists to catch), reads that device's
//!    identity, and returns a guard **plus the status at capture time**.
//! 2. The caller calls [`SessionGuard::check`] at least every 250 ms and **aborts on any status other
//!    than [`GuardStatus::Present`]**.
//!
//! # Fail closed (G3)
//!
//! Any status other than `Present` aborts. `Unverifiable` is **not** a warning: a guard that cannot
//! confirm its binding is a guard that is not satisfied. No path in this module returns `Present`
//! without having read and compared a real identity.
//!
//! # Why `capture` returns a tuple and not just a `Result`
//!
//! `Disabled` (the `dev-mode` build, see below) is a **legitimate status of a successfully constructed
//! guard**, not an error. A `Result`-only signature could not express it, so the status is returned
//! alongside. The `#[must_use]` boundary is pinned by tests 13a/13b and is **partial** — it catches
//! `capture(..);` but not `let (_g, _s) = capture(..)?;`.
//!
//! # Not `Send`, not `Sync`, not `Clone`
//!
//! Same reasoning as `Secret<T>`: a guard that could be moved between threads or duplicated would make
//! "the session is bound" a property of a copy rather than of the session. Pinned by test 12.
//!
//! # Status semantics (§5.1)
//!
//! `Missing`, `IdentityMismatch` and `Unverifiable` are distinguished because their **diagnostics**
//! differ, not because their consequences do — all three abort. A status type must not be forced to
//! carry a value the system does not have: when identity cannot be read there is no `observed` value,
//! and fabricating one (an empty string, the mount path with a blank UUID) would make the type assert
//! something untrue. That is why `Unverifiable` exists as a distinct variant (clause 2, applied to an
//! enum).

use std::marker::PhantomData;
use std::path::{Path, PathBuf};

// F3.5 §11: `dev-mode` compiles the guard off. That is a deliberate, temporarily-acceptable state for
// development and a **catastrophic** one for a release: a shipped binary would report `Disabled` where
// a user believed a session was guarded. Two mechanical defences, because a rule that is only written
// down is a rule that will eventually be broken:
//
//   1. `dev-mode` is not in `default` (asserted by CI, using `cargo metadata`).
//   2. Enabling it requires `TOKENGEN_DEV_MODE_ACK=1` in the build environment. A release build that
//      acquires the feature by accident fails to compile rather than shipping disabled silently.
//
// The acknowledgement is a **build-time** variable, not runtime configuration: it cannot be set by a
// user of a built binary, so G1 (no ambient configuration changing security behaviour) is unaffected.
#[cfg(feature = "dev-mode")]
#[allow(clippy::manual_assert)]
const _: () = {
    match option_env!("TOKENGEN_DEV_MODE_ACK") {
        Some(v) if matches!(v.as_bytes(), b"1") => {}
        _ => panic!(
            "dev-mode is enabled without TOKENGEN_DEV_MODE_ACK=1. This feature compiles the \
             session guard OFF and must never be present in a release build. If you intend to \
             build with it, set TOKENGEN_DEV_MODE_ACK=1 explicitly."
        ),
    }
};

/// Which identity component a status refers to. Non-secret.
pub use tokengen_sys::device::IdentityComponent;

/// The identity bound at capture time: the filesystem UUID and the hardware serial.
///
/// **Not secret** — these are device properties, not key material. `Clone`/`Debug`/`PartialEq` are
/// therefore appropriate, unlike the main crate's secret-bearing types. G9 (constant-time comparison)
/// does not apply: this is not a secret comparison, and the project says so explicitly rather than by
/// omission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceIdentity {
    /// The filesystem UUID, from the reverse traversal of `/dev/disk/by-uuid`.
    pub uuid: String,
    /// The hardware serial, from `device/serial` or, for USB, `device/vpd_pg80`.
    pub serial: String,
}

/// The result of a guard check. **Every variant except `Present` is abort-worthy** (§5.2).
#[must_use]
#[non_exhaustive]
pub enum GuardStatus {
    /// The bound device is present and its identity matches.
    Present,
    /// The bound device is no longer present.
    Missing,
    /// A **different** device is now at the bound path. Carries both identities so the diagnostic can
    /// name what changed.
    IdentityMismatch {
        /// The identity bound at capture.
        expected: DeviceIdentity,
        /// The identity read now.
        observed: DeviceIdentity,
    },
    /// The device may be present, but identity could not be **confirmed**. Abort-worthy: under G3 a
    /// guard that cannot confirm its binding is not satisfied. Carries the component that was
    /// unreadable — never a fabricated value.
    Unverifiable {
        /// Which component could not be read.
        component: IdentityComponent,
    },
    /// The guard is compiled off (`dev-mode`). **Never a silent `Present`.**
    Disabled,
}

impl GuardStatus {
    /// True only for [`GuardStatus::Present`] — the single status that permits the session to continue.
    ///
    /// Provided so a caller cannot accidentally write `if let Present = … { } else { }` and invert the
    /// default. Fail-closed means the **default** must be "abort".
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, GuardStatus::Present)
    }
}

/// Why a guard could not be established.
///
/// Carries no secret material — these are failures of *device resolution*, not of key handling — so
/// `Debug` is safe and useful here.
///
/// `Copy` is deliberately **not** derived: a future variant carrying a `DeviceIdentity` would not be
/// `Copy`, and deriving it now would make that a breaking change later.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionError {
    /// The path's backing device is not a removable transport. Test 1 asserts this path.
    NotOnRemovableDevice,
    /// The path could not be resolved to a backing device.
    DeviceNotFound,
    /// A required identity component could not be read. The component is named so the caller learns
    /// *what* was unverifiable without inventing a value for it.
    IdentityUnreadable {
        /// Which component was unreadable.
        component: IdentityComponent,
    },
    /// This build has no backend for the current target (`NotSupported` on macOS and Windows until
    /// F3.7). Fail closed, never a plausible `Ok`.
    NotSupported,
}

/// The seam between the guard and the platform.
///
/// **Why a trait**, and why keyed on a resolved device rather than a path: a path-keyed interface
/// cannot express *"the same path is now a different device"*, which is precisely the swap this
/// feature detects. `resolve` returns an opaque [`ResolvedDevice`], and identity is read from that.
///
/// It lives in this crate (not `tokengen-sys`) so the **mock** used by tests 2–7 is a first-class
/// implementation rather than a test-only back door, and so the platform error type is mapped to
/// [`SessionError`] before it reaches a caller.
pub trait DeviceReader {
    /// Resolve a path to the **device** backing it.
    ///
    /// # Errors
    /// Fails closed: a non-removable backing device, a missing device, or an unsupported target all
    /// produce an error rather than a plausible success.
    fn resolve(&self, path: &Path) -> Result<ResolvedDevice, SessionError>;

    /// Read the identity of a resolved device.
    ///
    /// # Errors
    /// Returns `Err` if either component cannot be read. A partial identity is never returned.
    fn identify(&self, device: &ResolvedDevice) -> Result<DeviceIdentity, SessionError>;
}

/// An opaque, resolved device, as seen by the guard.
///
/// Private field, no `Clone`, and **no `Debug`**: it holds the resolved device name, and a derived
/// `Debug` would print *where the tool ran* into any formatted error, against the G2/G11–G13 posture
/// of leaving no trace on the host. Use [`DeviceIdentity`] when a diagnostic value is needed.
pub struct ResolvedDevice {
    /// Platform handle. Private so no caller can fabricate a device or depend on its layout.
    inner: tokengen_sys::device::DeviceDescriptor,
}

/// The real reader: delegates to `tokengen-sys`, mapping its error type to [`SessionError`].
///
/// This is the only type that touches the platform layer. It performs **no** policy of its own — every
/// platform decision belongs in `tokengen-sys/src/device.rs`, where the probes are.
#[derive(Debug, Default)]
pub struct SystemDeviceReader;

impl SystemDeviceReader {
    /// Construct the real reader.
    #[must_use]
    pub fn new() -> Self {
        SystemDeviceReader
    }
}

/// Map a platform error to the caller-facing error.
///
/// A **total** mapping with no catch-all-to-success: an unrecognised platform error becomes an error,
/// never a default that could read as success.
fn map_error(err: tokengen_sys::device::DeviceReadError) -> SessionError {
    use tokengen_sys::device::DeviceReadError as E;
    use tokengen_sys::device::IdentityComponent as C;
    match err {
        E::NotRemovable => SessionError::NotOnRemovableDevice,
        E::StatFailed | E::InvalidPath => SessionError::DeviceNotFound,
        E::DeviceNotFound => SessionError::DeviceNotFound,
        E::UuidNotFound => SessionError::IdentityUnreadable {
            component: C::FilesystemUuid,
        },
        E::PropertyUnreadable => SessionError::IdentityUnreadable {
            component: C::HardwareSerial,
        },
        E::NotSupported => SessionError::NotSupported,
        // `DeviceReadError` is `#[non_exhaustive]`, so a future variant must not break this crate.
        // The catch-all is **an error, never a success**: an unrecognised platform failure must fail
        // closed. Mapping it to anything that could read as "resolved" or "identity matches" would be
        // the false-assurance defect this project treats as its worst.
        _ => SessionError::DeviceNotFound,
    }
}

impl DeviceReader for SystemDeviceReader {
    fn resolve(&self, path: &Path) -> Result<ResolvedDevice, SessionError> {
        tokengen_sys::device::resolve(path)
            .map(|inner| ResolvedDevice { inner })
            .map_err(map_error)
    }

    fn identify(&self, device: &ResolvedDevice) -> Result<DeviceIdentity, SessionError> {
        tokengen_sys::device::identify(&device.inner)
            .map(|id| DeviceIdentity {
                uuid: id.uuid,
                serial: id.serial,
            })
            .map_err(map_error)
    }
}

/// Binds a session to the identity of the device backing a path.
///
/// See the module documentation for the model and the fail-closed rule.
pub struct SessionGuard<R: DeviceReader> {
    /// The reader, retained so `check` can re-resolve and re-identify.
    ///
    /// Under `dev-mode` the guard never consults it — the feature compiles the guard off, and the
    /// fields are kept so the type has the **same shape in both builds**. That is deliberate: a guard
    /// whose layout differs between `dev-mode` and release would make "the same program with the guard
    /// removed" false, which is exactly the reassurance `dev-mode` must not imply.
    #[cfg_attr(feature = "dev-mode", allow(dead_code))]
    reader: R,
    /// The path bound at capture. Re-resolved on every check — the **device** is the unit of identity,
    /// so the path is only an entry point. Unused under `dev-mode` (see `reader`).
    #[cfg_attr(feature = "dev-mode", allow(dead_code))]
    path: PathBuf,
    /// The identity observed at capture. Compared against on every check.
    bound: DeviceIdentity,
    /// Not `Send`/`Sync`: the guard's binding is a property of the session, not of a copy. Modelled as
    /// F3 models `LockHandle`, and pinned by test 12.
    _not_send_or_sync: PhantomData<*const ()>,
}

impl<R: DeviceReader> SessionGuard<R> {
    /// Bind to the device backing `cwd`. **Fails closed.**
    ///
    /// Returns the guard together with the status observed at capture, because two non-`Present`
    /// outcomes are legitimate here and must stay distinguishable: [`GuardStatus::Disabled`] (the
    /// `dev-mode` build) and [`GuardStatus::Unverifiable`] are states of a *successfully constructed*
    /// guard, not errors. Collapsing them into `Result` would make `dev-mode` unrepresentable.
    ///
    /// **Reading the status is mandatory.** `#[must_use]` on this function catches `capture(r, p);` but
    /// **not** `let (_g, _s) = capture(r, p)?;` — no `#[must_use]` sees through a binding pattern. The
    /// attribute is a partial guard, and tests 13a/13b pin both directions so the boundary is measured
    /// rather than assumed.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] when the device cannot be resolved or its identity cannot be read.
    /// A guard is **never** constructed over an unread identity: doing so would leave `check`
    /// comparing against a value the system does not have.
    #[must_use = "the guard status must be surfaced; capture does not imply Present — \
                  check the status before treating the session as guarded"]
    pub fn capture(reader: R, cwd: &Path) -> Result<(Self, GuardStatus), SessionError> {
        // `dev-mode`: the guard is compiled off. Report that **distinguishably** — never a silent
        // `Present`. The guard is still constructed so the caller's types line up, but no binding is
        // claimed, and `check` will keep returning `Disabled`.
        #[cfg(feature = "dev-mode")]
        let result = {
            let guard = SessionGuard {
                reader,
                path: PathBuf::from(cwd),
                // No binding is claimed, and none is compared: `check` returns `Disabled` without
                // consulting this. The placeholder has no meaning and is never read.
                bound: DeviceIdentity {
                    uuid: String::new(),
                    serial: String::new(),
                },
                _not_send_or_sync: PhantomData,
            };
            Ok((guard, GuardStatus::Disabled))
        };

        #[cfg(not(feature = "dev-mode"))]
        let result = {
            let device = reader.resolve(cwd)?;
            let bound = reader.identify(&device)?;
            let guard = SessionGuard {
                reader,
                path: cwd.to_path_buf(),
                bound,
                _not_send_or_sync: PhantomData,
            };
            Ok((guard, GuardStatus::Present))
        };

        result
    }

    /// Re-verify the binding. The caller calls this at least every 250 ms and aborts on any status
    /// other than [`GuardStatus::Present`].
    ///
    /// **No cache, no rate limit, no "last known good".** Every call re-resolves the path and re-reads
    /// the identity: a guard that returned a remembered `Present` would be reporting on the past rather
    /// than the present, which is the false-assurance class this project treats as its worst defect.
    #[must_use = "the status determines whether the session may continue; only Present permits it"]
    pub fn check(&self) -> GuardStatus {
        #[cfg(feature = "dev-mode")]
        let status = {
            // Compiled off. Never `Present`, at capture or at any later check.
            GuardStatus::Disabled
        };

        #[cfg(not(feature = "dev-mode"))]
        let status = {
            // 1. Re-resolve the path to a *device*. An error here is not "unchanged" — it means the
            //    binding cannot be confirmed, which fails closed. The variant distinguishes why.
            let device = match self.reader.resolve(&self.path) {
                Ok(d) => d,
                Err(SessionError::IdentityUnreadable { component }) => {
                    return GuardStatus::Unverifiable { component }
                }
                // A device that is gone, or a path that no longer resolves, is `Missing` — not
                // `Unverifiable`. The distinction matters for the diagnostic, not the outcome.
                Err(_) => return GuardStatus::Missing,
            };

            // 2. Re-read the identity. Unreadable is `Unverifiable`, never a match.
            let observed = match self.reader.identify(&device) {
                Ok(id) => id,
                Err(SessionError::IdentityUnreadable { component }) => {
                    return GuardStatus::Unverifiable { component }
                }
                Err(_) => return GuardStatus::Missing,
            };

            // 3. Compare. Not constant-time, deliberately: this is not a secret comparison (G9 does not
            //    apply), and the project states that rather than leaving it to inference.
            if observed == self.bound {
                GuardStatus::Present
            } else {
                GuardStatus::IdentityMismatch {
                    expected: self.bound.clone(),
                    observed,
                }
            }
        };

        status
    }

    /// The identity bound at capture, for diagnostics.
    #[must_use]
    pub fn identity(&self) -> &DeviceIdentity {
        &self.bound
    }
}
