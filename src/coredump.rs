//! Core-dump disabling: a thin safe wrapper over `tokengen-sys`.
//!
//! On Unix this sets `RLIMIT_CORE` to zero, so a crash cannot write key material
//! into a core file. It should be called once at process startup, before any key
//! is generated.
//!
//! **Contains no `unsafe`.** All FFI lives in `tokengen-sys`.
//!
//! # Platform status
//!
//! **Linux only in this revision.** The Windows backend is deferred (see the F3
//! blueprint §14 W1). On a target with no backend, this returns
//! [`CoreDumpError::NotSupported`] — it never reports success for a capability
//! that is absent, because a stub returning `Ok` would leave invariant G15
//! silently unmet while appearing satisfied.
//!
//! Note also that Windows has no direct `RLIMIT_CORE` equivalent: when that
//! backend is implemented, `SetErrorMode` suppresses the crash dialog but does
//! not guarantee Windows Error Reporting omits a dump in all configurations.

pub use tokengen_sys::CoreDumpError;

/// Disable core dumps for the current process.
///
/// Idempotent and safe to call repeatedly. Call once at startup, before
/// generating any key.
///
/// On failure this returns `Err`; the caller is responsible for surfacing it.
/// This module does not print (invariant G10).
pub fn disable_core_dumps() -> Result<(), CoreDumpError> {
    tokengen_sys::disable_core_dumps()
}
