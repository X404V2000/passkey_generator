//! Core-dump disabling via `setrlimit(RLIMIT_CORE, 0)`.
//!
//! Split out of the crate root under
//! [`AM-002`](../../../plan/reports/F3/AM-002_tokengen-sys_Module_Split.md).
//!
//! **One of exactly two `unsafe`-bearing modules in this crate** (the other is
//! [`crate::memory`]).
//!
//! # Platform status
//!
//! **Unix only in this revision.** The Windows backend is deferred (F3 blueprint
//! §14 W1); a non-Unix target receives `NotSupported`, never `Ok`. A stub that
//! reported success would leave invariant G15 silently unmet while appearing
//! satisfied.
//!
//! Note also that Windows has no direct `RLIMIT_CORE` equivalent: when that
//! backend is implemented, `SetErrorMode` suppresses the crash dialog but does
//! not guarantee Windows Error Reporting omits a dump in all configurations.

#[cfg(unix)]
// The `unsafe` opt-out for this module. Confined here and to `crate::memory`;
// every `unsafe` block inside carries a `// SAFETY:` justification. The main
// `tokengen` crate cannot acquire this allowance — its root uses `forbid`, which
// no module can relax (verified: `error[E0453]`).
#[allow(unsafe_code)]
mod platform {
    use crate::CoreDumpError;

    pub(super) fn disable_core_dumps() -> Result<(), CoreDumpError> {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        // SAFETY: `setrlimit` reads the `rlimit` struct we pass. The struct is
        // stack-allocated and remains valid for the duration of the call; the
        // call does not retain the pointer.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };

        if rc == 0 {
            Ok(())
        } else {
            // SAFETY: `__errno_location` returns a valid pointer to this thread's
            // errno for the lifetime of the thread.
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EPERM {
                Err(CoreDumpError::PermissionDenied)
            } else {
                Err(CoreDumpError::Other(errno))
            }
        }
    }
}

/// Targets with no backend in this revision. Fail closed — see the module docs.
#[cfg(not(unix))]
mod platform {
    use crate::CoreDumpError;

    pub(super) fn disable_core_dumps() -> Result<(), CoreDumpError> {
        Err(CoreDumpError::NotSupported)
    }
}

/// Disable core dumps for the current process.
///
/// Crate-internal: callers use [`crate::disable_core_dumps`].
pub(crate) fn disable_core_dumps() -> Result<(), crate::CoreDumpError> {
    platform::disable_core_dumps()
}
