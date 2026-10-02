//! Memory locking: `mlock`, `munlock`, and the page arithmetic around them.
//!
//! Split out of the crate root under
//! [`AM-002`](../../../plan/reports/F3/AM-002_tokengen-sys_Module_Split.md).
//!
//! **One of exactly two `unsafe`-bearing modules in this crate** (the other is
//! [`crate::coredump`]). The count is enumerated rather than asserted, which is
//! the point of the split: a guarantee whose scope is checked by eye stops being
//! checkable once the file it lives in grows a second platform domain.
//!
//! Every `unsafe` block carries a `// SAFETY:` justification.

#[cfg(unix)]
// The `unsafe` opt-out for this module. Confined here and to `crate::coredump`;
// every `unsafe` block inside carries a `// SAFETY:` justification. The main
// `tokengen` crate cannot acquire this allowance — its root uses `forbid`, which
// no module can relax (verified: `error[E0453]`).
#[allow(unsafe_code)]
mod platform {
    use crate::{LockError, LockHandle};
    use core::marker::PhantomData;

    /// Page size, or a safe fallback if the query fails.
    fn page_size() -> usize {
        // SAFETY: `sysconf` takes an int and returns a long; it has no pointer
        // arguments and cannot fail in a way that affects memory safety.
        let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if raw > 0 {
            // A page size is small and positive; the cast cannot truncate in
            // practice on any supported platform.
            raw as usize
        } else {
            4096
        }
    }

    fn round_up(value: usize, align: usize) -> usize {
        // `align` is a power of two from the OS. Saturating arithmetic avoids a
        // panic in debug builds on absurd inputs, which `panic = "deny"` would
        // otherwise turn into a build failure.
        match value.checked_add(align - 1) {
            Some(v) => v & !(align - 1),
            None => value,
        }
    }

    fn classify(errno: i32) -> LockError {
        match errno {
            libc::EPERM | libc::EACCES => LockError::PermissionDenied,
            libc::ENOMEM => LockError::ResourceLimit,
            other => LockError::Other(other),
        }
    }

    pub(super) fn lock_range(raw_start: usize, raw_len: usize) -> Result<LockHandle, LockError> {
        let page = page_size();
        let raw_end = match raw_start.checked_add(raw_len) {
            Some(v) => v,
            None => return Err(LockError::Other(libc::EINVAL)),
        };

        let start = raw_start & !(page - 1);
        let end = round_up(raw_end, page);
        let len = end.saturating_sub(start);

        // SAFETY: `mlock` reads only the address range given to it. The range is
        // derived from a live allocation whose base and length the caller
        // supplied, is page-aligned on both ends as `mlock` requires, and does
        // not outlive that allocation because the returned handle is consumed by
        // `unlock` before the owning `Secret` is deallocated. `mlock` does not
        // retain the pointer.
        let rc = unsafe { libc::mlock(start as *const libc::c_void, len) };

        if rc == 0 {
            Ok(LockHandle {
                base: start,
                rounded_len: len,
                _not_send: PhantomData,
            })
        } else {
            // SAFETY: `__errno_location` returns a valid pointer to this thread's
            // errno for the lifetime of the thread.
            let errno = unsafe { *libc::__errno_location() };
            Err(classify(errno))
        }
    }

    pub(super) fn unlock_range(base: usize, len: usize) {
        if len == 0 {
            return;
        }
        // SAFETY: `munlock` reads only the address range given to it. The range is
        // exactly the one `mlock` accepted, held in the handle that was consumed
        // by the caller, and the owning allocation is still live at this point
        // because `Secret::drop` unlocks before deallocating.
        let _ = unsafe { libc::munlock(base as *const libc::c_void, len) };
    }
}

/// Targets with no backend in this revision. Fail closed.
///
/// Returning `Err(NotSupported)` — never `Ok(())` — is deliberate: a stub that
/// reported success would make the caller's `Locked` status a lie and leave
/// invariants G14/G15 silently unmet. See the F3 blueprint §14 W1.
///
/// The signature must match the Unix implementation exactly. It is checked by
/// the `cfg-forcing check` in `scripts/cfg_check.sh`, which compiles this branch
/// on any host — because the Unix gates never see it. A `cfg`-gated stub that is
/// never compiled can drift from its callers silently, which is exactly what
/// happened once already (failures-table entry 11).
#[cfg(not(unix))]
mod platform {
    use crate::{LockError, LockHandle};

    pub(super) fn lock_range(_raw_start: usize, _raw_len: usize) -> Result<LockHandle, LockError> {
        Err(LockError::NotSupported)
    }

    pub(super) fn unlock_range(_base: usize, _len: usize) {}
}

/// Lock a page-aligned range covering `[raw_start, raw_start + raw_len)`.
///
/// Crate-internal: callers use [`crate::lock_allocation`], which handles the
/// empty case and is the documented entry point.
pub(crate) fn lock_range(
    raw_start: usize,
    raw_len: usize,
) -> Result<crate::LockHandle, crate::LockError> {
    platform::lock_range(raw_start, raw_len)
}

/// Release the range described by a handle.
///
/// Crate-internal: callers use [`crate::unlock`].
pub(crate) fn unlock_range(base: usize, len: usize) {
    platform::unlock_range(base, len);
}
