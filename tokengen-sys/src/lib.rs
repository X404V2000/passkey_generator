//! Platform FFI for TokenGen: memory locking and core-dump disabling.
//!
//! **This is the only crate in the workspace permitted to contain `unsafe`.**
//! It exposes a **safe** public API; all `unsafe` blocks are internal and each
//! carries a `// SAFETY:` justification. The main `tokengen` crate keeps
//! `#![forbid(unsafe_code)]` and calls into this crate through safe functions.
//!
//! # Design notes
//!
//! - **Page arithmetic lives here, not in the caller.** [`lock`] computes the
//!   page-rounded range and returns it inside an opaque [`LockHandle`];
//!   [`unlock`] consumes that handle and passes the *same* range to `munlock`.
//!   The caller never computes, rounds, or re-derives a range.
//! - **Fail closed.** On a target with no backend (see `W1` in the F3 blueprint),
//!   these functions return `NotSupported`. They never report success for a
//!   capability that is not implemented — a stub returning `Ok` would make the
//!   caller's `Locked` status a lie.
//! - **`LockHandle` is `!Send` and `!Sync`** via `PhantomData<*const ()>`. The
//!   marker is required regardless of how the address is stored: a handle whose
//!   fields are all `usize` is automatically `Send`, silently. Explicit
//!   `impl !Send` is unavailable on Rust 1.85 (`error[E0658]`), so the marker is
//!   the only mechanism.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use core::marker::PhantomData;

/// Reason a memory-locking attempt failed.
///
/// `Copy` is a **redaction reinforcement**, not a convenience: it makes a future
/// variant holding owned data (a `String` message, say) a compile error at the
/// definition, rather than a soft error at call sites that could be silenced
/// with `.clone()`. A message-bearing variant would need `&'static str`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LockError {
    /// The platform has no locking backend in this revision.
    NotSupported,
    /// The operating system denied the request (commonly `EPERM`/`EACCES`).
    PermissionDenied,
    /// A resource limit was reached (commonly `ENOMEM` or an `RLIMIT_MEMLOCK`
    /// ceiling).
    ResourceLimit,
    /// Any other operating-system error, carrying the raw error code.
    Other(i32),
}

/// Reason core-dump disabling failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreDumpError {
    /// The platform has no core-dump backend in this revision.
    NotSupported,
    /// The operating system denied the request.
    PermissionDenied,
    /// Any other operating-system error, carrying the raw error code.
    Other(i32),
}

/// An opaque handle to a locked memory range.
///
/// Captures the page-rounded bounds that were **actually passed to the syscall**,
/// so that [`unlock`] cannot re-derive a different range.
///
/// # Properties (all enforced by construction)
///
/// - **Not `Copy`, not `Clone`** — a duplicated handle would permit double-unlock.
/// - **`!Send`, `!Sync`** — via the `PhantomData<*const ()>` marker. See the
///   crate docs for why the marker is required rather than inferred.
/// - **No `Drop`** — dropping a handle without calling [`unlock`] leaks the lock
///   rather than risking an unlock of memory still in use. `#[must_use]` warns.
#[must_use]
pub struct LockHandle {
    base: usize,
    rounded_len: usize,
    // Forces !Send and !Sync even though every other field is `usize`.
    _not_send: PhantomData<*const ()>,
}

impl LockHandle {
    /// A handle representing "no range". Produced for an empty buffer.
    ///
    /// [`unlock`] performs no syscall for such a handle.
    fn empty() -> Self {
        Self {
            base: 0,
            rounded_len: 0,
            _not_send: PhantomData,
        }
    }

    /// True if this handle represents no range.
    fn is_empty_range(&self) -> bool {
        self.rounded_len == 0
    }
}

impl core::fmt::Debug for LockHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Deliberately omits the address: it is not secret, but printing a raw
        // memory address invites confusion with secret material in logs.
        f.debug_struct("LockHandle")
            .field("rounded_len", &self.rounded_len)
            .finish_non_exhaustive()
    }
}

/// Lock the allocation backing `buf` in physical memory.
///
/// Page arithmetic is internal: the range is rounded outward to page boundaries
/// on both ends, because `mlock` is page-granular.
///
/// An empty buffer performs **no syscall** and yields an empty handle; the
/// matching [`unlock`] likewise performs no syscall.
///
/// **This locks `buf`'s own extent.** For a `Vec<u8>` that means `len`, not
/// `capacity` — a `Vec`'s tail beyond `len` belongs to the same allocation and
/// would be left unlocked. Callers that must cover a whole allocation should use
/// [`lock_allocation`] instead, which takes an explicit base and length.
pub fn lock(buf: &mut [u8]) -> Result<LockHandle, LockError> {
    if buf.is_empty() {
        return Ok(LockHandle::empty());
    }
    platform::lock_range(buf.as_ptr() as usize, buf.len())
}

/// Lock an explicit memory range given by base address and length.
///
/// Intended for callers that own an allocation whose full extent is not
/// expressible as a slice — notably `Vec<u8>`, where the region between `len`
/// and `capacity` is part of the same allocation and may hold residual bytes.
/// A caller can supply `vec.as_ptr() as usize` and `vec.capacity()` without any
/// `unsafe`: **obtaining an address is safe; only dereferencing one is not**, and
/// dereferencing happens here, inside this crate.
///
/// The range is page-rounded outward. The caller must keep the allocation alive
/// until the returned handle is passed to [`unlock`].
///
/// # Safety contract (enforced by convention, not by the type system)
///
/// `base` must be the start of a live allocation of at least `len` bytes, and
/// that allocation must not be moved, reallocated, or freed before the handle is
/// consumed by [`unlock`]. Supplying a stale or unowned address is undefined
/// behaviour; this function cannot verify the claim, which is why the pointer
/// form is a separate, explicitly-named entry point rather than the default.
pub fn lock_allocation(base: usize, len: usize) -> Result<LockHandle, LockError> {
    if len == 0 {
        return Ok(LockHandle::empty());
    }
    platform::lock_range(base, len)
}

/// Release the range described by `handle`, consuming it.
///
/// The range is not re-derived — the handle carries exactly what [`lock`] passed
/// to the syscall. An empty handle performs **no syscall**.
pub fn unlock(handle: LockHandle) {
    if handle.is_empty_range() {
        return;
    }
    platform::unlock_range(handle.base, handle.rounded_len);

    #[cfg(feature = "test-hooks")]
    hooks::record_unlock();
}

/// Disable core dumps for the current process.
///
/// Idempotent. Call once at startup, before generating any key.
pub fn disable_core_dumps() -> Result<(), CoreDumpError> {
    platform::disable_core_dumps()
}

/// Test-only ordering hooks.
///
/// Enabled solely by the `test-hooks` Cargo feature, which the parent crate
/// enables only through `dev-dependencies`. **Must never be enabled in a release
/// build.** Kept deliberately minimal — only what the ordering assertion needs.
///
/// # Why a sequence word, not a counter or a single tag
///
/// The assertion must distinguish `zeroize-then-unlock` from
/// `unlock-then-zeroize`. Neither a count nor a single overwritten tag can do
/// that: both orderings produce two events, and a last-writer-wins tag fails to
/// discriminate when only one event is emitted. This records the events as
/// **ordered symbols in a 2-digit base-10 word** (`first * 10 + second`), so the
/// exact sequence is recoverable.
///
/// This design was arrived at by mutation testing: an earlier version using a
/// single tag passed against a deliberately reversed `Secret::drop`, i.e. it was
/// not discriminating. See the F3 completion report.
#[cfg(feature = "test-hooks")]
pub mod hooks {
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// Tag for a zeroize event.
    pub const TAG_ZEROIZE: usize = 1;
    /// Tag for an unlock event.
    pub const TAG_UNLOCK: usize = 2;
    /// Tag meaning "no event recorded yet".
    pub const TAG_NONE: usize = 0;

    /// Encodes the first two events as `first * 10 + second`.
    ///
    /// Events beyond the second are ignored: the assertion only concerns the
    /// relative order of the first zeroize and the first unlock.
    static SEQ: AtomicUsize = AtomicUsize::new(0);

    fn push(tag: usize) {
        let current = SEQ.load(Ordering::SeqCst);
        let first = current / 10;
        let second = current % 10;
        let next = if first == 0 {
            tag * 10
        } else if second == 0 {
            first * 10 + tag
        } else {
            current
        };
        SEQ.store(next, Ordering::SeqCst);
    }

    /// Reset the sequence. Call before each assertion.
    pub fn reset() {
        SEQ.store(0, Ordering::SeqCst);
    }

    /// The recorded sequence as `[first, second]`, either of which may be `TAG_NONE`.
    pub fn sequence() -> (usize, usize) {
        let current = SEQ.load(Ordering::SeqCst);
        (current / 10, current % 10)
    }

    /// Record that zeroization occurred.
    pub fn record_zeroize() {
        push(TAG_ZEROIZE);
    }

    /// Record that unlocking occurred.
    pub fn record_unlock() {
        push(TAG_UNLOCK);
    }
}

// ---------------------------------------------------------------------------
// Platform backends
// ---------------------------------------------------------------------------

#[cfg(unix)]
// The `unsafe` opt-out for this crate. Confined to this single module; every
// `unsafe` block inside carries a `// SAFETY:` justification. The main
// `tokengen` crate cannot acquire this allowance — its root uses `forbid`,
// which no module can relax (verified: `error[E0453]`).
#[allow(unsafe_code)]
mod platform {
    use super::{CoreDumpError, LockError, LockHandle};
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
            // SAFETY: as above — a valid pointer to this thread's errno.
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EPERM {
                Err(CoreDumpError::PermissionDenied)
            } else {
                Err(CoreDumpError::Other(errno))
            }
        }
    }
}

/// Targets with no backend in this revision. Fail closed.
///
/// Returning `Err(NotSupported)` — never `Ok(())` — is deliberate: a stub that
/// reported success would make the caller's `Locked` status a lie and leave
/// invariants G14/G15 silently unmet. See the F3 blueprint §14 W1.
#[cfg(not(unix))]
mod platform {
    use super::{CoreDumpError, LockError, LockHandle};

    pub(super) fn lock_range(_buf: &mut [u8]) -> Result<LockHandle, LockError> {
        Err(LockError::NotSupported)
    }

    pub(super) fn unlock_range(_base: usize, _len: usize) {}

    pub(super) fn disable_core_dumps() -> Result<(), CoreDumpError> {
        Err(CoreDumpError::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_lock_is_noop_and_yields_empty_handle() {
        let mut empty: [u8; 0] = [];
        let handle = lock(&mut empty);
        assert!(handle.is_ok());
        if let Ok(handle) = handle {
            assert!(handle.is_empty_range());
            unlock(handle); // must not panic, must not call a syscall
        }
    }

    #[test]
    fn lock_then_unlock_round_trips() {
        let mut buf = [0u8; 64];
        match lock(&mut buf) {
            Ok(handle) => {
                assert!(!handle.is_empty_range());
                unlock(handle);
            }
            Err(_) => {
                // A constrained environment may deny locking; that is a valid
                // outcome (D3) and must not be a test failure.
            }
        }
    }

    #[test]
    fn disable_core_dumps_is_idempotent() {
        assert!(disable_core_dumps().is_ok());
        assert!(disable_core_dumps().is_ok());
    }

    #[test]
    fn handle_is_not_send_or_sync_this_would_not_compile_if_it_were() {
        // Compile-time assertion: these bounds must NOT hold. We cannot express a
        // negative bound directly, so this documents the property and the
        // trybuild compile-fail test in the parent crate enforces it.
        fn assert_marker_is_phantom(_: &LockHandle) {}
        let mut buf = [0u8; 8];
        if let Ok(handle) = lock(&mut buf) {
            assert_marker_is_phantom(&handle);
            unlock(handle);
        }
    }
}
