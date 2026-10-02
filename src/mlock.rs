//! Memory locking: a thin safe wrapper over `tokengen-sys`.
//!
//! This module exists to give the main crate a module boundary around the
//! syscall dependency. It is deliberately close to pass-through — its job is not
//! to duplicate work but to ensure that no `unsafe` and no platform arithmetic
//! appears in the crate that handles key material.
//!
//! **Contains no `unsafe`.** If this module ever grows beyond delegation, that is
//! a signal the split is wrong and `tokengen-sys` should absorb more — flag it
//! rather than letting wrapper logic accrete here.

use tokengen_sys::{LockError, LockHandle};

pub use tokengen_sys::LockError as MemoryLockError;

/// Lock a whole allocation in physical memory.
///
/// Takes a base address and the **full length of the allocation** rather than a
/// slice, because a slice cannot express a `Vec`'s capacity tail. Page rounding
/// is performed inside `tokengen-sys`; this module does no arithmetic.
///
/// The caller must keep the allocation live until the returned handle is passed
/// to [`unlock`].
pub fn lock_allocation(base: usize, len: usize) -> Result<LockHandle, LockError> {
    tokengen_sys::lock_allocation(base, len)
}

/// Release a lock. Consumes the handle.
///
/// The handle carries exactly the range that was passed to the syscall, so this
/// function does not re-derive it. An empty range performs no syscall.
pub fn unlock(handle: LockHandle) {
    tokengen_sys::unlock(handle);
}
