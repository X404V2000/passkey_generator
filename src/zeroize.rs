//! Zeroization and memory locking for secret key material.
//!
//! [`Secret<T>`] wraps a byte buffer, wipes it on drop, and — where the platform
//! supports it — locks the backing allocation so it cannot be paged to disk.
//!
//! This module contains **no `unsafe`**. All platform FFI lives in the
//! `tokengen-sys` crate, which is the only crate in this workspace permitted to
//! contain it. The crate root's `#![forbid(unsafe_code)]` applies here unchanged.

use core::marker::PhantomData;

use crate::mlock;
use tokengen_sys::{LockError, LockHandle};

/// Buffer types that [`Secret`] can wrap.
///
/// Sealed: only `Vec<u8>` and the fixed-size arrays `[u8; 16]`, `[u8; 32]`,
/// `[u8; 64]`, `[u8; 128]`, and `[u8; 256]` implement it. Callers outside this
/// crate cannot add implementations.
pub trait SecretBuf: private::Sealed {
    /// The buffer's initialized bytes.
    fn as_bytes(&self) -> &[u8];

    /// The buffer's initialized bytes, mutably, for zeroization on drop.
    fn as_bytes_mut(&mut self) -> &mut [u8];

    /// Base address and full length of the **entire** allocation, for locking.
    ///
    /// For `Vec<u8>` the length is `capacity()`, not `len()`: the region between
    /// `len` and `capacity` belongs to the same allocation and may hold residual
    /// bytes from earlier use. Locking only `len()` would leave that tail
    /// unlocked, and page-rounding the `len` range does **not** cover it —
    /// measured: with `len = 100` and `capacity = 32768`, rounding `len` outward
    /// locks 4096 bytes and leaves 28 KB of the same allocation unlocked.
    ///
    /// Returning an address rather than a slice is deliberate: obtaining an
    /// address is safe in Rust, whereas producing a `&mut [u8]` spanning
    /// uninitialized capacity would require `unsafe`. The address is only ever
    /// passed back into `tokengen-sys`, which performs the dereference.
    fn allocation_base_and_len(&mut self) -> (usize, usize);
}

mod private {
    /// Sealing trait. Not nameable outside this crate.
    pub trait Sealed {}
}

impl private::Sealed for Vec<u8> {}

impl SecretBuf for Vec<u8> {
    fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }

    fn allocation_base_and_len(&mut self) -> (usize, usize) {
        // Both calls are safe. The address is only handed to `tokengen-sys`.
        (self.as_ptr() as usize, self.capacity())
    }
}

macro_rules! impl_secret_buf_array {
    ($($n:literal),+) => {
        $(
            impl private::Sealed for [u8; $n] {}

            impl SecretBuf for [u8; $n] {
                fn as_bytes(&self) -> &[u8] {
                    &self[..]
                }

                fn as_bytes_mut(&mut self) -> &mut [u8] {
                    &mut self[..]
                }

                fn allocation_base_and_len(&mut self) -> (usize, usize) {
                    // A fixed-size array *is* the whole allocation.
                    (self.as_ptr() as usize, $n)
                }
            }
        )+
    };
}

impl_secret_buf_array!(16, 32, 64, 128, 256);

/// Status of the memory-locking attempt made by [`Secret::new`].
///
/// [`Secret::new`] always attempts to lock. If locking fails, the `Secret` still
/// exists and still zeroizes on drop — only the swap protection is lost.
///
/// Callers MUST surface [`MemoryLockStatus::Denied`]. Note the limits of
/// `#[must_use]` on this type (contract B6): it warns when the whole tuple is
/// discarded, but **not** for `let (secret, _) = Secret::new(buf);`.
///
/// Carries no secret material by construction: it holds a `LockError` and
/// nothing else. Redaction is therefore a structural property of the type, not a
/// property of a `Debug` implementation a future contributor might edit.
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoryLockStatus {
    /// The allocation is locked in physical memory.
    Locked,
    /// Locking failed; the secret is still zeroized on drop.
    Denied(LockError),
}

/// A wrapper that zeroizes its contents on drop and, where possible, locks the
/// backing memory to prevent swapping.
///
/// Deliberately **not** `Clone`, `Copy`, `Debug`, `Display`, or `PartialEq` —
/// each would risk an unwipeable copy or leak the contents. It is also not
/// `Send`/`Sync`.
///
/// # Drop order
///
/// Zeroize **first**, then unlock. Unlocking first would release the swap
/// protection at the moment the secret is most exposed — precisely the window
/// this type exists to close.
pub struct Secret<T: SecretBuf> {
    buf: T,
    handle: Option<LockHandle>,
    // A secret should not move between threads without an explicit decision
    // being made elsewhere; the marker makes that a compile error.
    _not_send: PhantomData<*const ()>,
}

impl<T: SecretBuf> Secret<T> {
    /// Wrap `buf`, zeroizing it on drop. Attempts to lock memory.
    ///
    /// Returns the wrapped buffer and the lock status.
    ///
    /// # Limits of `#[must_use]` (contract B6)
    ///
    /// The attribute catches `Secret::new(buf);` — the whole tuple discarded.
    /// It does **not** catch `let (secret, _) = Secret::new(buf);`. That case is
    /// a documented limitation, not a guarantee; callers must read the status.
    ///
    /// The attribute on the *function* is what makes the first case warn. Note it
    /// must be here and not only on `MemoryLockStatus`: a tuple return type is not
    /// itself `#[must_use]`, so marking the enum alone would leave the discarded
    /// tuple silent — which is exactly what the compile-fail test detected.
    #[must_use = "the memory-lock status must be surfaced; a denied lock means the secret is swappable"]
    pub fn new(mut buf: T) -> (Self, MemoryLockStatus) {
        let (base, len) = buf.allocation_base_and_len();

        let (handle, status) = match mlock::lock_allocation(base, len) {
            Ok(handle) => (Some(handle), MemoryLockStatus::Locked),
            Err(err) => (None, MemoryLockStatus::Denied(err)),
        };

        let secret = Self {
            buf,
            handle,
            _not_send: PhantomData,
        };
        (secret, status)
    }

    /// Read-only access to the secret bytes.
    ///
    /// Callers MUST NOT copy the result into a non-`Secret` buffer: a plain
    /// `Vec<u8>` or `String` copy would be unwipeable.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_bytes()
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.as_bytes().len()
    }

    /// True if the buffer holds zero bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.as_bytes().is_empty()
    }
}

impl<T: SecretBuf> Drop for Secret<T> {
    fn drop(&mut self) {
        // 1. Zeroize FIRST.
        zeroize::Zeroize::zeroize(self.buf.as_bytes_mut());

        #[cfg(feature = "test-hooks")]
        tokengen_sys::hooks::record_zeroize();

        // 2. Then unlock, consuming the handle so double-unlock is unrepresentable.
        if let Some(handle) = self.handle.take() {
            mlock::unlock(handle);
        }

        // 3. Deallocation proceeds as normal.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_wraps_and_reads() {
        let (secret, _status) = Secret::new(b"hunter2".to_vec());
        assert_eq!(secret.as_slice(), b"hunter2");
        assert_eq!(secret.len(), 7);
        assert!(!secret.is_empty());
    }

    #[test]
    fn secret_len_matches() {
        for len in [1usize, 32, 256] {
            let (secret, _status) = Secret::new(vec![0xABu8; len]);
            assert_eq!(secret.len(), len);
        }
    }

    #[test]
    fn secret_returns_lock_status() {
        let (_secret, status) = Secret::new(vec![0u8; 64]);
        // Either outcome is valid; a constrained environment may deny locking.
        match status {
            MemoryLockStatus::Locked | MemoryLockStatus::Denied(_) => {}
        }
    }

    #[test]
    fn secret_vec_works() {
        let (secret, _status) = Secret::new(vec![1u8, 2, 3]);
        assert_eq!(secret.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn secret_array_32_works() {
        let (secret, _status) = Secret::new([7u8; 32]);
        assert_eq!(secret.len(), 32);
        assert!(secret.as_slice().iter().all(|&b| b == 7));
    }

    #[test]
    fn empty_secret_is_permitted_and_reads_empty() {
        let (secret, _status) = Secret::new(Vec::new());
        assert!(secret.is_empty());
        assert_eq!(secret.len(), 0);
    }

    #[test]
    fn vec_allocation_len_is_capacity_not_len() {
        // The property that makes the capacity tail covered by locking. A Vec
        // whose length is small but whose capacity is large must report the
        // capacity as its allocation length.
        let mut v: Vec<u8> = Vec::with_capacity(32 * 1024);
        v.extend_from_slice(&[1u8; 4]);
        let (_base, len) = v.allocation_base_and_len();
        assert_eq!(len, v.capacity());
        assert!(
            len > v.len(),
            "capacity must exceed len for this property to matter"
        );
    }

    #[test]
    fn array_allocation_len_is_the_array() {
        let mut arr = [0u8; 32];
        let (_base, len) = arr.allocation_base_and_len();
        assert_eq!(len, 32);
    }
}
