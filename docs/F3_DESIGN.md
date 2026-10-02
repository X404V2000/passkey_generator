# F3 Design: Zeroization, Memory Locking, and Core-Dump Disabling

## 1. Purpose

Key material spends its life in physical memory. Two things can copy it out of that memory without
anyone deciding to: the kernel may **swap** the page to disk, and the kernel may write a **core dump**
on a crash. Both leave key bytes in a file that outlives the process, outside every protection the
program applies to itself.

F3 adds two mechanisms and a wrapper that ties them together: lock secret allocations so they cannot
be paged out, disable core dumps for the process, and wipe secret bytes before releasing either
protection. It is the layer that makes "the key was only ever in RAM" a statement the code can
support, rather than an assumption about how the operating system behaves.

## 2. Public API

```rust
// src/zeroize.rs
pub struct Secret<T: SecretBuf> { /* private */ }

impl<T: SecretBuf> Secret<T> {
    pub fn new(buf: T) -> (Self, MemoryLockStatus);
    pub fn as_slice(&self) -> &[u8];
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
}

#[must_use]
#[non_exhaustive]
pub enum MemoryLockStatus {
    Locked,
    Denied(LockError),
}

pub trait SecretBuf: private::Sealed {
    fn as_bytes(&self) -> &[u8];
    fn as_bytes_mut(&mut self) -> &mut [u8];
    fn allocation_base_and_len(&mut self) -> (usize, usize);
}

// src/mlock.rs
pub fn lock_allocation(base: usize, len: usize) -> Result<LockHandle, LockError>;
pub fn unlock(handle: LockHandle);

// src/coredump.rs
pub fn disable_core_dumps() -> Result<(), CoreDumpError>;
```

`Secret` implements `SecretBuf` for `Vec<u8>` and for `[u8; 16]`, `[u8; 32]`, `[u8; 64]`, `[u8; 128]`,
`[u8; 256]`. The trait is **sealed** — callers outside the crate cannot add implementations, so the
set of buffer types that receive zeroization is closed.

`Secret` is deliberately **not** `Clone`, `Copy`, `Debug`, `Display`, `PartialEq`, `Send`, or `Sync`.
Each omission is load-bearing: a clone or a `Debug` impl is an unwipeable copy of key material in a
place the type system no longer tracks.

## 3. Why the sub-crate (`tokengen-sys`)

Security invariant G13 requires the main crate to carry `#![forbid(unsafe_code)]`. `mlock`, `munlock`,
and `setrlimit` are not exposed as safe functions — they require an FFI call — so the guarantee and
the capability cannot coexist in one crate.

There are two ways to resolve that, and only one of them is acceptable:

| Approach | Mechanism | Verdict |
|---|---|---|
| **Relax the guarantee** | Change the crate root from `forbid(unsafe_code)` to `deny(unsafe_code)`, then add module-level `#[allow(unsafe_code)]` where needed | **REJECTED** |
| **Isolate the capability** | Move every FFI call into a separate crate that is the only one permitted `unsafe`; everything else keeps `forbid` | **CHOSEN** |

The first approach was **disproved empirically, not argued against**. `forbid` cannot be relaxed by
any inner attribute — doing so produces `error[E0453]: allow(unsafe_code) incompatible with previous
forbid`. So the choice is not between a strong guarantee and a convenient one; `deny` + `allow` is
strictly weaker, because it puts a lint *convention* in place of a lint *guarantee*, and the
convention is one `#[allow]` away from being defeated anywhere in the crate.

Under the chosen design the split is enforced structurally:

```
$ # attempt to acquire unsafe in the main crate
$ # (a module with #[allow(unsafe_code)] containing an unsafe block)
error[E0453]: allow(unsafe_code) incompatible with previous forbid
  = note: `forbid` lint level was set on command line
```

No module in `tokengen` can acquire `unsafe`, and no configuration can change that. The capability
lives in exactly one crate, all of it within a single `#[allow(unsafe_code)] mod platform`, with a
`// SAFETY:` justification on every `unsafe` block.

**Negative acceptance criterion.** No `#[allow(unsafe_code)]` appears anywhere in `src/`. This single
check mechanically distinguishes this design from the rejected one — the alternative fails it by
construction.

**The sentence the whole split rests on:** *obtaining an address is safe in Rust; only dereferencing
one is not.* It is why `SecretBuf` returns a `(usize, usize)` address pair rather than a widened
slice, and therefore why `src/zeroize.rs` needs no `unsafe` at all.

## 4. Why zeroize-then-unlock

`Secret::drop` performs three steps in this order:

1. **Zeroize** the initialized bytes.
2. **Unlock** the allocation, consuming the handle.
3. Deallocate (normal `Drop` proceedure).

Reversing steps 1 and 2 opens the exposure window the whole module exists to close. `mlock` prevents
the page being written to swap; `munlock` removes that protection immediately. If the unlock happens
first, the freshly-unlocked page is resident in physical memory at the exact moment it still holds
the key — and the kernel is free to evict it to disk between the two steps. The protection is
released while the material it protects is still present and still un-wiped.

The order is asserted by **`tests/zeroize_ordering.rs`**, which observes the real `Drop`
implementation. It is discriminating: with the order reversed, the test fails
(`left: (2, 1)`, `right: (1, 2)`).

## 5. Why the handle is an artifact and why it is `!Send`

`lock_allocation` returns an opaque `LockHandle` rather than a range the caller could reconstruct.
The handle carries **exactly** the page-rounded bounds that were passed to the syscall, so `unlock`
cannot re-derive a different range. Two failure modes are made unrepresentable:

- **Double unlock.** The handle is not `Copy` and not `Clone`; `unlock` consumes it by value.
- **Range divergence.** The caller never computes, rounds, or stores a range.

**`!Send` / `!Sync` via `PhantomData<*const ()>`.** A handle whose fields are all `usize` is
*automatically* `Send` and `Sync` — silently, and wrongly, because a lock is process-wide state tied
to a specific allocation. Explicit negative impls (`impl !Send for LockHandle`) are unstable on Rust
1.85 (`error[E0658]`), so the marker is the only available mechanism. This was verified by compile
probe, not assumed: a `usize`-only handle is `Send`.

`LockHandle` has **no `Drop`**. Dropping a handle without unlocking leaks the lock, which is the
fail-safe direction: the alternative — unlocking on drop — would release protection at a moment the
owner did not choose, possibly while the `Secret` is still alive.

## 6. Why `Copy` + `#[non_exhaustive]` on the error types

`LockError` and `CoreDumpError` derive `Copy`. This is a **redaction reinforcement**, not a
convenience: adding a variant that owns data — a `String` message, say — becomes a compile error at
the type definition, rather than a soft error at call sites that could be silenced with `.clone()`.
Any future message-bearing variant must be a `&'static str`, which cannot carry key material.

Both are `#[non_exhaustive]`, so callers must handle unknown variants; the enums can grow without
breaking downstream matches.

`MemoryLockStatus` holds a `LockError` and nothing else. Redaction is therefore **structural** — a
property of what the type can contain — rather than a property of a `Debug` implementation a future
contributor might edit.

## 7. Why `allocation_base_and_len`, not a slice

The blueprint originally specified `lock_memory(buf: &[u8])`. That signature **cannot** deliver the
requirement it was paired with (B13: the locked range must cover the whole allocation).

For a `Vec<u8>` the region between `len` and `capacity` belongs to the same allocation and may hold
residual bytes from earlier use. A `&[u8]` describes only `len`, and page-rounding outward does not
recover the difference — measured:

```
len=100  cap=32768   page-rounded len-range covers  4096 bytes
                     capacity-range covers        ≥32768 bytes
```

28 KB of the same allocation would have been left unlocked. Producing a `&mut [u8]` spanning
uninitialised capacity requires `unsafe`, which `src/` cannot have.

`allocation_base_and_len()` returns the address and the **capacity** for `Vec<u8>`, and the array
length for `[u8; N]` (where `len == capacity` by definition, so the two forms coincide).
`tokengen_sys::lock_allocation(base, len)` accepts that pair and performs the dereference inside its
own `unsafe` boundary, under a documented safety contract: the address must name a live allocation
that is neither moved nor freed before `unlock`.

## 8. Invariants

| Invariant | Status under F3 |
|---|---|
| G4 — secret material is zeroized | **Satisfied** for all `Secret<T>` buffers |
| G9 — constant-time comparison | Not addressed by F3 (no comparison in this feature) |
| G10 — no secret material printed | **Satisfied**: no `Debug`/`Display` on `Secret`; `LockHandle`'s `Debug` omits the address; error types carry no data |
| G13 — `forbid(unsafe_code)` in the main crate | **Satisfied**, and structurally enforced |
| G14 — secret memory cannot be paged out | **Satisfied on Unix.** **UNMET on Windows** — see §11 |
| G15 — core dumps disabled | **Satisfied on Unix.** **UNMET on Windows** — see §11 |

**No invariant was amended for F3.** The sub-crate design exists precisely so that G13 does not have
to be relaxed. An earlier draft proposed changing the invariant framework; that is not required and
was not done.

## 9. Lint configuration, and why it looks duplicated

The workspace declares `unsafe_code = "forbid"` plus the clippy set. `tokengen` inherits via
`[lints] workspace = true`.

`tokengen-sys` **cannot** do that. Cargo rejects a manifest carrying both workspace inheritance and a
local override:

```
error: cannot override `workspace.lints` in `lints`, either remove the overrides
       or `lints.workspace = true` and manually specify the lints
```

So `tokengen-sys` inherits no workspace lints and declares all of its own — including the clippy
lints repeated verbatim from the workspace. The manifest carries a comment explaining that the
repetition is intentional, so a future tidy-up does not silently break the opt-out.

**Consequence to record:** a future change to the workspace lint table will not propagate to
`tokengen-sys`. This is a **maintenance consequence, not a security change** — the security property
(`tokengen-sys` may use `unsafe`, `tokengen` may not) is unaffected and verified.

## 10. The test-hooks feature

The ordering assertion needs to observe events inside `Drop`. A `#[cfg(test)]` module cannot be used:
`cfg(test)` is set only for the crate under test, so a dependency's test module is not compiled at all
(`error[E0433]`). Cross-crate test hooks require a **Cargo feature**.

`tokengen-sys` defines `test-hooks`, opt-in and not in `default`. `tokengen` enables it only through
`dev-dependencies`, so it is absent from the default and release build graphs.

Scope discipline: the hook records one ordered two-symbol sequence and nothing else; it stores no
secret material; it is not reachable in a release build. The sequence encodes **order**, not a count —
a counter cannot distinguish `zeroize-then-unlock` from `unlock-then-zeroize`, because both emit two
events. Asserting a single last-writer tag is also insufficient: an early version did exactly that and
passed against a reversed `Drop`.

The ordering tests are serialized by a shared mutex. The hook state is process-global, and Cargo runs
a binary's tests in parallel by default; without the lock, concurrent tests interleave their events
and the suite flakes.

## 11. What F3 explicitly does NOT do

- **No platform support beyond Linux/Unix.** The Windows backend is **deferred** (decision W1).
  Non-Unix targets return `NotSupported` — never `Ok`. G14 and G15 are **unmet on Windows** in this
  revision, and the README must say so. A stub returning `Ok` would make `MemoryLockStatus::Locked` a
  lie.
- **`#[must_use]` does not catch every discard.** It warns when the whole `(Secret, MemoryLockStatus)`
  tuple is dropped, but **not** for `let (secret, _) = Secret::new(buf);`. This is a documented
  limitation, not a guarantee: callers must read the status.
- **No protection against a hostile kernel or hypervisor.** Zeroization is best-effort against a
  privileged observer that can read physical memory or has already compromised the OS.
- **No constant-time guarantees** — F3 introduces no comparison of secret data.
- **Not a key store.** `Secret` wraps a buffer for the duration of an operation; it is not a
  long-lived vault, and it does not persist anything.
- **Windows `SetErrorMode` is not an `RLIMIT_CORE` equivalent.** When that backend is implemented,
  `SetErrorMode` suppresses the crash dialog but does not guarantee Windows Error Reporting omits a
  dump in all configurations.

## 12. Compilation targets and cfg branches

| Branch | Compiled by `cargo build` on this host? | Compiled by a gate? |
|---|---|---|
| `#[cfg(unix)]` platform module | Yes | Yes — the normal gate run |
| `#[cfg(not(unix))]` platform stub | **No** — invisible on Linux | **Yes** — `scripts/cfg_check.sh` |

The stub is the entire Windows fail-closed mechanism and is **not compiled by any `cargo` command run
on this host**. It was once left with a stale signature as a result, producing `error[E0061]` on every
non-Unix target while every gate stayed green (failures-table entry 11).

`scripts/cfg_check.sh` closes this by copying the workspace, inverting the two `cfg` gates so the
stub is compiled and the `unix` module is not, and building. It requires no Windows toolchain. It
**fails loudly** if either textual anchor is missing, so a refactor cannot turn it into a silent
no-op. It is a mandatory step in the gate-run standard.
