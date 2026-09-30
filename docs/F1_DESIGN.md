# F1 Design Document: Core CSPRNG Entropy Module

## 1. Purpose

F1 is the root of trust for TokenGen. It provides cryptographically secure random bytes from the operating system's CSPRNG to every other module that requires randomness. It is deliberately minimal, dependency-isolated, and auditable, performing exactly one task: fetching raw entropy from the operating system syscall interface, or failing closed.

## 2. Public API

```rust
/// Error returned when the operating system's CSPRNG fails.
///
/// This type is deliberately opaque: it exposes only the underlying
/// OS error. It does not leak stack traces, internal state, or
/// partial random data.
#[derive(Debug)]
pub enum EntropyError {
    /// The OS CSPRNG call failed.
    OsFailure(OsError),
}

/// Source of cryptographically secure random bytes.
///
/// Implementations MUST source bytes exclusively from an OS CSPRNG.
/// Implementations MUST NOT retry, fall back, or return partial data
/// on failure. On any error, they MUST return `Err(EntropyError::OsFailure(..))`.
pub trait EntropySource {
    /// Fill `buf` with cryptographically secure random bytes.
    ///
    /// Returns `Ok(())` on success.
    /// Returns `Err(EntropyError::OsFailure(..))` on failure — the
    /// buffer's contents are unspecified in that case and MUST NOT
    /// be used.
    ///
    /// If `buf` is empty, returns `Ok(())` without calling the OS.
    fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError>;
}

/// Production implementation of [`EntropySource`] backed by the OS CSPRNG.
///
/// Uses `getrandom::getrandom`, which maps to:
/// - Windows: `BCryptGenRandom`
/// - Linux:   `getrandom(2)` syscall
/// - macOS:   `SecRandomCopyBytes`
pub struct OsEntropy;

impl OsEntropy {
    /// Create a new `OsEntropy`. No resources are allocated.
    pub fn new() -> Self;
}

impl Default for OsEntropy { /* returns OsEntropy::new() */ }

impl EntropySource for OsEntropy { /* calls getrandom::getrandom */ }

/// Convenience wrapper: fill `buf` using the OS CSPRNG.
///
/// Equivalent to `OsEntropy::new().fill(buf)`.
pub fn fill_random(buf: &mut [u8]) -> Result<(), EntropyError>;
```

## 3. Why There Is No Fallback RNG

TokenGen enforces a strict fail-closed security policy. If the operating system CSPRNG fails or indicates that sufficient entropy is not yet gathered, any attempt to fall back to weaker entropy sources (such as userspace PRNGs, timestamps, or unseeded algorithms) would silently generate predictable keys. Failing immediately with an explicit error ensures that compromised or low-entropy secrets can never be created or presented to the user.

## 4. Why the `EntropySource` Trait Exists

The `EntropySource` trait enables pure dependency injection exclusively for automated testing and fuzzing. It allows unit test harnesses to inject controlled mock failures and boundary edge cases without modifying production execution paths. In release binaries, callers interact with the zero-overhead `OsEntropy` implementation or the `fill_random` convenience wrapper.

## 5. What This Module Explicitly Does NOT Do

- Key generation (F2)
- Charset selection (F2)
- Rejection sampling (F2)
- Zeroization of caller-owned buffers (F3)
- Memory locking / `mlock` / `VirtualLock` (F3)
- Core dump disabling (F3)
- USB presence monitoring (F3.5)
- Host footprint elimination (F3.6)
- Any UI, CLI, or config (F4, F7, F10)
- Any launcher or signature verification (F7.5)
- Any network, disk, env, stdin, or process interaction (never, in any feature)

## 6. Invariants

| # | Invariant | F1 Compliance |
|---|---|---|
| G1 | No network access, ever | No network crates; no network symbols. |
| G2 | No disk writes of key material | F1 writes nothing anywhere. |
| G3 | Fail closed on crypto/RNG errors | Returns `Err(EntropyError::OsFailure(_))`; no fallback, no retries. |
| G4 | Zeroize sensitive buffers | Caller's responsibility (F3); F1 retains no buffers across calls. |
| G5 | CSPRNG from OS only | `getrandom` exclusively. |
| G7 | Single portable binary per OS | F1 is an internal library crate with no runtime footprint. |
| G8 | Reproducible builds + signed releases | Compiles with `--locked` and strict dependency pinning. |
| G10 | No telemetry, analytics, crash reporting | F1 prints nothing, logs nothing, reports nothing. |
