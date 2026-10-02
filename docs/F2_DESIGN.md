# F2 Design Document: Charset & Rejection Sampling Key Generator

## 1. Purpose

F2 turns raw random bytes from F1 into uniformly distributed character keys of a caller-specified length and character set. It is the module that produces the passkeys, tokens, and API keys TokenGen exists to generate. It does one thing: given an entropy source, a charset, and a length, it returns a key. Correctness here is not optional — a non-uniform mapping would leak structural information about the key and reduce its effective entropy.

## 2. Public API

```rust
/// A character set used for key generation.
///
/// The set is stored as a sequence of unique bytes. Duplicates are a
/// programming error and MUST be rejected at construction time.
pub struct Charset { /* private */ }

impl Charset {
    /// Construct a charset from a byte slice.
    ///
    /// Returns `Err(GeneratorError::EmptyCharset)` if the slice is empty.
    /// Returns `Err(GeneratorError::DuplicateByte)` if any byte repeats.
    pub fn new(bytes: &[u8]) -> Result<Self, GeneratorError>;

    /// The lowercase ASCII letters a–z (26 bytes).
    pub fn lowercase() -> Self;

    /// The uppercase ASCII letters A–Z (26 bytes).
    pub fn uppercase() -> Self;

    /// The digits 0–9 (10 bytes).
    pub fn digits() -> Self;

    /// The standard symbol set: `!@#$%^&*()-_=+[]{}<>?/|~` (24 bytes).
    pub fn symbols() -> Self;

    /// Length of the charset in bytes.
    pub fn len(&self) -> usize;

    /// True if the charset has zero bytes.
    ///
    /// A successfully constructed `Charset` is never empty, but this method is
    /// provided for API completeness and to satisfy clippy's `len_without_is_empty`.
    pub fn is_empty(&self) -> bool;
}

/// Error type for all key-generation failures.
#[derive(Debug)]
pub enum GeneratorError {
    /// The charset was empty.
    EmptyCharset,
    /// The charset contained a duplicate byte.
    DuplicateByte,
    /// The underlying entropy source failed.
    Entropy(crate::entropy::EntropyError),
    /// The requested length was zero.
    ZeroLength,
}

/// Generate a random key of `length` characters drawn uniformly from
/// `charset`, using `entropy` as the source of randomness.
pub fn generate_key<S: EntropySource>(
    entropy: &S,
    charset: &Charset,
    length: usize,
) -> Result<Vec<u8>, GeneratorError>;

/// Convenience wrapper: generate a key using the OS CSPRNG.
pub fn generate_key_os(charset: &Charset, length: usize) -> Result<Vec<u8>, GeneratorError>;
```

### 2.1 Amendment to §3 of the F2 specification

The specification declared `symbols()` as **26 bytes** in four places (§3 doc comment, §3 note, B4, and test 3) while listing the characters `!@#$%^&*()-_=+[]{}<>?/|~`, which number **24**. The character list is preserved verbatim and the count is corrected to 24. Rationale: the spec's own §3 note instructs "Count them before shipping," and the set is unique, so the count — not the character list — was the error. No API signature changes.

## 3. Why Rejection Sampling

Naive modulo (`byte % charset_len`) introduces bias whenever the charset length does not evenly divide 256. For a charset of size `n`, byte values below `256 % n` map to two outputs while the rest map to one, making some characters measurably more likely. Rejection sampling computes `limit = 256 - (256 % n)`, which is always an exact multiple of `n`, and discards every byte `>= limit`. Because each accepted byte is an independent uniform draw and `limit % n == 0`, the resulting index is uniform over `[0, n)`, so the output is uniform over all `n^length` possible keys.

## 4. Why `Charset` Validates Input

An empty charset has no valid output — there is no character to emit, so generation would either loop forever or fabricate a value. Duplicate bytes are subtler: modulo/rejection arithmetic assumes `charset[i]` identifies a unique outcome. If `b'a'` appears twice, then `n` overcounts the distinct outcomes and the uniformity proof no longer holds over *characters* — a caller reasoning about entropy from `charset.len()` would overstate the real keyspace. Both are rejected at construction time so that no later stage can receive an inconsistent charset.

## 5. What This Module Explicitly Does NOT Do

- Entropy sourcing (F1)
- Zeroization of output buffers (F3)
- Memory locking / `mlock` / `VirtualLock` (F3)
- Core dump disabling (F3)
- USB presence monitoring (F3.5)
- Host footprint elimination (F3.6)
- Default length / charset selection (F4/F7)
- Word-based (Diceware) generation (future feature, not F2)
- Display, clipboard, or storage of keys (F5/F6/F7)
- UI, CLI, config (F4, F7, F10)
- Launcher or signature verification (F7.5)
- Any network, disk, env, stdin, or process interaction (never, in any feature)

## 6. Invariants

| # | Invariant | F2 Compliance |
|---|---|---|
| G1 | No network access, ever | No network crates; no network symbols. |
| G3 | Fail closed on crypto/RNG errors | B9 — entropy error propagates, no retry. |
| G5 | CSPRNG from OS only | F2 uses only the injected `EntropySource`. |
| G8 | Reproducible builds + signed releases | F2 compiles with `--locked`, no new deps. |
| G10 | No telemetry, analytics, crash reporting | F2 prints nothing, logs nothing. |
| G2 | No disk writes of key material | F2 writes nothing. |
| G4 | Zeroize sensitive buffers | Not F2's job (F3). F2 returns `Vec<u8>`; caller wraps in `Zeroizing`. |
| G6 | No clipboard by default | N/A in F2. |
| G7 | Single portable binary per OS | F2 is a library module. |
| G9 | Constant-time comparisons for secrets | F2 performs no comparisons on secrets. Duplicate detection operates on the *charset*, not on secrets; constant-time is not required. |
| G11 | Zero files written outside USB mount | F2 writes nothing. |
| G12 | Zero registry / plist / dconf writes | F2 touches no OS config. |
| G13 | No MRU / recent-files integration | F2 touches no such APIs. |
| G14 | Memory locked for key buffers | Not F2's job (F3). |
| G15 | Core dumps disabled at startup | Not F2's job (F3). |
| G16 | Process exits on USB removal | Not F2's job (F3.5). |
| G17 | USB identity bound at startup | Not F2's job (F3.5). |
| G18 | Launcher verifies main binary | Not F2's job (F7.5). |

F2's responsibility is narrow: G1, G3, G5, G8, G10. Everything else belongs to later features.
