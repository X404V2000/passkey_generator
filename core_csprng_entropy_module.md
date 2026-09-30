# Blueprint: Secure Portable Token/Passkey Generator

**Version:** 1.0 (Draft)
**Purpose:** A blueprint precise enough that a local LLM (Gemini Flash) can generate production-quality code, feature by feature, without security regressions.

---

## 0. Global Design Principles (Apply to Every Feature)

These are **invariants**. Every feature must respect them. If a feature can't, it doesn't ship.

| # | Invariant | Enforcement |
|---|---|---|
| G1 | No network access, ever | No HTTP/TCP/UDP crates linked; CI grep audit |
| G2 | No disk writes of key material by default | Code review + unit test asserting no `write` calls on key paths |
| G3 | Fail closed on crypto/RNG errors | Rust `Result` propagation; never fall back to weak RNG |
| G4 | Zeroize all sensitive buffers on drop | `zeroize::Zeroizing<T>` on every key-bearing type |
| G5 | CSPRNG from OS only | `getrandom` crate exclusively; ban `rand::thread_rng` for keys |
| G6 | No clipboard by default | Explicit user action required |
| G7 | Single portable binary per OS | No installer, no registry, no `$HOME` writes |
| G8 | Reproducible builds + signed releases | CI pipeline + detached signatures |
| G9 | Constant-time comparisons for secrets | `subtle::ConstantTimeEq` |
| G10 | No telemetry, no analytics, no crash reporting | Stripped in build config |

---

## 1. Overall Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    generator (single binary)             │
│                                                          │
│  ┌────────────┐   ┌──────────────┐   ┌────────────────┐  │
│  │  UI Layer  │──▶│  Core API    │──▶│  Entropy Layer │  │
│  │ (CLI/GUI)  │   │  (pure fn)   │   │  (OS CSPRNG)   │  │
│  └────────────┘   └──────────────┘   └────────────────┘  │
│         │               │                    │           │
│         │               ▼                    ▼           │
│         │         ┌──────────────┐   ┌────────────────┐  │
│         │         │ Key Material │   │ Rejection      │  │
│         │         │  (Zeroizing) │   │ Sampling       │  │
│         │         └──────────────┘   └────────────────┘  │
│         │                                                │
│         ▼                                                │
│  ┌────────────────┐   ┌────────────────┐                 │
│  │  Display Layer │   │ Clipboard      │                 │
│  │  (render only) │   │ (opt-in only)  │                 │
│  └────────────────┘   └────────────────┘                 │
└──────────────────────────────────────────────────────────┘
```

**Three-layer separation is mandatory:**
- **Entropy Layer** — talks to OS, returns raw bytes.
- **Core API** — pure functions; takes bytes in, returns key material out. Fully unit-testable with injected entropy.
- **UI Layer** — never touches raw entropy; only calls Core API.

This lets you test the Core with deterministic entropy vectors, and swap the UI without touching crypto.

---

## 2. Feature List (Build Order)

We build **one at a time**, in this order, each fully finished before moving on:

| # | Feature | Why first |
|---|---|---|
| **F1** | **Core CSPRNG Entropy Module** | Everything depends on it. Get it right or nothing else matters. |
| F2 | Charset + Rejection Sampling Key Generator | The actual key production. |
| F3 | Zeroization & Memory Hygiene | Prevents leaks in RAM/swap. |
| F4 | CLI Interface | First usable surface. |
| F5 | Secure Display (screen-only, scramble-on-blur) | Prevents shoulder-surfing. |
| F6 | Optional Clipboard with Auto-Clear | Convenience without silent risk. |
| F7 | Portable Config (next to binary only) | Preferences without leaving traces. |
| F8 | USB Self-Verification Tool | Lets users verify the binary they downloaded. |
| F9 | Release Signing & Checksum Pipeline | Distribution integrity. |
| F10 | GUI (optional, later) | Friendly for non-technical users. |

---

# F1 — Core CSPRNG Entropy Module

**Goal:** A single, auditable module that returns cryptographically secure random bytes from the OS, with no fallbacks, no userspace PRNG, and hard failure on any error.

---

## 1.1 Purpose

Provide a minimal, dependency-light, memory-safe interface to the OS CSPRNG. This module is the **root of trust** for the entire application. If this is wrong, every key produced is compromised.

---

## 1.2 Functional Requirements

| ID | Requirement |
|---|---|
| F1-R1 | Return `N` cryptographically secure random bytes on request |
| F1-R2 | Source bytes exclusively from OS CSPRNG (`getrandom`) |
| F1-R3 | Return an error (never fall back) if OS entropy is unavailable |
| F1-R4 | Zeroize any temporary buffers used internally |
| F1-R5 | No global mutable state |
| F1-R6 | No logging of any byte produced |
| F1-R7 | Fully unit-testable with a mockable trait |

---

## 1.3 Non-Functional Requirements

| ID | Requirement |
|---|---|
| F1-N1 | No `unsafe` code in this module |
| F1-N2 | All public functions return `Result<_, EntropyError>` |
| F1-N3 | Zero heap allocation for buffers ≤ 256 bytes (use stack arrays) |
| F1-N4 | Compile-time: no features that pull in `std`-only or network code |
| F1-N5 | Test coverage ≥ 95% including error paths |

---

## 1.4 Algorithm

**High-level flow (single call):**

```
function fill_random(buf: &mut [u8]) -> Result<(), EntropyError>:
    if buf.is_empty():
        return Ok(())                      # no-op, not an error

    result = os_random(buf)                # getrandom::getrandom(buf)

    match result:
        Ok(())  -> return Ok(())
        Err(e)  -> return Err(EntropyError::OsFailure(e))
                                          # NEVER retry with weaker source
                                          # NEVER continue with partial data

# Caller is responsible for zeroizing buf after use.
```

**Why no retry loop:** A retry could mask a systemic OS entropy failure. Better to fail visibly.

**Why no fallback:** Any fallback (time, PID, userspace PRNG) defeats the entire purpose.

---

## 1.5 Data Types

```
// Opaque error type — no internal detail leaked to user unless desired
enum EntropyError {
    OsFailure(OsError),     // wraps platform error
    // (future) HardwareFailure, etc.
}

// Trait for testability — Core depends on this, not on getrandom directly
trait EntropySource {
    fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError>;
}

// Production implementation
struct OsEntropy;
impl EntropySource for OsEntropy {
    fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError> {
        // calls getrandom::getrandom(buf)
    }
}

// Test-only implementation (compiled only under #[cfg(test)])
struct MockEntropy { bytes: Vec<u8>, cursor: usize }
impl EntropySource for MockEntropy { /* ... */ }
```

---

## 1.6 Safety Measures Specific to F1

| Measure | Rationale |
|---|---|
| **No `unsafe`** | Removes an entire bug class; `getrandom` already handles syscall FFI safely. |
| **`EntropySource` trait** | Enables deterministic tests without weakening production code. |
| **Fail-closed errors** | Prevents silent weak-key generation. |
| **No buffer reuse across calls** | Each call fills a fresh buffer; caller zeroizes. |
| **No logging hooks** | Even debug logs are banned in this module. |
| **`#![forbid(unsafe_code)]`** at crate root | Compiler-enforced. |
| **`#![deny(clippy::print_stdout, clippy::print_stderr)]`** | Prevents accidental leakage via debug prints. |

---

## 1.7 USB-Protection Relevance

This module does **not** read from USB. It does **not** read from disk. It does **not** read environment variables. It only calls the OS CSPRNG syscall. That means:

- A malicious USB cannot influence entropy input.
- A malicious USB cannot intercept the bytes (they never touch the filesystem).
- The only attack surface is the OS syscall itself, which is outside your app's trust boundary and documented as such.

---

## 1.8 Test Plan

| Test | Type | Assertion |
|---|---|---|
| `fill_random_produces_bytes` | Unit | Buffer is not all zeros, no panic |
| `fill_random_empty_ok` | Unit | Empty slice returns `Ok(())` |
| `fill_random_1kb_ok` | Unit | 1 KB request succeeds |
| `fill_random_returns_error_on_failure` | Unit (mock) | Mocked OS failure returns `Err`, no fallback |
| `fill_random_no_reuse` | Unit | Two consecutive calls differ |
| `distribution_smoke` | Statistical | 1 MB of bytes passes a chi-square uniformity check (loose bound) |
| `no_network_symbols` | CI grep | Binary has no `socket`/`connect`/`http` symbols |
| `no_disk_write_in_module` | CI grep | No `File::create`, `write`, `fs::` in F1 source |

---

## 1.9 Public API (Frozen Contract)

Gemini Flash should generate **exactly** this surface for F1:

```
// entropy.rs
pub enum EntropyError { OsFailure(OsError) }

pub trait EntropySource {
    fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError>;
}

pub struct OsEntropy;
impl OsEntropy { pub fn new() -> Self }
impl EntropySource for OsEntropy { ... }

// Convenience free function for callers who don't need injection
pub fn fill_random(buf: &mut [u8]) -> Result<(), EntropyError>
```

Nothing else public. Nothing else exported. Minimal surface = minimal attack surface.

---

## 1.10 Dependencies (Locked)

```
getrandom = "0.2"      # only this crate
zeroize   = "1"        # for downstream use; not needed inside F1 itself
# (dev-dependencies)
# none beyond std for F1 tests
```

**No `rand`, no `rand_core`, no `ring`, no `openssl`.** Those may come later, but F1 stays minimal.

---

## 1.11 Cargo Configuration for F1

```
# Cargo.toml (relevant excerpts)
[package]
edition = "2021"
rust-version = "1.75"

[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
print_stdout = "deny"
print_stderr = "deny"
unwrap_used  = "deny"
expect_used  = "deny"
panic        = "deny"

[dependencies]
getrandom = "0.2"
```

---

## 1.12 Acceptance Criteria for F1

F1 is **done** when:

- [ ] All public API functions implemented as specified in §1.9
- [ ] All tests in §1.8 pass
- [ ] CI grep checks in §1.8 pass
- [ ] `cargo clippy -- -D warnings` clean
- [ ] `cargo audit` clean
- [ ] No `unsafe`, no `unwrap`, no `expect`, no `panic!`
- [ ] Module documented with `///` on every public item
- [ ] No logging, printing, or I/O in the module
- [ ] A one-page `F1_DESIGN.md` committed alongside the code

---

## 🔒 What F1 Explicitly Does NOT Do

To avoid scope creep that would weaken it:

- ❌ Does not generate keys (that's F2)
- ❌ Does not decide charset or length
- ❌ Does not zeroize caller buffers (caller's job; enforced in F3)
- ❌ Does not store anything
- ❌ Does not touch USB, disk, network, env vars, or stdin
- ❌ Does not implement its own PRNG

---

## Next Step

When you're ready, prompt your local Gemini Flash with:

> **"Implement F1 exactly as specified in the F1 section of this blueprint. Produce `entropy.rs`, `Cargo.toml`, and `F1_DESIGN.md`. Do not add anything not in the spec. Do not use any crate other than `getrandom`."**

Then paste the generated code back here and I'll review it for:
- Compliance with every invariant (G1–G10)
- Hidden risks in the implementation
- Whether it satisfies all F1 acceptance criteria

Once F1 is verified and frozen, we move to **F2 — Charset + Rejection Sampling Key Generator**.

Ready when you are.
