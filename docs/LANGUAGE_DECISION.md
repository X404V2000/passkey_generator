# Language Decision Record — TokenGen

**Status:** Decided
**Date:** 2026-10-02
**Decision owner:** Project maintainer
**Applies to:** All features F1–F10, and the disposition of the legacy Python implementation

---

## 1. Decision

**Rust (Edition 2021, MSRV 1.75) is the implementation language for the entire TokenGen product.** This was already the declared stack in §7 of the project handoff and is reaffirmed here as a deliberate, documented choice rather than an inherited default.

**The Python implementation under `src/passkey_gen/` is removed from the trust path and is not a supported deliverable.**

---

## 2. Context

TokenGen is now an **open-source project intended for use by thousands of people**, not a hackathon submission. That change raises the cost of an incorrect security claim from "a footnote in a demo" to "a published vulnerability report against software people relied on."

Two implementations currently coexist in this repository:

| | Python (`src/passkey_gen/`) | Rust (`src/`) |
|---|---|---|
| Language | Python 3.10+ | Rust 1.75+ |
| Dependencies | `cryptography`, `cbor2` | `getrandom` |
| Status | Packageable (`pip install -e .`), publishes a `passkey-gen` console script | F1 frozen, F2 frozen |
| Git-tracked | Yes, in full | Yes |
| Tests | ~563 LOC | 18 unit tests, all passing |

The question this record answers: should the project continue in Rust, remain in Python, or support both?

---

## 3. Why Rust

The decision is not a matter of preference. Three of TokenGen's own published invariants are **not satisfiable in Python**, and a security tool may not ship claims it cannot meet.

### G4 — "Zeroize all sensitive buffers on drop"

Rust: `Zeroizing<T>` from the `zeroize` crate wipes on drop, enforced by the type system, with no path that skips it. `Vec<u8>` is owned and mutable, so the bytes are always reachable and overwritable.

Python: `str` and `bytes` are **immutable and interned**. Once a secret reaches a `str`, it cannot be wiped — the object may be shared, cached, or copied by the interpreter, and CPython does not zero freed memory. Any library returning a `str` or `bytes` creates an unwipeable copy.

### G9 — "Constant-time comparisons for secrets"

Rust: the `subtle` crate provides `ConstantTimeEq` types. Non-constant-time comparison of those types is a visible, reviewable deviation.

Python: CPython offers no constant-time guarantee. `hmac.compare_digest` is a single function, not a discipline, and nothing prevents `==` from being used elsewhere.

### G14 — "Memory locked for key buffers"

Rust: `mlock` on an owned, fixed buffer is sound — the address is stable.

Python: `mlock` can only be reached through `ctypes`, and the interpreter's GC may still move or copy objects. Locking a Python-managed buffer does not guarantee the secret stays in the locked page.

### Mechanical verification

Rust's `#![forbid(unsafe_code)]` is **compiler-enforced**. Rust's dependency policy is checkable by `cargo deny`. For a project with thousands of users, guarantees a reviewer can verify mechanically are the only ones that survive scrutiny. Python's equivalent guarantees are checkable only by reading every line and hoping no `str` escaped — which is exactly the failure mode documented in §4.

### Hardware-facing features

F3.5 (USB presence + identity binding, G16/G17) requires reacting within one second to device removal, across Windows (`SetupAPI`), Linux (`libudev`/sysfs), and macOS (`IOKit`). A single portable binary (G7) with no interpreter and no GC pauses is required. G18's signature-verifying launcher (F7.5) is the component most likely to be attacked, and memory safety there is non-negotiable.

---

## 4. Findings That Forced the Decision

The following were verified by direct inspection of the current tree, not inferred.

### 4.1 `WebAuthnPasskey.destroy()` does not zeroize

`src/passkey_gen/webauthn.py`:

```python
def destroy(self) -> None:
    """Zeroize and discard the private key instance."""
    if self._destroyed:
        return
    self._private_key = None   # drops the reference; wipes nothing
    self._destroyed = True
```

Setting a reference to `None` does not zeroize memory. Specific consequences:

- `zeroize_buffer` is **imported at module level but never called anywhere in this file** — the import creates the appearance of zeroization without performing it.
- `webauthn.py` contains **no `mlock` and no `ctypes` usage**, so G14 is not addressed for private keys.
- The private key is a `cryptography` library object whose internal buffers are not reachable from Python and therefore cannot be wiped by any Python-level code.

### 4.2 Unwipeable secrets are returned to callers

- `export_private_key_pem()` returns `pem_bytes.decode("ascii")` — a **`str`** containing the private key, which can never be wiped (G4).
- `sign_assertion()` returns `bytes` derived from key material, also unwipeable.

### 4.3 `assert` in a signing path

`sign_assertion()` uses `assert isinstance(...)` to select the signing algorithm. `assert` statements are **stripped when Python runs with `-O`**, so the type check silently disappears. A security path must not depend on an assertion.

### 4.4 README claims zeroization that does not occur

`README.md` line 180 states, of a `WebAuthnPasskey` context block:

> `# Exiting the block immediately wipes and zeroizes the private key from memory!`

Per §4.1, this is false.

### 4.5 What is *not* a finding

For accuracy, `SecurePasskey.destroy()` in `src/passkey_gen/memory.py` **does** genuinely work: it calls `munlock` on a locked `ctypes` buffer, then calls `zeroize_buffer`, which reaches native `explicit_bzero`/`memset`. That module delivers what it claims. The defect is confined to `webauthn.py` and to the README's generalization of `memory.py`'s guarantee to code that does not implement it.

This distinction matters: the project's core memory-hygiene design is sound. The problem is a module that does not follow it while being documented as if it does.

---

## 5. Consequences

1. **Rust is the product.** F1–F10 proceed in Rust. F3 (`zeroize`, `mlock`, core-dump disable) and F3.5 (session guard) are the immediate priorities, and both are features where Rust's guarantees are load-bearing.
2. **Python is not a supported deliverable.** `src/passkey_gen/`, `tests/`, `pyproject.toml`, and the `passkey-gen` console script entry point must not be published as a security-equivalent implementation.
3. **`SECURITY.md` is required** before public release, with a real disclosure process and an explicit statement of the guarantees the Rust implementation provides and does not provide.
4. **The README requires correction** before further users arrive (§4.4). Overstated guarantees in a security tool are worse than absent ones.
5. **The "What This Tool Cannot Do" section must be extended** to state plainly that the Python implementation is unmaintained and must not be used.

---

## 6. Options Considered and Rejected

| Option | Rejected because |
|---|---|
| **Continue in Python** | Cannot satisfy G4, G9, or G14. Would require deleting those invariants from the documented contract, which defeats the project's purpose. |
| **Support both implementations** | A second, weaker implementation confuses users and doubles the audit surface. Users will install whichever is easier, which is `pip install`. |
| **Keep Python as `examples/`, clearly labelled** | Rejected *for the trust path*. A clearly-labelled, explicitly non-security reference may be revisited later, but it must not be installable as `passkey-gen`. |
| **Rewrite Python in Rust via FFI/PyO3 bindings** | Adds a dependency and a C-ABI surface (against G1/minimal-attack-surface) for no benefit to the primary use case, which is a portable standalone binary. |

---

## 7. Migration Plan

Ordered by risk. Not all steps need to land at once.

| # | Action | Priority |
|---|---|---|
| 1 | Add `SECURITY.md` stating the Rust guarantees; disclose the Python limitation | Immediate |
| 2 | Correct `README.md` §4.4 and remove Python install instructions as the primary path | Immediate |
| 3 | Remove the `passkey-gen` console script from `pyproject.toml`, or remove the file | High |
| 4 | Move `src/passkey_gen/` and `tests/` out of the trust path (delete or relocate to `legacy/` with a warning banner) | High |
| 5 | Port any capability unique to `webauthn.py` (COSE/JWK/PEM export) into Rust when a feature owns it | Tracked |
| 6 | Reconcile the handoff document's claims with the actual repository state | High |

**Note on step 5:** `webauthn.py` currently holds FIDO2/WebAuthn functionality (ES256, Ed25519, COSE, JWK, PEM) with no Rust counterpart and no feature in the current roadmap. It should be scheduled explicitly rather than lost, since deleting it without an owner silently drops a capability.

---

## 8. What This Decision Does Not Do

- It does not delete any code. Removal is a separate, reviewable change.
- It does not resolve the repository's current documentation inconsistencies, which are tracked separately.
- It does not amend any frozen feature. F1 and F2 are unaffected by this record.

---

## 9. Review Trigger

This decision should be revisited if:

- The project adopts a wasm or browser deployment target, where the calculus differs.
- A contributor demonstrates that a Python implementation can satisfy G4, G9, and G14 with mechanical verification.
- The roadmap changes such that the primary distribution model is no longer a portable standalone binary.
