# Appendix — the legacy Python implementation, and why it was removed

The Python implementation that preceded the Rust workspace is **no longer in this repository**. This appendix
is the durable record of why, so the decision stays auditable without shipping code that must not be run.

It was deleted on 2026-10-23. It remains in git history and in the maintainer's backup.

---

## The defect that decided it

`legacy/python/passkey_gen/memory.py` did this:

```python
try:
    _mlock = libc.mlock
    ...
except Exception:
    # Gracefully degrade to managed Python memory wiping if libc functions are unavailable
    pass
```

**Memory-locking failure was swallowed.** And again when obtaining the buffer address:

```python
try:
    c_char_array = (ctypes.c_char * buf_len).from_buffer(buf)
    addr = ctypes.addressof(c_char_array)
except Exception:
    addr = None
```

**G3 is fail-closed.** A tool that cannot hold a secret in locked memory must **refuse**, not continue with a
weaker guarantee while reporting success. This is the false-assurance class — the failure this project treats
as its worst — and it sat in the implementation a user would have received by `pip install`.

## Why it could not simply be fixed

* **Zeroization could not be enforced.** `WebAuthnPasskey.destroy()` dropped a reference without wiping; a
  `bytes` object cannot be reliably overwritten in CPython, and copying it to make it wipeable creates another
  copy that also cannot be wiped.
* **Constant-time comparison was unavailable.** Python has no guaranteed constant-time primitive in the
  standard library, and `==` on `bytes` short-circuits.
* **`mlock` could not be sound.** The garbage collector may move objects, so a locked address is not the
  address the data occupies later. Rust's `Zeroizing<T>` on a stable allocation is sound; this was
  best-effort masquerading as a guarantee.

## Secondary reasons for deletion

* **Its tests never ran.** Nine test files, no CI step. Green ticks would have been imaginary.
* **The code contradicted its own README.** A file saying *"Do not use this code"* inside a security
  repository invites exactly that.
* **Nothing depended on it.** The Rust workspace never referenced it.

## What replaced it

The Rust workspace (`src/`, `tokengen-sys/`, `tokengen-cli/`), where these properties are **type-system and
compile-time obligations** rather than runtime hopes. See `docs/LANGUAGE_DECISION.md` for the full reasoning.

## What still guards against a recurrence

`tests/f39_trust_path.rs` asserts that **no packaging path binds to a Python entry point**
(`pyproject.toml` carries no `[project.scripts]`) and that the package finder cannot collect a legacy package.

Those tests remain, which is why deleting the code did not remove the protection —
**the guard was always about the path, not the files.**
