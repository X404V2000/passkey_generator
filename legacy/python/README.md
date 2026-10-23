# Legacy Python — **REFERENCE ONLY. NOT RUNNABLE. NOT PART OF THE TRUST PATH.**

**This is not the tool, and it does not run.** The supported implementation of TokenGen is the **Rust**
workspace at the repository root (`src/`, `tokengen-sys/`, `tokengen-cli/`).

## What is actually in this directory

| File | Purpose |
|---|---|
| `passkey_gen/webauthn.py` | The **WebAuthn/CBOR** encoding — the algorithmic reference the Rust implementation will be checked against |
| `passkey_gen/charsets.py` | The character-set definitions, for the same reason |

**Nothing else survives.** See AM-009.

## What was removed, and why

The rest of the original prototype was **deleted** on 2026-10-23:

`memory.py`, `clipboard.py`, `display.py`, `process.py`, `cli.py`, `generator.py`, `__init__.py`, and all nine
test files.

**`memory.py` violated G3 — fail-closed — and could not be fixed:**

```python
except Exception:
    # Gracefully degrade to managed Python memory wiping if libc functions are unavailable
    pass
```

A tool that cannot lock its memory must **refuse**, not continue with a weaker guarantee while reporting
success. In another branch it swallowed the failure to obtain the buffer address entirely. That is the
false-assurance class this project treats as its worst defect.

The other runtime modules carried the same swallowed-exception shape, and the tests **never ran** — there was
no CI step for Python, so any green result would have been imaginary.

**Deleting the unsafe runtime is now possible precisely because this file no longer imports it.** The CBOR
encoding below never depended on `memory.py`; the import there was incidental.

## Why these two files were kept

They are the only **end-to-end** exercise of WebAuthn/CBOR passkey generation in this repository. When that
behaviour is rebuilt in Rust it will want a reference for how it was wired — **as an algorithm, not as a
program**.

**Treat them as a specification written in Python syntax.** Copy the structure; do not import, execute, or
trust them.

## This is still guarded

`tests/f39_trust_path.rs` asserts that **no packaging path binds to a Python entry point** — `pyproject.toml`
carries no `[project.scripts]` — and that the package finder cannot collect anything from here. Those tests
pass with only these two files present.
