# Legacy Python implementation — **UNMAINTAINED. NOT PART OF THE TRUST PATH.**

**Do not use this code. It is not the tool.**

The supported implementation of TokenGen is the **Rust** workspace at the repository root
(`src/`, `tokengen-sys/`). This directory is the **original Python prototype**, kept for reference only.

## Why it is here, and not deleted

It is the only **end-to-end** exercise of the WebAuthn/CBOR passkey generation that exists in this
repository. **F4** rebuilds that behaviour in Rust, and will want a reference for how it was wired.

That is the whole reason. It is not here because it works, is supported, or should be run.

## Why it is not the installed command

Until this change, `pyproject.toml` carried:

```toml
[project.scripts]
passkey-gen = "passkey_gen.cli:main"
```

so `pip install .` produced a `passkey-gen` command bound to **this** code. That is recorded risk **R7** —
*"the legacy Python path is installed instead of Rust"*.

The entry point has been **removed**, and this code moved out of `src/`. `pip install .` now creates **no
runnable command at all**. That is deliberate: the Rust CLI does not exist yet (it is F4), and installing
**no** command is honest where installing the **wrong** one is not.

## The reason it cannot be the tool — G3

`passkey_gen/memory.py` contains:

```python
except Exception:
    # Gracefully degrade to managed Python memory wiping if libc functions are unavailable
    pass
```

**"Gracefully degrade" is the opposite of this project's first invariant, G3 (fail-closed).** When `mlock`
is unavailable, this implementation **continues without it**, and the CLI reports the state next to other
`[SECURE]` lines:

```
[*] Linux Process Defense Audit:
  - Core Dumps Disabled (RLIMIT_CORE=0): [SECURE]
  - Memory Lock Available (mlock):       [UNAVAILABLE]
```

| | when the mechanism is unavailable |
|---|---|
| **Rust (the project)** | returns `Err(NotSupported)`; **the guard refuses to run** |
| **this prototype** | runs anyway, degraded, with no refusal |

A user of this code gets a tool whose central guarantee is **conditional**, and nothing stops them. That is
the false-assurance failure mode the project treats as its worst defect.

**Stated fairly:** this code attempts zeroization and `mlock` in good faith, and its behaviour is a
reasonable choice for a different project. It is wrong for **this** one, whose invariants forbid it. It is
not excluded because it is Python; it is excluded because it **cannot honour G3** without a rewrite, and no
one has asked for that rewrite.

## The tests here do not run

`legacy/python/tests/` holds nine test files. **No CI job runs them, and they cannot run without `pytest`
and the Python dependencies installed.** They are inert.

They are recorded here explicitly so nobody mistakes their presence for coverage. `pyproject.toml` no longer
configures `pytest` for this directory at all.

## If you are looking for the tool

* **Design and guarantees:** `docs/` and the repository `README.md`.
* **What the tool cannot do:** `README.md` → "What This Tool Cannot Do". Read this before trusting anything.
* **Security reports:** `SECURITY.md` at the repository root.
* **Roadmap:** `plan/PROJECT_PLAN.md`.

## Decision record

Removal from the trust path: **F3.9** (`plan/reports/F3.9/`) and **D-P12**
(`plan/founder_office/decisions/`). Risk register entry: **R7** (`plan/PROJECT_PLAN.md`).
