# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's **private vulnerability reporting** for this repository:
**Security** tab → **Report a vulnerability**.
(<https://github.com/X404V2000/passkey_generator/security/advisories/new>)

This is a **private** channel: the report is visible only to the maintainers until it is resolved and, if
appropriate, published as an advisory with credit to you.

If you cannot use GitHub's private reporting, open a **minimal** public issue saying only that you have a
security report and would like a private channel — **no details** — and one will be provided.

## What to include

* What you found, and **how to reproduce it** — the smallest sequence that shows the problem.
* The **commit** or release you tested, and the **platform** (Linux; Windows and macOS currently have no
  backends — see below).
* Whether the problem is already public, and whether you intend to publish.
* How you would like to be credited, or that you would prefer not to be.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | **within 7 days** |
| An initial assessment — is it a defect, is it in scope, what severity | **within 30 days** |
| A fix or a dated plan for one | **within 90 days**, or an explanation why not |

These are targets, not guarantees. This is a small project and there is **no bounty** — reporting a
vulnerability here will not be paid, and this document will not imply otherwise. If a target slips, you will
be told rather than left waiting.

If you believe a vulnerability is being exploited, say so in your report and it will be prioritised.

## Supported versions

**There is no supported release yet.** Version 1.0 has not shipped, and the release gate
(`plan/PROJECT_PLAN.md` §8) is still open. The repository is public so the work can be reviewed, not because
there is a usable product.

Until a release exists, **the only supported version is the current `main`** — a report against any other
commit will be assessed against `main`.

## Scope

**In scope:**

* The **Rust** implementation — `src/`, `tokengen-sys/`.
* The generation of secrets and passkeys — entropy, charset/rejection sampling, and any path that could
  bias, leak, or repeat output.
* **Memory hygiene** — zeroization (G4), memory locking (G14), core-dump suppression (G15).
* The **session guard** — device identity binding, and any way a session could continue when it should stop
  (G16, G17).
* The **distribution pipeline** — the CI matrix, release signing, checksums, and the reproducibility claim.

**Out of scope:**

* **`legacy/python/`** — a non-runnable reference for the WebAuthn/CBOR encoding. The Python runtime itself
  was deleted (AM-009) because it violated G3. What remains is **unmaintained**, is **not part of the tool**,
  and is not installed by any packaging path. It violates G3 by design and its own README says so. Reports
  about it will be closed as out of scope; see `legacy/python/README.md`.
* **Documented limitations.** `README.md` → *"What This Tool Cannot Do"* lists what this tool explicitly
  does not do, including platform gaps and residual risks. **Reporting a documented limitation is not
  reporting a vulnerability** — though if you think a limitation is *understated*, that is a defect in the
  documentation and is worth reporting as one.
* Anything requiring an attacker who already has root, kernel, or physical control of the machine, except
  where the project claims otherwise in its documented threat model.

## ⚠️ Platform status — read before testing

**Only Linux has a device backend.** Windows and macOS currently build and then **refuse** with
`NotSupported`: there is no memory locking, no core-dump suppression, and no device identity on those
platforms. The code is compiled by CI on all three, but **nothing on Windows or macOS has been executed**.

**Compiled is not verified.** A report that Windows or macOS "does not work" is correct, known, and already
recorded — it is the F3.7 work, not a vulnerability.

## What this project does and does not claim

**Does:**

* fails **closed** — when a security mechanism is unavailable, the tool refuses rather than continuing
  degraded. This is invariant G3 and it is the single most important property here;
* ships **no telemetry** and makes no network calls;
* signs releases and publishes checksums, and intends reproducible builds (G8).

**Does not:**

* claim to defend against a compromised kernel, hypervisor, or hardware that can read physical memory;
* claim that a device which controls its own identity cannot be cloned;
* claim any guarantee on a platform whose backend does not exist.

The authoritative list of what is **not** guaranteed is `README.md` → *"What This Tool Cannot Do"*. **Read it
before testing** — it will save you time and avoid a report about something the project has already told you
it does not do.

## Hardening already in place

Reporters sometimes find the same classes of issue repeatedly. These are known, and are **not**
vulnerabilities unless you can show the mitigation fails:

* the test suite asserts that **only `Present`** permits a session to continue, and that `dev-mode` can never
  present as `Present`;
* the build **refuses to compile** `dev-mode` without an explicit acknowledgement variable, so a release
  binary cannot acquire the guard-disabling path by accident;
* device identity is compared as a **device property, not a credential** — it is not treated as a secret,
  and the reason is recorded in the design document rather than left implicit.
