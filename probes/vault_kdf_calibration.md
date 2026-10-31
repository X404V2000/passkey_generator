# Probe — Vault KDF calibration and atomic-write guarantees

**Purpose:** close Bruce's blockers **B1** (Argon2id parameters must be measured) and **B2** (atomic-write
guarantees on USB filesystems must be measured) *before* any vault format is frozen.

**Method:** measured on the maintainer's hardware and on the real USB drives attached at the time, not
reasoned about.

---

## B2 — Atomic writes on a real USB stick: **PASSED**

The two attached drives are both **`ntfs3`**. On `/media/…/125GB`:

| Step | Result |
|---|---|
| write temp file + `fsync` | OK |
| **`fsync` the directory** | **OK** |
| **`os.replace` (atomic rename)** | **OK** |
| cleanup | OK |

**This is good news, but it is not a general result.** `ntfs3` is a kernel driver on Linux; the same stick on
Windows uses a different driver, and FAT32/exFAT have weaker rename and directory-fsync semantics than NTFS.

**Verdict for the blueprint:** the sequence *write-temp → fsync → rename → fsync-parent → keep previous good
copy* is **viable on the tested configuration**. It must be **re-probed per filesystem and per OS** before the
vault ships on that combination, and the vault must **refuse to write** on a filesystem where the sequence
cannot be confirmed — rather than writing and hoping.

---

## B1 — Argon2id parameters: **THE IMPORTANT FINDING**

### This hardware

| | |
|---|---|
| CPU | **Intel Celeron N4020 @ 1.10 GHz — 2 cores** |
| RAM | 7.6 GiB (≈4 GiB available) |

Measured memory-bandwidth proxy (allocate + fill, one pass):

| Buffer | Time |
|---|---|
| 64 MiB | 0.045 s |
| 256 MiB | 0.131 s |
| 1024 MiB | 0.584 s |

### Why this matters more than the numbers

**RFC 9106's first recommendation is `m=2 GiB, t=1, p=4`.** On this machine:

* **`p=4` is impossible** — there are **2 cores**. Argon2id's parallelism has no threads to use, so the
  parameter buys nothing and costs honesty.
* **2 GiB is not reliably allocatable** — ~4 GiB is available, and a vault must not fail to open because
  another application was running.

**A KDF parameter set chosen on a developer's fast machine will either be slow enough to be unusable on this
class of hardware, or weak enough to be useless.** This is the same class of error as the earlier
`rust-version = "1.75"` claim that was never measured.

### The design consequence — this is the finding

**The parameters must be chosen for the WEAKEST supported device, not the strongest.**

The vault must therefore record its own parameters in the header, and the reader must:

1. **read the parameters from the vault**, never assume a default;
2. **refuse** if the recorded cost is below a compiled-in floor (a downgrade attack);
3. **warn** if it is far above what this machine can do in a stated time budget — and still attempt it.

**A vault created on a fast machine must open on a slow one.** That is the availability requirement (S1–S4)
colliding with the confidentiality requirement, and the header is where the collision is resolved.

### What must be probed on real hardware before freezing

1. **Actual Argon2id timing** at candidate parameters on this machine — not the proxy above. Needs the
   `argon2` crate, which we are not adding yet.
2. **The slowest device we intend to support.** If that is a Raspberry Pi or an old laptop, calibrate there.
3. **Parameters must be validated against a time budget** (e.g. ≤ 2 s on the weakest device, and a higher
   cost for exports, which are attacked offline with more time).

**No parameter value is proposed here.** Proposing one without measuring it on the intended target is exactly
the guess this project has already been burned by.

---

## B1 — MEASURED (retrospective post-dated; see T-0004 phase 0)

Measured with `argon2 0.5.3` (dev-dependency only) on 2026-10-31, `cargo test -p tokengen --test
argon2_calibration -- --nocapture --ignored`, median of 3, release build.

| Configuration | Median | Work (KiB·t) |
|---|---|---|
| RFC-9106 #2 (`m=64MiB t=3 p=4`) | 0.370 s | 196 608 |
| `64MiB t=3 p=2` | 0.375 s | 196 608 |
| `64MiB t=1 p=2` | 0.135 s | 65 536 |
| `128MiB t=3 p=2` | 0.805 s | 393 216 |
| `256MiB t=1 p=2` | 0.659 s | 262 144 |
| **`256MiB t=2 p=2`** | **1.092 s** | **524 288** |
| `512MiB t=1 p=2` | 1.218 s | 524 288 |
| RFC-9106 #1 (`m=1GiB t=1 p=2`) | 2.603 s | 1 048 576 |

### What the numbers show

**`p=4` buys nothing here.** `RFC-9106 #2` with `p=4` takes **0.370 s**; the same work with `p=2` takes
**0.375 s** — indistinguishable, because there are only two cores. Recording `p=4` in a vault header would be a
claim about parallelism the hardware cannot honour.

**`t=1` at high memory is not equivalent to `t>1` at lower memory**, even at equal `m·t`. `512MiB t=1` and
`256MiB t=2` both score 524 288 but differ: time-memory tradeoff resistance is better with more iterations,
because an attacker's ASIC/GPU gains less from trading memory for recomputation. **Prefer iterations over raw
memory once the window is reached.**

**RFC-9106 #1 is unusable here** at 2.6 s for a single unlock.

### Proposed starting point (for Bruce and Grace to attack, not a frozen value)

`m = 256 MiB, t = 2, p = 2` → 1.09 s on this hardware.

* inside the 250 ms – 2 s user budget;
* more iteration depth than the `t=1` alternatives at similar cost;
* leaves headroom for slower devices — a device twice as slow would take ~2.2 s, which is why the **floor and
  the ceiling both go in the header** and the reader warns rather than silently accepting a weaker one.

**Still required before freezing:** a measurement on the **weakest device we intend to support**, and the
export's parameters (which should be *higher*, because an export is attacked offline at leisure).

### MSRV constraint discovered

`argon2 0.6.0` pulls `ctutils`, which **requires rustc 1.87**. The project pins **1.85.1**. The probe therefore
uses **`argon2 0.5.3`**.

**Consequence for the blueprint:** adopting the newest `argon2` means raising the declared MSRV — which this
project has already been burned by once (`rust-version = "1.75"` was false for months). Raising the MSRV is a
decision with a blast radius, not a dependency bump.

## Bruce's ruling

* **B2 closed** for `ntfs3` on Linux; **re-probe required** per filesystem/OS combination.
* **B1 NOT closed.** This probe establishes *why* it matters and *what must be measured*, not the values.
  **The vault format may not be frozen until real Argon2id timings exist on this class of hardware.**
