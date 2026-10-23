# F4 Completion Report — the CLI Interface

| | |
|---|---|
| **Feature** | F4 — the first user-facing surface |
| **Status** | **FROZEN** — anchored to commit `9a304d6` |
| **Supersedes** | the earlier freeze at `8ec7cdb`, which is **no longer reachable** (removed by the history purge) |
| **Gates** | run from an extracted copy, cold rebuild, rustc 1.85.1 recorded — **all ten pass** |
| **CI** | green on all five jobs, all three platforms |
| **Production cryptography** | **none added.** F4 wires frozen library capabilities to a terminal. |

---

## 1. What was built

`tokengen generate` — a separate binary crate (`tokengen-cli`), with subcommands because F5–F8 add
*actions* (`verify`, `config`, `doctor`) that a bare-flags CLI could not grow into without breaking the
interface users will script against.

**The library's print deny stays absolute.** The binary's print exceptions live in its own manifest, where a
reviewer of the security-critical code will not trip over them (D-P13).

## 2. The contract, measured at the freeze point

| Case | Exit | Meaning |
|---|---|---|
| success from a removable device | 0 | a secret, once |
| internal disk (real block device, fixed) | **3** | security refusal |
| working directory with **no block device** (tmpfs/overlay) | **4** | no device to bind to |
| macOS / Windows (no backend) | **4** | platform cannot provide |
| bad flag, bad length, bad charset | **2** | usage |
| `status`, `help`, `version` | **0** | they report; reporting is their job |
| entropy/generator failure | 5 | generation |

**One rule, no exceptions: a non-zero exit leaves stdout empty.** Re-verified at `9a304d6`: **zero
violations** across every failing invocation.

⚠️ Note for anyone re-running the gate: extracted to `/tmp`, `generate` returns **4**, not 3 — `/tmp` is a
tmpfs, so there is no block device to bind. That is AM-007 behaving correctly, not a regression. **The gate
standard now requires running this suite from both a tmpfs and a disk checkout** (failure-table entry 15).

## 3. Changes to F4 after the first freeze

The original freeze at `8ec7cdb` was overtaken by two amendments that change the CLI's behaviour and match
arms. Both are recorded rather than silently folded in:

| Amendment | Effect on F4 |
|---|---|
| **AM-007** | `SessionError::NoBlockDevice` added → a new match arm returning exit **4** with an accurate message (a tmpfs path is not "a missing device") |
| **AM-008/AM-010** | `SerialSource` carried through the session layer; `tokengen status` now prints **which binding level the user has** and what it does and does not detect |

## 4. Defects found and closed across F4's life

| # | Defect | Found by |
|---|---|---|
| 1 | **DEFECT-006 repeated** — the CLI was *built* in CI and never *tested* | Ada, auditing CI |
| 2 | **DEFECT-007 repeated** — "a guard refusal exits 3" asserted universally | **CI** (macOS/Windows) |
| 3 | `cfg_check.sh` hard-coded the two crates it copied | local gate run |
| 4 | **`tmpfs` reported as `DeviceNotFound`** — a false cause | **Grace** |
| 5 | **`status` exempt** from the no-stdout-on-failure rule | **Grace** |
| 6 | **DEFECT-007 again, one layer deeper** — tests asserted **where they ran** | **the freeze procedure** |
| 7 | **DEFECT-005 repeated** — `set -e` in a PowerShell step; cargo never ran | **CI** (Windows) |
| 8 | **`serial_source` dropped** at the session boundary | Ada, closing AM-010 |
| 9 | Missing import in a trybuild fixture — local clippy passed, CI failed | **CI** (all three) |

**Seven of the nine were caught by a checker, not by a person.** That is the argument for building them.

## 5. What F4 does NOT establish

1. **The success path is unverified.** Generation from a removable device needs hardware; CI and this host
   had none attached during the run. The test is **announced as skipped**, never silently passed.
2. **The binding-level line is untested end to end.** `status` prints it only on a removable device, so the
   three unit tests cover the wording and the *call site* is unexercised.
3. **There is no passphrase prompt.** Deferred by D-P13: F3.5's contract requires polling *"even while
   blocked on input"*, `stdin` reads block, and a single-threaded CLI cannot meet it. F4 takes flags only.
4. **The dev-mode path was exercised on Linux only.**
5. **The TTY scrollback warning is untested interactively.**
6. **`tokengen-cli` is excluded from F3.6's static footprint check** — declared, printed and counted, because
   a terminal write is not a file write. Its behaviour is covered by the behavioural test instead.

## 6. Freeze statement

F4's **interface, exit codes and contract are frozen** from `9a304d6`. Changes require a recorded amendment.

**The freeze rests on the evidence above and no more.** Items 1 and 2 are the ones most likely to hide a
defect, and both need hardware this environment does not have.
