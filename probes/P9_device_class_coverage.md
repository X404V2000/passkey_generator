# Probe P9 — device-class coverage

**Run:** 2026-10-18, on the maintainer's host with three USB drives and one internal NVMe attached.
**Purpose:** not to confirm that the attached drives work, but to determine **which classes of device are
untested** — and whether any of those gaps could hide a defect like DEFECT-012.

**Re-runnable:** the tables below were produced from `lsblk`, `/sys/block/*` and `tokengen_sys::device::*`.
A script that reproduces the matrix is a natural follow-up; this record is the measured snapshot and the
reasoning about it.

---

## 1. The class space

A drive's treatment depends on the cross-product of:

| axis | values |
|---|---|
| transport | `usb`, `mmc`, `nvme`, `sata`, unknown |
| disk serial | present (`Disk`), absent with a bridge serial (`Enclosure`), neither (**refused**) |
| serial source format | plain text `device/serial`, binary `vpd_pg80`, USB bridge `…/serial`, none |
| removable flag | `1`, `0` (the HDD is USB with `RM=0`) |
| partition layout | none, one, many, LUKS, LVM, no filesystem |

## 2. What was measured

| disk | transport | `vpd_pg80` | `device/serial` | `wwid` | RM | partitions | verdict | binds at |
|---|---|---|---|---|---|---|---|---|
| `sda1` | usb | **binary 24 B** | absent | present | 1 | 1 (LUKS) | **ACCEPT** | Disk |
| `sdb1` | usb | absent | absent | absent | 1 | 1 | **ACCEPT** | **Enclosure** |
| `sdc1` | usb | **binary 20 B** | absent | present | **0** | 1 | **ACCEPT** | Disk |
| `nvme0n1p2` | nvme | absent | **present** | absent | 0 | 2 | **REFUSE** (internal) | — |

**Confirmed on real hardware:**

* A **LUKS** partition is accepted — the filesystem UUID is read from `/dev/disk/by-uuid` for the *partition*,
  not its contents, so encryption is irrelevant to identification. (Covered **by accident** until now.)
* `sdc` is a USB drive with **`RM=0`** and is still accepted: the **removable flag is not authoritative**,
  transport is. This is the rule F3.5 chose, now exercised.
* `sda` exposes **`vpd_pg80` with no `device/serial`**; `nvme` exposes **`device/serial` with no `vpd_pg80`**.
  Both orders of the serial path occur in real hardware.
* A **whole disk with no filesystem** yields `UuidNotFound` with `component = FilesystemUuid` — a *named*
  component, not a generic error. (Exercised on all three USB disks without formatting anything.)

## 3. The gap this probe was really for — DEFECT-012's condition

DEFECT-012 arose because the enclosure walk could return the **host controller's** serial, identical for every
drive on that controller. **Two attached drives (`sda`, `sdb`) share the `usb1` controller**, so the condition
is present on this machine and was exercised:

```
sda1 serial=03022028102425210844  source=Disk        pci_shaped=false
sdb1 serial=1223907121600042      source=Enclosure   pci_shaped=false
identical_serial=false   identical_uuid=false
```

**Two drives on one controller now produce distinct identities, and neither is controller-shaped.**

## 4. Classes still untested — stated, not implied

| # | Class | Why it is untested | Risk |
|---|---|---|---|
| 1 | plain `device/serial` on a **removable** drive | only the internal NVMe has one, and it is refused | the Disk path via plain text is unverified on an accepted drive |
| 2 | **MMC / eMMC** (SD cards) | no such hardware | transport handling wholly unexercised |
| 3 | **SATA** attached directly | no such hardware | as above |
| 4 | **multiple partitions** on one removable drive | every removable drive here has exactly one | a UUID lookup could match the wrong partition — **the most likely place for a real bug** |
| 5 | a drive **inserted while the tool runs** | requires an interactive session | the poll-loop race is untested |
| 6 | a drive whose serial is a **non-ASCII or very long** string | not available | encoding assumptions unverified |

## 4a. The LUKS case, resolved — correct, but for an unrecorded reason

`sda1` is LUKS. Two UUIDs are in play:

| node | UUID | exists when |
|---|---|---|
| `/dev/sda1` — the raw **container** | `97f65252-…` | always |
| `/dev/mapper/luks-97f65252-…` → `dm-0` — the **filesystem inside** | `25e8a061-…` | **only while unlocked** |

`uuid_for_device("/dev/sda1")` returns the **container** UUID, and that is **the right choice**:

* it is **always available**, unlocked or not — `dm-0` does not exist when the drive is locked;
* it is **stable across lock/unlock cycles**, because locking does not touch the raw partition;
* it cannot be changed without re-encrypting the container.

**It was chosen by exact-path match, not by that reasoning.** The code looks up the canonical path of the
*partition node* and returns whatever UUID links to it; the container UUID happens to be that. A future change
— for example "also accept the UUID of a dm-crypt child", which looks like a harmless robustness improvement —
would make the identity depend on whether the drive was unlocked, and a **re-locked drive would then appear
to be a different device**. This is recorded here so that change is visibly a change.

**Multi-partition confusion, the risk P9 expected to find, does not exist:** the lookup is an exact
`dest == target` comparison on canonicalised paths, so a disk with many partitions yields the UUID of *that*
partition or `UuidNotFound`. Nothing can be mismatched.

## 5. What P9 changes

**Nothing in the code.** Its value is the negative result — the table of classes *not* covered — which is what
a release decision has to rest on. Class 4 (multiple partitions on one removable drive) is the most likely to
hide a defect, because `uuid_for_device` performs a reverse lookup across `/dev/disk/by-uuid` and a
multi-partition disk gives it more than one candidate to confuse.
