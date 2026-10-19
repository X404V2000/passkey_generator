# F3.5 Platform Probes — Linux

**Host:** `Linux 6.12.107+deb13-amd64 x86_64` (Debian, NVMe root)
**Date:** 2026-10-02
**Purpose:** the artifacts required by the "Probes and Evidence" section, per
the F3.5 design directive §6 and §8.

Every claim the F3.5 blueprint makes about platform mechanics must be backed by one of: **a probe
committed here**, **a citation**, or an explicit **stated limitation**. An unlabelled assertion is not
acceptable.

Reproduce with `bash probes/linux_device.sh`.

---

## P1 — `blkid` is absent, and cannot be the UUID source

```
$ command -v blkid
(no output — not installed)
```

**Claim supported:** `blkid` must not be the Linux UUID mechanism.

**Why:** `blkid` is an external binary from `util-linux`, not guaranteed present. Shelling out to it
violates **G7** (single portable binary, no dependence on host utilities), and its presence-dependent
behaviour means the tool fails *open or closed unpredictably* depending on the host — worse than
either consistent outcome.

**Status:** probed. The engineer's §6.1 finding is confirmed.

---

## P2 — `/sys/block/*/serial` does not exist

```
$ ls /sys/block/*/serial
ls: cannot access '/sys/block/*/serial': No such file or directory
```

**Claim supported:** the draft's serial path is wrong.

**Status:** probed. This is the class-A defect in the F3 taxonomy — a specification that reads as
authoritative but cannot be executed as written.

---

## P3 — the real serial path is on the parent device, and is device-class dependent

```
$ cat /sys/block/nvme0n1/device/serial
S73CNE1T927699
```

The real path is one level down, on the device's parent node.

**Claim supported:** serial lookup is **device-class dependent** (NVMe vs SATA vs USB differ), and
must be probed per class rather than assumed from a single path.

**Status:** probed **for NVMe only**. SATA and USB classes are **not available on this host** — see
P7. Their paths are a **stated limitation** (W-item), to be verified against real hardware by a
maintainer, not asserted from the NVMe result.

---

## P4 — `/dev/disk/by-uuid` exists and is readable without privileges

```
$ ls -la /dev/disk/by-uuid/
lrwxrwxrwx  8E8B-8EBE -> ../../nvme0n1p1
lrwxrwxrwx  b171e454-4a25-4581-8c63-1186f5660498 -> ../../nvme0n1p2
```

**Claim supported:** the directory is the dependency-free UUID source, **provided the reverse lookup
is used** — see P5. The links map `uuid → device`; identity needs `device → uuid`.

---

## P5 — device → UUID resolution with **no external binary** (the key finding)

The mechanism, end to end:

```
$ stat -c '%d' /
66306                          # st_dev, encoding major:minor

$ # major = st_dev / 256, minor = st_dev % 256
$ # 259:2

$ readlink -f /sys/dev/block/259:2
/sys/devices/pci0000:00/0000:00:13.0/0000:01:00.0/nvme/nvme0/nvme0n1/nvme0n1p2
                               # the block device behind the mount

$ # scan /dev/disk/by-uuid/* and match the link whose target is that device
$ readlink -f /dev/disk/by-uuid/b171e454-4a25-4581-8c63-1186f5660498
/dev/nvme0n1p2                 # ↑ matches the device resolved above
```

**Result:** `b171e454-4a25-4581-8c63-1186f5660498` obtained **without `blkid`, without `udevadm`, and
without any external binary.** Only `stat`, `readlink`, and directory reads — all achievable in Rust
via `libc::stat` plus `std::fs`.

**Claims supported:**

1. **mount → device resolution is required and is achievable** (`st_dev` → `/sys/dev/block/<maj:min>`).
   The engineer's §6.3 finding — that the draft's table skipped this step — is confirmed.
2. **The UUID mechanism is dependency-free**, satisfying G7, via the *reverse* of the `/dev/disk/by-uuid`
   map rather than a forward lookup.

**This is the finding that changes the blueprint's design**, and it is the reason the Probes section
was required before writing: the naive mechanism (`blkid`, or a forward `uuid → device` lookup) does
not work, and the workable one is only visible by probing.

---

## P6 — `is_removable` is a device property

```
$ cat /sys/block/nvme0n1/removable
0
```

**Claim supported:** `is_removable` is a property of the **block device**, read from
`/sys/block/<dev>/removable`. It cannot be a property of a mount path — reinforcing that the platform
layer's unit of work is a *resolved device*, not a path.

---

## P7 — no removable device on this host (the central coverage limitation)

```
$ lsblk -o NAME,RM,TRAN
NAME        RM TRAN
nvme0n1      0 nvme
├─nvme0n1p1  0 nvme
└─nvme0n1p2  0 nvme
```

**Claim supported:** `RM=0` for every device. **There is no removable device on this machine.**

**Consequences, stated as a limitation:**

1. Every `Present` / `Missing` / `Unverifiable` / `IdentityMismatch` transition — i.e. the entire
   swap-detection path — can be exercised **only against a mock reader**. The mock is not a
   convenience; it is the only happy path available here.
2. The **real** `SystemDeviceReader` can be covered only by the negative case that this host permits:
   `cwd` on a non-removable device ⇒ `NotOnRemovableDevice`.
3. **F3.5's real removable-device behaviour is unverified in this environment.** This is a **stated
   limitation**, recorded as an open item with a manual-verification step for the maintainer — exactly
   as W1 is for Windows/`mlock`. It is not a silent gap.

---

## Summary table

| # | Claim | Status | Consequence |
|---|---|---|---|
| P1 | `blkid` unusable (G7) | **Probed** | UUID must be obtained without external binaries |
| P2 | `/sys/block/*/serial` wrong | **Probed** | real path is `device/serial`, one level down |
| P3 | serial path is device-class dependent | **Probed — NVMe only** | SATA/USB are a **stated limitation** |
| P4 | `/dev/disk/by-uuid` readable | **Probed** | usable via reverse lookup |
| P5 | device → UUID works without binaries | **Probed** | the mechanism the blueprint will specify |
| P6 | `is_removable` is a device property | **Probed** | resolution before property reads |
| P7 | no removable device on host | **Probed** | mock is the only happy path; limitation recorded |

## Not probed on this host — citations or limitations

| Claim | Basis |
|---|---|
| SATA / USB serial paths | **Stated limitation** — no such device here |
| macOS device mechanisms | **Citation only** — no macOS host; labelled as such, W-item |
| Windows device mechanisms | **Citation only** — no Windows host; labelled as such, W-item |
| Real removable-device detection latency | **Unverifiable here** — no removable device |

Per the rule adopted from the directive: *a citation is acceptable where a probe is impossible; an
unlabelled assertion is not.* Every row above is labelled.

---

## P9 — Planned: device-class coverage on real hardware (Founder's drives)

**Status: NOT YET RUN — no removable device currently attached.** Recorded here so the requirement is not
forgotten, and so it is not mistaken for evidence already gathered.

The maintainer has **two test devices**: a USB flash drive, and a **2.5" HDD in a USB enclosure**. The second
is the more valuable test, because it differs from a flash stick in two ways that bear directly on the design:

| Property | USB flash stick | 2.5" HDD in USB enclosure | Why it matters |
|---|---|---|---|
| `TRAN` | `usb` | `usb` | same |
| **`RM` (removable)** | `1` | **often `0`** | **Test 1 rejects non-removable devices.** If a USB HDD reports `RM=0`, TokenGen refuses a device the user considers removable. Is that correct? Answer with data, not assumption. |
| **Spin-up latency** | negligible | **up to seconds when spun down** | §9's budget is **250 ms**. If a sleeping HDD exceeds it, the arithmetic must be **re-derived — the claim must not be softened**. |
| `vpd_pg80` serial | present (P8) | expected present — **verify** | do not assume it matches the flash path |

**What P9 must measure, when a device is attached:**

1. `cat /sys/block/<dev>/removable` for the HDD — record the value. If `0`, this is a **design question**, not
   a bug: the guard's removable check may need to consider transport as well as the flag.
2. `timed` read of `vpd_pg80` on a **spun-down** HDD — record the wall-clock time against the 250 ms budget.
3. The full `stat → st_dev → /sys/dev/block` chain on the HDD, as for the flash stick.
4. **Swap detection with two real devices**: capture on device A, swap to device B, confirm
   `IdentityMismatch` — the two devices give us the pair the design requires.

**No writes, no mounting required** for any of this: all four are reads of sysfs and stat. **Do not use the
maintainer's LUKS-encrypted drive** for mounted or destructive work under any circumstance.
