# Probe P11 — identity survives a physical re-plug

**Run:** 2026-10-14, by the maintainer physically removing **and re-inserting both USB drives**, then asking
the implementation to read them again. This is a real unplug/re-plug, not a simulated one.

## Why this probe exists

G16/G17 require the guard to bind a session to a device and **detect a swap**. That property has two halves,
and both must hold:

* a device that is unplugged and re-plugged must be recognised as **the same device** (otherwise every
  session aborts on an accidental wobble);
* a **different** device must be recognised as different (otherwise the binding is worthless).

Tests 2–7 prove the second half against a mock. This probe is evidence for the first half **on real
hardware**, which no mock can provide — the mock's identity is a value the test chose, not one the kernel
reported.

## Result — identities before and after the re-plug

| Target | Before | After re-plug | Verdict |
|---|---|---|---|
| `/dev/sdb1` (500 GB) | uuid=`510CE8A04FC8A579` serial=`235678C218CA` | **identical** | **stable** |
| `/dev/sda1` (116 GB) | `PropertyUnreadable` | **identical** | stable |
| `/` (internal NVMe) | `NotRemovable` | **identical** | stable |

## Why they are stable — the mechanism, not luck

The identities are read from **persistent device data**, never from the port or enumeration:

| Component | Source | Portable across re-plug? |
|---|---|---|
| serial | `/sys/block/<disk>/device/vpd_pg80` (the disk's ATA serial) | yes — a property of the disk |
| uuid | `/dev/disk/by-uuid/<uuid>` (the filesystem's identity) | yes — a property of the medium |

**And the re-plug did change something observable**, which is what makes this a real test rather than a
no-op: the USB device path moved from `…/host2/target2:0:0/2:0:0:0` to `…/host3/target3:0:0/3:0:0:0`. Had
identity been derived from the path (as a naive implementation might), these values would have changed and
every session would have aborted. They did not.

The transport **classification** does read the device path — correctly, since that is where transport lives —
but it is used only to decide *removable or not*, never to identify the device. Those are separate concerns
and the code keeps them separate.

## Limitation, stated

This shows stability across **one** re-plug, on **one** host, for **these two** drives. It is evidence, not
a proof: a device whose firmware regenerates its serial per enumeration would fail this property, and could
not be detected by this probe. That is recorded in the feature's limitations (L2 territory) rather than
generalised from here.

## Reproduce

```bash
lsblk -o NAME,SIZE,TRAN,RM,LABEL,MOUNTPOINT,SERIAL     # note the serials
# physically remove and re-insert the drives
cargo test -p tokengen-sys --test device_real -- --nocapture
```
The `real_removable_device_is_accepted` test prints the identity it read.
