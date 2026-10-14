#!/usr/bin/env python3
"""Probe: a USB drive can expose TWO different serials, and they mean different things.

WHY THIS EXISTS
---------------
Measured on the maintainer's 2.5" HDD in a USB enclosure (`sdb`), 2026-10-14:

    /sys/block/sdb/device/vpd_pg80   ->  235678C218CA      (the DISK's ATA serial)
    /sys/block/sdb/device/wwid       ->  t10.HGST HTS545050A7E680    235678C218CA
    lsblk -o SERIAL                  ->  RBF50A152X65YP    (the USB BRIDGE serial)
    udevadm ID_SERIAL_SHORT          ->  RBF50A152X65YP    (bridge)
    udevadm ID_USB_SERIAL_SHORT      ->  235678C218CA      (disk)

**The two values are not the same serial read two ways — they are two different
serials from two different components.** The enclosure's USB-SATA bridge has its
own serial; the disk inside has the ATA serial that VPD page 0x80 reports.

WHY IT MATTERS FOR THE SESSION GUARD
------------------------------------
Identity binding must survive being unplugged and re-plugged (G16/G17), and must
CHANGE when a different device is substituted.

  - The BRIDGE serial identifies the ENCLOSURE. Move the disk to a different
    enclosure and the bridge serial changes — a false `IdentityMismatch`.
  - The DISK serial identifies the MEDIUM. Move the enclosure to a different port,
    or replace the disk inside while keeping the enclosure, and the disk serial
    changes while the bridge serial does not.

Neither is universally "right": they answer different questions. The guard must
choose deliberately and record which it chose, rather than taking whichever path
happens to exist first.

CURRENT CHOICE: VPD page 0x80 (the DISK serial), read from `device/vpd_pg80`.
Rationale: it identifies the medium the secret's working directory lives on, which
is what "the device I bound to" means to a user. The alternative — the enclosure —
would bind the session to a piece of plastic that a user may swap for an identical
model with different contents.

STATED LIMITATION (must be recorded with the feature): a user who moves the SAME
disk to a DIFFERENT enclosure keeps the disk serial and therefore keeps the binding
— which is correct, because it is the same medium. A user who replaces the DISK
while keeping the enclosure gets a new disk serial and the guard aborts — also
correct. What is NOT detectable is an attacker who images the disk byte-for-byte
onto identical media: the serial is a property of the device, not of its contents.

AVAILABILITY IS DEVICE-DEPENDENT, MEASURED
    sda (Lexar flash)  device/serial absent, vpd_pg80 ABSENT, wwid present but EMPTY
    sdb (500 GB HDD)   device/serial absent, vpd_pg80 PRESENT (20 bytes), wwid present

So on `sda` the serial is unavailable from sysfs at all. That is W4 territory
(`SG_IO`, deferred to F3.7) and the guard fails closed rather than degrading.

NOTE ON A YESTERDAY/TODAY DISCREPANCY, RECORDED RATHER THAN HIDDEN: the earlier
session recorded `vpd_pg80` as absent on BOTH drives. It is absent on `sda` and
PRESENT on `sdb` today. The earlier note was either taken while the drives differed
in state, or was over-generalised from `sda` alone — which would be the fourth
instance of a probe narrower than its claim. It is re-measured here per drive.

Run: python3 probes/usb_dual_serial.py
"""
import os


def vpd_serial(disk):
    p = f"/sys/block/{disk}/device/vpd_pg80"
    try:
        d = open(p, "rb").read()
    except OSError:
        return None
    if len(d) < 4 or d[1] != 0x80:
        return None
    n = (d[2] << 8) | d[3]
    if 4 + n > len(d):
        return None
    return d[4:4 + n].decode("ascii", "replace").rstrip("\0").strip()


def wwid(disk):
    try:
        return open(f"/sys/block/{disk}/device/wwid").read().strip()
    except OSError:
        return None


def removable(disk):
    try:
        return open(f"/sys/block/{disk}/removable").read().strip()
    except OSError:
        return None


def main():
    disks = sorted(d for d in os.listdir("/sys/block") if d.startswith(("sd", "nvme")))
    print(f"{'disk':<10} {'RM':<4} {'vpd_pg80 (disk serial)':<26} wwid")
    for d in disks:
        v = vpd_serial(d) or "(absent/unreadable)"
        w = wwid(d)
        w = "(empty)" if w == "" else (w or "(absent)")
        if len(w) > 50:
            w = w[:47] + "..."
        print(f"{d:<10} {str(removable(d)):<4} {v:<26} {w}")

    print()
    print("Compare `vpd_pg80` against `lsblk -o SERIAL` for the same device:")
    print("  if they DIFFER, vpd_pg80 is the DISK serial and lsblk is the USB BRIDGE serial.")


if __name__ == "__main__":
    main()
