#!/usr/bin/env python3
"""Probe: decide "removable" from the TRANSPORT, not the kernel's removable flag.

WHY THIS EXISTS (Founder decision, 2026-10-13)
----------------------------------------------
`/sys/block/<dev>/removable` is not a usable proxy for "external". Measured on this host:

    sda       TRAN=usb   RM=1     external flash drive
    sdb       TRAN=usb   RM=0     external 500 GB enclosure   <-- kernel says NON-removable
    nvme0n1   TRAN=nvme  RM=0     internal root

`sdb` and `nvme0n1` are indistinguishable by the flag, but only `sdb` is external. The **transport**
separates them: `sdb` sits under a USB controller, `nvme0n1` does not.

DECISION: a device is removable for the guard's purposes if it is on a removable transport (usb; later
mmc/thunderbolt). The kernel's `removable` flag is retained as a secondary signal only.

MECHANISM: resolve `/sys/block/<disk>/device` and count `usbN` path components. Depth-independent — the
device path length varies by transport (NVMe is shallower than SCSI-over-USB), so a fixed `../../..`
walk is fragile and wrong.

STATED LIMITATION (must be recorded with the feature): a device soldered internally but attached over
USB (some eMMC/embedded storage) would be treated as removable. It cannot be distinguished from sysfs
alone. This is accepted — refusing every USB device to defend against it would reject every external
drive, including both of the maintainer's.

Run: python3 probes/transport_removability.py
"""
import os
import re

USB_COMPONENT = re.compile(r"^usb\d+$")
TRANSPORT_MARKERS = {
    "usb": "removable",
    "mmc": "removable",
    "thunderbolt": "removable",
    "firewire": "removable",
    "nvme": "fixed",
    "ata": "fixed",
    "sata": "fixed",
    "scsi": "unknown",
}


def transport_of(disk):
    """Return (transport, is_removable_transport) for a whole-disk name."""
    dev = f"/sys/block/{disk}/device"
    if not os.path.exists(dev):
        return ("absent", False)
    try:
        resolved = os.path.realpath(dev)
    except OSError:
        return ("unresolvable", False)

    parts = resolved.split(os.sep)
    for p in parts:
        if USB_COMPONENT.match(p):
            return ("usb", True)
        for marker in ("mmc", "thunderbolt", "firewire", "nvme", "ata", "sata"):
            if p.startswith(marker):
                return (marker, TRANSPORT_MARKERS.get(marker, "unknown") == "removable")
    return ("unknown", False)


def flag_of(disk):
    try:
        return open(f"/sys/block/{disk}/removable").read().strip()
    except OSError:
        return "absent"


def main():
    print("=== transport vs the kernel's removable flag ===")
    print(f"{'disk':<12} {'RM':<6} {'transport':<14} {'removable-transport?':<22} verdict")
    for disk in sorted(os.listdir("/sys/block")):
        rm = flag_of(disk)
        transport, removable = transport_of(disk)
        verdict = "ACCEPT" if removable else "REFUSE"
        print(f"{disk:<12} {rm:<6} {transport:<14} {str(removable):<22} {verdict}")

    print()
    print("=== FINDING ===")
    print("  The flag alone cannot separate `sdb` (external USB enclosure, RM=0) from")
    print("  `nvme0n1` (internal root, RM=0). The transport can. Decision: transport is")
    print("  authoritative; the flag is a secondary signal.")
    print()
    print("  stated limitation: an internally-soldered USB device is indistinguishable")
    print("  from an external one and would be accepted. Not detectable from sysfs.")


if __name__ == "__main__":
    main()
