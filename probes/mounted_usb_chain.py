#!/usr/bin/env python3
"""Probe: what does the resolution chain yield for REAL mounted USB drives?

The implementation resolves `cwd` (a mounted path). This probe shows, for each real
mount point, what st_dev gives versus what st_rdev gives, and whether the resulting
major:minor actually exists under /sys/dev/block.

This distinguishes the two cases the implementation must handle:
  - a MOUNTED PATH  -> the backing device is in st_dev
  - a DEVICE NODE   -> the backing device is in st_rdev
"""
import os

TARGETS = [
    "/",
    "/media/deathrok/125GB",
    "/media/deathrok/500GB",
    "/dev/sda1",
    "/dev/sdb1",
]


def sysdev(maj, minr):
    p = f"/sys/dev/block/{maj}:{minr}"
    try:
        return os.path.realpath(p)
    except OSError:
        return "MISSING"


for t in TARGETS:
    try:
        st = os.stat(t)
    except OSError as e:
        print(f"{t:<28} {e}")
        continue
    dev, rdev = st.st_dev, st.st_rdev

    # The TWO candidate decodings, both to be checked for existence.
    dev_res = sysdev(os.major(dev), os.minor(dev))
    rdev_res = sysdev(os.major(rdev), os.minor(rdev))

    print(f"{t:<28}")
    print(f"    st_dev  {dev:<8} -> {os.major(dev)}:{os.minor(dev):<6} -> {dev_res}")
    print(f"    st_rdev {rdev:<8} -> {os.major(rdev)}:{os.minor(rdev):<6} -> {rdev_res}")

print()
print("A mounted path resolves via st_dev; a device node via st_rdev.")
print("The implementation must tell the two apart — the st_dev value for a device")
print("node is the device-holding filesystem's, not the device's.")
