#!/usr/bin/env python3
"""Determine the correct st_dev -> major:minor decoding.

The F3.5 blueprint's P5 mechanism was probed on a *mounted filesystem path* only.
For a **device node** (/dev/sda1) st_dev is not the same encoding, and a naive
dev/256 split produces a major:minor that does not exist under /sys/dev/block.
"""
import os

for p in ["/", "/dev/sda", "/dev/sda1", "/dev/sdb", "/dev/nvme0n1p2", "/dev/nvme0n1"]:
    try:
        st = os.stat(p)
    except OSError as e:
        print(f"{p:<20} {e}")
        continue
    dev = st.st_dev
    rdev = st.st_rdev
    print(
        f"{p:<20} st_dev={dev:<8} "
        f"os.major={os.major(dev):<4} os.minor={os.minor(dev):<4} | "
        f"st_rdev={rdev:<8} rdev_maj={os.major(rdev):<4} rdev_min={os.minor(rdev):<4}"
    )

print()
print("For a block device node, the kernel identifier is st_rdev (maj:min), NOT st_dev.")
print("os.major/os.minor handle the encoding; a hand-rolled /256 split does not.")
