#!/usr/bin/env bash
# Probe: resolving a path to a device must distinguish st_dev from st_rdev.
#
# WHY THIS EXISTS
# ---------------
# F3.5 blueprint §6.2 / Probe P5 specifies: `stat(path).st_dev` -> major:minor ->
# /sys/dev/block/<maj>:<min>. P5 was probed on `/` only — a MOUNTED FILESYSTEM PATH.
#
# For a DEVICE NODE (/dev/sda1) the device is NOT in st_dev; it is in st_rdev, and a
# naive `dev / 256` split yields a major:minor that does not exist under /sys/dev/block.
# Observed 2026-10-13 with two USB mass-storage devices attached:
#
#   /          st_dev=66306  -> 259:2  (correct; mounted path)
#   /dev/sda1  st_dev=6      -> 0:6    (WRONG; the device is 8:1 from st_rdev)
#
# The implementation must decompose with the glibc rules (as os.major/os.minor do),
# not a hand-rolled /256, and must read st_rdev for a device node.
#
# Run: bash probes/stdev_vs_rdev.sh   (or: python3 probes/stdev_vs_rdev.py)
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${DIR}/stdev_vs_rdev.py"
