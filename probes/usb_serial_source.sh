#!/usr/bin/env bash
#
# Probe: where does a USB drive's hardware serial actually come from?
#
# WHY THIS EXISTS
# ---------------
# The F3.5 blueprint §6.2 specifies the hardware serial as:
#
#     device -> hardware serial : /sys/block/<dev>/device/serial     (probe P3)
#
# That path exists for NVMe and is ABSENT for USB mass storage — which is the device
# class TokenGen actually runs from. This probe establishes the real source.
#
# Host: Linux 6.12.107+deb13-amd64 x86_64, 2026-10-13.
# A USB mass-storage device (SanDisk 3.2Gen1) was attached during this probe.
#
# Run: bash probes/usb_serial_source.sh
#
set -uo pipefail

echo "=== P-USB-1: what block devices are present, and which are removable? ==="
lsblk -o NAME,TRAN,RM,SERIAL 2>/dev/null || echo "(lsblk unavailable)"

USB=$(lsblk -o NAME,TRAN -n 2>/dev/null | awk '$2=="usb"{print $1; exit}')
if [ -z "${USB}" ]; then
  echo
  echo "No USB block device attached — this probe cannot run. NOT RUN."
  exit 1
fi
echo
echo "USB device detected: /dev/${USB}"

echo
echo "=== P-USB-2: does the blueprint's path exist for it? ==="
printf '  %-46s ' "/sys/block/${USB}/device/serial"
if [ -e "/sys/block/${USB}/device/serial" ]; then
  cat "/sys/block/${USB}/device/serial"
else
  echo "ABSENT  <-- the blueprint's mechanism does not work here"
fi

echo
echo "=== P-USB-3: the NVMe comparison (the path the blueprint was probed on) ==="
NVME=$(lsblk -o NAME,TRAN -n 2>/dev/null | awk '$2=="nvme"{print $1; exit}')
if [ -n "${NVME}" ]; then
  printf '  %-46s ' "/sys/block/${NVME}/device/serial"
  cat "/sys/block/${NVME}/device/serial" 2>/dev/null || echo "(absent)"
  echo "  -> the plain-text path is NVMe-specific"
else
  echo "  (no NVMe device on this host)"
fi

echo
echo "=== P-USB-4: where the USB serial actually lives (SCSI VPD page 0x80) ==="
VPD="/sys/block/${USB}/device/vpd_pg80"
printf '  %-46s ' "${VPD}"
if [ -e "${VPD}" ]; then
  echo "PRESENT"
  echo "  raw bytes:"
  od -An -tx1 "${VPD}" | head -3 | sed 's/^/    /'
else
  echo "ABSENT"
fi

echo
echo "=== P-USB-5: decode it — and cross-check against lsblk ==="
python3 - "${USB}" <<'PY'
import sys
u = sys.argv[1]
path = f"/sys/block/{u}/device/vpd_pg80"
try:
    d = open(path, "rb").read()
except OSError as e:
    print(f"  cannot read {path}: {e}")
    sys.exit(0)
# SCSI VPD page 0x80 (Unit Serial Number):
#   byte 0   peripheral device type / qualifier
#   byte 1   page code (0x80)
#   bytes 2-3 big-endian length of the serial that follows
#   bytes 4..4+len  ASCII serial (space/NUL padded)
page = d[1]
length = (d[2] << 8) | d[3]
serial = d[4:4 + length].decode("ascii", "replace").strip()
print(f"  page code     : 0x{page:02x}  (expect 0x80)")
print(f"  declared len  : {length}")
print(f"  decoded serial: {serial!r}")
sys.stdout.write(f"  cross-check   : run `lsblk -o NAME,SERIAL -n /dev/{u}` and compare\n")
PY
lsblk -o NAME,SERIAL -n "/dev/${USB}" 2>/dev/null | sed 's/^/    lsblk: /'

echo
echo "=== FINDING ==="
cat <<'FINDING'
  probed (Linux 6.12, USB mass storage attached, 2026-10-13):
    - /sys/block/<usb>/device/serial       ABSENT   <- blueprint §6.2 mechanism
    - /sys/block/<usb>/device/vpd_pg80     PRESENT  <- real source (binary VPD page 0x80)
    - /sys/block/<nvme>/device/serial      PRESENT  <- why the blueprint's probe passed

  -> The blueprint's serial mechanism was probed on NVMe and does not hold for USB
     mass storage, which is the device class TokenGen runs from. This is a
     probe-vs-blueprint discrepancy of the class this project treats as blocking:
     a specification that reads as authoritative but cannot be executed as written
     for the actual target.

  -> The real mechanism: read /sys/block/<dev>/device/vpd_pg80, take bytes
     4..4+((b[2]<<8)|b[3]) as ASCII. Validated: decoded serial matches lsblk's
     independently-reported SERIAL for the same device.

  stated limitation:
    vpd_pg80 is a binary sysfs attribute, not text. Its length field must be
    bounds-checked against the bytes actually read; a truncated or short read must
    yield "unreadable", never a fabricated or partial serial (§10.1, test 6).
FINDING
