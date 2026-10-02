#!/usr/bin/env bash
#
# F3.5 Linux platform probes.
#
# Reproduces the evidence recorded in probes/README.md. Read-only: this script
# reads sysfs and /dev/disk only; it changes nothing.
#
# Run: bash probes/linux_device.sh
# Expected: output matching probes/README.md (device names and UUIDs will differ
# on other hosts; the *shape* of each result is what is being verified).

set -uo pipefail

hr() { printf '\n%s\n' "---- $* ----"; }

echo "# F3.5 platform probe output"
echo "# Host: $(uname -srm)"
echo "# Date: $(date -Iseconds)"

hr "P1 blkid presence (G7: no external binaries)"
if command -v blkid >/dev/null 2>&1; then
    echo "blkid PRESENT at $(command -v blkid)"
    echo "NOTE: its presence here does NOT make it usable — see probes/README.md P1."
else
    echo "blkid ABSENT — cannot be the uuid source"
fi

hr "P2 /sys/block/*/serial (the draft's claimed path)"
ls /sys/block/*/serial 2>&1 | head -3

hr "P3 real serial path (parent device, per class)"
found=0
for d in /sys/block/*/; do
    name=$(basename "$d")
    if [ -e "$d/device/serial" ]; then
        printf '  %s: %s\n' "$name" "$(cat "$d/device/serial" 2>/dev/null)"
        found=1
    fi
done
[ "$found" -eq 0 ] && echo "  (no serial found via device/serial on this host)"

hr "P4 /dev/disk/by-uuid contents"
ls -la /dev/disk/by-uuid/ 2>&1 | tail -n +2

hr "P5 device -> uuid WITHOUT blkid (the mechanism the blueprint uses)"
for path in / /home; do
    [ -d "$path" ] || continue
    dev=$(stat -c '%d' "$path" 2>/dev/null) || continue
    maj=$(( dev / 256 ))
    min=$(( dev % 256 ))
    link="/sys/dev/block/${maj}:${min}"
    if [ -e "$link" ]; then
        target=$(readlink -f "$link")
        base=$(basename "$target")
        echo "path=$path  st_dev=$dev  maj:min=${maj}:${min}"
        echo "  sysfs -> $target"
        for l in /dev/disk/by-uuid/*; do
            [ -e "$l" ] || continue
            t=$(readlink -f "$l")
            case "$t" in
                *"/$base") echo "  uuid: $(basename "$l")" ;;
            esac
        done
    else
        echo "path=$path  st_dev=$dev  maj:min=${maj}:${min}  (no /sys/dev/block link)"
    fi
done

hr "P6 is_removable is a device property"
for d in /sys/block/*/; do
    name=$(basename "$d")
    [ -e "$d/removable" ] && printf '  %s removable=%s\n' "$name" "$(cat "$d/removable")"
done

hr "P7 removable device present?"
if command -v lsblk >/dev/null 2>&1; then
    lsblk -o NAME,RM,TRAN
    echo
    if lsblk -o RM -n | grep -qv '^ *0$'; then
        echo "RESULT: at least one removable device present"
    else
        echo "RESULT: NO removable device — the mock is the only happy path (see README P7)"
    fi
else
    echo "lsblk absent; inspect /sys/block/*/removable manually"
fi

hr "done"
echo "Compare against probes/README.md. The shape of each result is the claim."
