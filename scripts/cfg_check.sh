#!/usr/bin/env bash
#
# cfg-forcing compile check.
#
# WHY THIS EXISTS
# ---------------
# `tokengen-sys` has a `#[cfg(unix)]` backend and a `#[cfg(not(unix))]` stub. On a
# Linux host the compiler never looks at the stub, so its signature can drift from
# its callers without any gate noticing. That happened once already: the stub's
# `lock_range` kept a `&mut [u8]` parameter after the callers moved to
# `(usize, usize)`, and the crate did not compile on any non-Unix target. No Unix
# gate could see it (failures-table entry 11).
#
# WHAT IT DOES
# ------------
# Copies the workspace to a temporary directory, inverts the two `cfg` gates so the
# non-Unix branch is compiled and the Unix branch is not, and builds. This makes
# the compiler type-check the deferred branch on any host, with no Windows
# toolchain required.
#
# The inversion is textual and therefore brittle by design: if the anchors move,
# this script FAILS LOUDLY rather than silently checking nothing. A gate that
# passes because it did not run is worse than no gate.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

TARGET="$WORK_DIR/tokengen-sys/src/lib.rs"

echo "cfg-forcing check: copying workspace to $WORK_DIR"
mkdir -p "$WORK_DIR/tokengen-sys/src"
cp -r "$REPO_ROOT/src" "$WORK_DIR/src"
cp "$REPO_ROOT/Cargo.toml" "$WORK_DIR/Cargo.toml"
cp "$REPO_ROOT/Cargo.lock" "$WORK_DIR/Cargo.lock" 2>/dev/null || true
cp "$REPO_ROOT/tokengen-sys/Cargo.toml" "$WORK_DIR/tokengen-sys/Cargo.toml"
cp "$REPO_ROOT/tokengen-sys/src/lib.rs" "$TARGET"

python3 - "$TARGET" <<'PY'
import sys

path = sys.argv[1]
src = open(path).read()

# Anchor 1: the Unix platform module. Turn it OFF.
unix_anchor = "#[cfg(unix)]\n// The `unsafe` opt-out"
if unix_anchor not in src:
    sys.exit("FATAL: could not find the Unix platform-module cfg anchor. "
             "The source moved; update scripts/cfg_check.sh rather than "
             "letting this gate pass vacuously.")
src = src.replace(unix_anchor, "#[cfg(any())]\n// The `unsafe` opt-out", 1)

# Anchor 2: the non-Unix stub. Turn it ON.
stub_anchor = "#[cfg(not(unix))]\nmod platform {"
if stub_anchor not in src:
    sys.exit("FATAL: could not find the non-Unix platform-module cfg anchor. "
             "The source moved; update scripts/cfg_check.sh rather than "
             "letting this gate pass vacuously.")
src = src.replace(stub_anchor, "#[cfg(all())]\nmod platform {", 1)

open(path, "w").write(src)
print("inverted: unix branch OFF, non-unix branch ON")
PY

echo "building with the non-Unix branch compiled..."
cd "$WORK_DIR"
if cargo build -p tokengen-sys 2>&1; then
    echo "cfg-forcing check: PASS — the non-Unix branch compiles"
else
    echo "cfg-forcing check: FAIL — the non-Unix branch does not compile" >&2
    exit 1
fi
