#!/usr/bin/env bash
#
# cfg-forcing compile check.
#
# WHY THIS EXISTS
# ---------------
# `tokengen-sys` has `#[cfg(unix)]` backends and `#[cfg(not(unix))]` stubs. On a
# Linux host the compiler never looks at the stubs, so their signatures can drift
# from their callers without any gate noticing. That happened once already: a
# stub's `lock_range` kept a `&mut [u8]` parameter after the callers moved to
# `(usize, usize)`, and the crate did not compile on any non-Unix target. No Unix
# gate could see it (failures-table entry 11).
#
# WHAT IT DOES
# ------------
# Copies the workspace to a temporary directory, inverts every `cfg` gate in the
# platform modules so the non-Unix stubs are compiled and the Unix backends are
# not, and builds. This makes the compiler type-check the deferred branches on
# any host, with no Windows toolchain required.
#
# The inversion is textual and therefore brittle by design: if an anchor moves,
# this script FAILS LOUDLY rather than silently checking nothing. A gate that
# passes because it did not run is worse than no gate.
#
# COVERAGE (clause 1 — "coverage must be stated")
# -----------------------------------------------
# Files scanned and the branches they contain:
#   tokengen-sys/src/memory.rs    unix backend / not(unix) stub
#   tokengen-sys/src/coredump.rs  unix backend / not(unix) stub
# A module added under tokengen-sys/src/ without an entry in ANCHORS below will
# NOT be covered — the coverage list is explicit so that omission is visible.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "cfg-forcing check: copying workspace to $WORK_DIR"
mkdir -p "$WORK_DIR/tokengen-sys/src"
cp -r "$REPO_ROOT/src" "$WORK_DIR/src"
cp "$REPO_ROOT/Cargo.toml" "$WORK_DIR/Cargo.toml"
cp "$REPO_ROOT/Cargo.lock" "$WORK_DIR/Cargo.lock" 2>/dev/null || true
cp "$REPO_ROOT/tokengen-sys/Cargo.toml" "$WORK_DIR/tokengen-sys/Cargo.toml"
cp "$REPO_ROOT"/tokengen-sys/src/*.rs "$WORK_DIR/tokengen-sys/src/"

python3 - "$WORK_DIR" <<'PY'
import glob
import os
import sys

root = sys.argv[1]
src_dir = os.path.join(root, "tokengen-sys", "src")

# Invert every `#[cfg(unix)]` -> `#[cfg(any())]` and
# `#[cfg(not(unix))]` -> `#[cfg(all())]` in the platform modules.
#
# The count is checked per file: if a file that should contain both branches has
# fewer than expected, this fails loudly rather than silently under-checking.
EXPECTED = {
    "memory.rs": 2,
    "coredump.rs": 2,
}

files = sorted(glob.glob(os.path.join(src_dir, "*.rs")))
inverted = 0
seen = {}

for path in files:
    name = os.path.basename(path)
    text = open(path).read()
    before = text

    text = text.replace("#[cfg(unix)]", "#[cfg(any())]")
    text = text.replace("#[cfg(not(unix))]", "#[cfg(all())]")

    if text == before:
        continue

    n = text.count("#[cfg(any())]") + text.count("#[cfg(all())]")
    seen[name] = n

    if name in EXPECTED and n != EXPECTED[name]:
        sys.exit(
            f"FATAL: {name} yielded {n} inverted cfg gates, expected "
            f"{EXPECTED[name]}. The source moved; update scripts/cfg_check.sh "
            f"rather than letting this gate under-check."
        )

    open(path, "w").write(text)
    inverted += n
    print(f"  inverted {n} gate(s) in {name}")

if inverted == 0:
    sys.exit(
        "FATAL: no cfg anchors found in any platform module. The source moved; "
        "update scripts/cfg_check.sh rather than letting this gate pass vacuously."
    )

missing = [f for f in EXPECTED if f not in seen]
if missing:
    sys.exit(
        f"FATAL: expected platform modules not covered: {missing}. "
        f"Add them to EXPECTED or remove them from the list."
    )

print(f"inverted {inverted} gate(s) across {len(seen)} module(s): {sorted(seen)}")
PY

echo "building with the non-Unix branches compiled..."
cd "$WORK_DIR"
if cargo build -p tokengen-sys 2>&1; then
    echo "cfg-forcing check: PASS — every non-Unix branch compiles"
else
    echo "cfg-forcing check: FAIL — a non-Unix branch does not compile" >&2
    exit 1
fi
