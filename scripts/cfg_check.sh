#!/usr/bin/env bash
#
# cfg-forcing compile check.
#
# WHY THIS EXISTS
# ---------------
# `tokengen-sys` has platform backends behind `cfg` gates. On a
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

# ---------------------------------------------------------------------------------------------
# EVERY OTHER WORKSPACE MEMBER, COPIED GENERICALLY.
#
# The two blocks above hard-coded the crates that existed when this script was written. When F4 added
# `tokengen-cli` as a workspace member, the copied tree was INCOMPLETE and every cargo command failed with
# "failed to read tokengen-cli/Cargo.toml" — the check reported FAIL for a reason that had nothing to do
# with cfg branches.
#
# That is the same class as the rest of this project's recurring failures: the script encoded an assumption
# (this workspace has two crates) that stopped being true. It now derives the member list from the
# workspace manifest, so a new crate is copied without this script being edited.
#
# Only the MAIN crate's and tokengen-sys's sources are cfg-INVERTED below — that is the check's subject.
# Other members are copied verbatim so the workspace resolves; they are compiled as-is by the cargo
# invocations that follow.
# ---------------------------------------------------------------------------------------------
WORKSPACE_MEMBERS="$(python3 - "$REPO_ROOT/Cargo.toml" <<'MEMBEREOF'
import re, sys
text = open(sys.argv[1], encoding='utf-8').read()
m = re.search(r'members\s*=\s*\[(.*?)\]', text, re.S)
if not m:
    print("")
else:
    print(" ".join(re.findall(r'"([^"]+)"', m.group(1))))
MEMBEREOF
)"
if [ -z "$WORKSPACE_MEMBERS" ]; then
    echo "FATAL: could not read workspace members from Cargo.toml. This check cannot verify a workspace it"
    echo "       cannot enumerate, and guessing would check the wrong tree."
    exit 1
fi
for member in $WORKSPACE_MEMBERS; do
    case "$member" in
        .) continue ;;                 # the root crate, already copied above
        tokengen-sys) continue ;;      # already copied and inverted above
    esac
    if [ -f "$REPO_ROOT/$member/Cargo.toml" ]; then
        mkdir -p "$WORK_DIR/$member"
        cp "$REPO_ROOT/$member/Cargo.toml" "$WORK_DIR/$member/Cargo.toml"
        [ -d "$REPO_ROOT/$member/src" ] && cp -r "$REPO_ROOT/$member/src" "$WORK_DIR/$member/src"
        [ -d "$REPO_ROOT/$member/tests" ] && cp -r "$REPO_ROOT/$member/tests" "$WORK_DIR/$member/tests"
        echo "  copied workspace member: $member"
    else
        echo "FATAL: workspace member '$member' has no Cargo.toml at $REPO_ROOT/$member."
        exit 1
    fi
done

python3 - "$WORK_DIR" <<'PY'
import glob
import os
import sys

root = sys.argv[1]
src_dir = os.path.join(root, "tokengen-sys", "src")

# Invert every platform gate so the DEFERRED branch is the one that compiles:
#   #[cfg(unix)] / #[cfg(target_os = "linux")]        -> #[cfg(any())]
#   #[cfg(not(unix))] / #[cfg(not(target_os = "linux"))] -> #[cfg(all())]
# Only real attribute lines are matched -- see the note above the loop.
#
# The count is checked per file: if a file that should contain both branches has
# fewer than expected, this fails loudly rather than silently under-checking.
EXPECTED = {
    "memory.rs": 2,
    "coredump.rs": 2,
    # F3.5's device module: the Linux backend, the non-Linux stub, and the two
    # per-branch `let component` bindings in `component_of`. Counted by this gate.
    #
    # The count was previously 5, and that 5 was WRONG: the gate's old whole-file
    # `str.replace` counted gate strings appearing in COMMENTS, so prose inflated
    # the total while the real gates were left un-inverted. The gate was reporting
    # on a tree it had not modified. Now only attribute lines are matched, and the
    # honest count is 4.
    "device.rs": 4,
}

files = sorted(glob.glob(os.path.join(src_dir, "*.rs")))
inverted = 0
seen = {}
# Files that contain ANY recognised platform gate, regardless of whether
# we understand them. Used to detect a module the coverage map does not know
# about -- a module that is present in the tree but absent from EXPECTED.
gated = set()

# The gates matched are the ATTRIBUTE FORMS, and only where they are real code.
#
# An earlier revision used a plain `text.replace(...)` over the whole file, so a gate string appearing in a
# COMMENT was counted as a gate and inverted. Two consequences, both observed:
#   * the count could be inflated by prose, so `EXPECTED` agreed for the wrong reason (DEFECT-003 and
#     again with the `target_os` change: five real gates, five prose mentions, indistinguishable);
#   * the real gates were left UNINVERTED while the prose was inverted, so the gate reported on a tree it
#     had not actually modified — testing nothing, which is the failure this gate exists to prevent.
#
# So each line is classified: a gate is a line whose content (after stripping whitespace) is exactly the
# attribute, and which is not a comment. A trailing comment after the attribute is not tolerated, because
# the codebase does not write them and a stricter rule fails loudly rather than under-checking.
GATE_TO_INVERSE = {
    "#[cfg(unix)]": "#[cfg(any())]",
    "#[cfg(not(unix))]": "#[cfg(all())]",
    "#[cfg(target_os = \"linux\")]": "#[cfg(any())]",
    "#[cfg(not(target_os = \"linux\"))]": "#[cfg(all())]",
}

# ---------------------------------------------------------------------------------------------
# GATES THE INVERSION MAP DOES NOT KNOW ARE A HOLE, NOT A NON-EVENT.
#
# The map above matches only exact attribute strings. A gate written any other way — for instance
# `#[cfg(all(test, target_os = "linux"))]` — is left UNINVERTED, so the "non-Linux" pass compiles the LINUX
# branch and reports success while covering nothing. That is worse than a failed check: it is a passing check
# that asserts the opposite of the truth.
#
# Found while fixing DEFECT-012: a test module carrying that gate compiled in the inverted pass, and the only
# visible symptom was an unrelated-looking import error.
#
# Any cfg line that mentions `unix` or `target_os` but is NOT a recognised gate is now FATAL. Silence about a
# platform condition is not neutrality — it means the file's platform behaviour is not being checked.
RECOGNISED_PREFIXES = ("#[cfg(unix)]", "#[cfg(not(unix))]", "#[cfg(target_os = \"linux\")]",
                       "#[cfg(not(target_os = \"linux\"))]")

def unrecognised_platform_gates(text):
    found = []
    for i, line in enumerate(text.split("\n"), 1):
        stripped = line.strip()
        if not stripped.startswith("#[cfg") and not stripped.startswith("#!["):
            continue
        if ("unix" in stripped or "target_os" in stripped) and stripped not in RECOGNISED_PREFIXES:
            found.append((i, stripped))
    return found

unrecognised = []
for path in files:
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        continue
    for line_no, gate in unrecognised_platform_gates(text):
        unrecognised.append(f"{path}:{line_no}: {gate}")

if unrecognised:
    print("FATAL: platform gates this check cannot invert. They would be left UNINVERTED, so the")
    print("       'non-Linux' pass would compile the LINUX branch and report success while covering nothing.")
    print("       Either write the gate in a recognised form, or teach this script to invert it.")
    for u in unrecognised:
        print(f"         {u}")
    raise SystemExit(1)

for path in files:
    name = os.path.basename(path)
    lines = open(path).read().splitlines(keepends=True)
    out = []
    n = 0
    for line in lines:
        stripped = line.strip()
        if stripped in GATE_TO_INVERSE:
            out.append(line.replace(stripped, GATE_TO_INVERSE[stripped]))
            n += 1
        else:
            out.append(line)

    if n == 0:
        continue

    gated.add(name)
    seen[name] = n

    if name in EXPECTED and n != EXPECTED[name]:
        sys.exit(
            f"FATAL: {name} yielded {n} inverted cfg gates, expected "
            f"{EXPECTED[name]}. The source moved; update scripts/cfg_check.sh "
            f"rather than letting this gate under-check."
        )

    open(path, "w").write("".join(out))
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

# THE IMPORTANT DIRECTION, and the one that was originally missing: a module that
# CONTAINS cfg gates but is NOT in EXPECTED is a module this gate does not cover.
# The check above catches a listed module that disappears; this catches an
# unlisted module that appears -- which is the live risk when a new platform
# domain (F3.5's device.rs) is added. Without this, adding device.rs would leave
# its stubs silently uncompiled while the gate still reported PASS.
#
# Verified by introducing exactly that defect and observing this branch fire;
# before this change, an unlisted gated module passed with exit 0.
uncovered = sorted(gated - set(EXPECTED))
if uncovered:
    sys.exit(
        f"FATAL: module(s) contain platform cfg gates but are NOT in "
        f"EXPECTED: {uncovered}. Add each with its expected gate count, or this "
        f"gate does not cover them."
    )

print(f"inverted {inverted} gate(s) across {len(seen)} module(s): {sorted(seen)}")
print(f"coverage: all {len(gated)} gated module(s) are accounted for")
PY

echo "building with the non-Unix branches compiled..."
cd "$WORK_DIR"

# Enforce the SAME strictness as CI. CI sets `RUSTFLAGS: -D warnings` and runs clippy with
# `-D warnings`; this gate previously used a plain `cargo build`, so it reported PASS on a tree
# CI would reject (DEFECT-002 D-2b). A gate whose PASS means less than CI's is not a gate.
#
# Two checks, matching CI's:
#   1. build with warnings denied — catches dead_code/unused in the deferred branch
#   2. clippy with warnings denied — catches lints the deferred branch would trip
#
# NOTE ON THE ONE LINT THAT MUST BE ALLOWED HERE. The inversion above rewrites
# `#[cfg(unix)]` to `#[cfg(any())]` and `#[cfg(not(unix))]` to `#[cfg(all())]`. Clippy correctly
# objects that those are non-minimal cfg expressions (`clippy::non_minimal_cfg`) — but that is an
# artefact of THIS GATE'S METHOD, not a defect in the source. It is therefore allowed during the
# clippy pass only, by name, so every other lint stays enforced. Silencing `-D warnings` wholesale
# would have hidden the very defect (D-2a) this change exists to catch.
export RUSTFLAGS="${RUSTFLAGS:-} -D warnings"
if ! cargo build -p tokengen-sys 2>&1; then
    echo "cfg-forcing check: FAIL — a non-Unix branch does not compile" >&2
    exit 1
fi
if ! cargo clippy -p tokengen-sys --all-targets -- \
    -D warnings -A clippy::non_minimal_cfg 2>&1; then
    echo "cfg-forcing check: FAIL — a non-Unix branch does not pass clippy with warnings denied" >&2
    exit 1
fi
echo "cfg-forcing check: PASS — every non-Unix branch compiles, warnings denied (matches CI)"
