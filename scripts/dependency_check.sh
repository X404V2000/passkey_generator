#!/usr/bin/env bash
#
# F3.6 — shipped-dependency check (per platform).
#
# Asserts that the crates COMPILED INTO A RELEASE BUILD match the recorded allow-list, for THIS target.
#
# Why this is the highest-value check in F3.6: G11-G13 are claims about what the TOOL does, but the real
# attack surface is the code the tool LINKS. A dependency that writes a cache file, reads %APPDATA%, or
# touches a registry would violate G11-G13 without a single line of this repository changing. A filesystem
# diff catches that only if it watches the right path at the right moment; this catches it at REVIEW TIME,
# deterministically, on all three platforms, before the code ever runs.
#
# ------------------------------------------------------------------------------------------------
# THE FIRST VERSION OF THIS CHECK WAS WRONG, AND CI CAUGHT IT
#
# It compared a single universal set against the graph on every runner, and failed on Windows: `libc` is
# declared under `[target.'cfg(unix)'.dependencies]` and is simply not in the Windows graph.
#
# The mistake was not the typo — it was the ASSUMPTION, "the shipped graph is the same everywhere", which
# was never verified and is false. A probe narrower than the claim it supported. The build graph is a
# property of a TARGET, so this check and its list are now keyed by target family.
#
# If this check fails, the message names the difference. Do not widen the list to make it pass: a new crate
# needs an amendment justifying it against G11-G13.
# ------------------------------------------------------------------------------------------------

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LIST="scripts/shipped-deps.txt"

if [ ! -f "$LIST" ]; then
    echo "FATAL: $LIST is missing. This check cannot assert an allow-list that does not exist."
    exit 1
fi

# Which section of the list applies here. `uname -s` is portable across the three runners (Git Bash on
# Windows reports MINGW*/MSYS*, and `$OS` is set to Windows_NT there).
case "$(uname -s)" in
    Linux|Darwin) section="unix" ;;
    MINGW*|MSYS*|CYGWIN*) section="windows" ;;
    *)
        # An unrecognised platform must NOT fall back to a section, because the wrong allow-list would
        # either fail spuriously or, worse, pass while checking the wrong graph.
        echo "FATAL: unrecognised platform '$(uname -s)'. This check does not know which allow-list applies,"
        echo "       and guessing would check the wrong graph. Add a section to $LIST for this platform."
        exit 1
        ;;
esac

# Extract the section, stopping at the next [header] or EOF.
recorded="$(awk -v want="$section" '
    /^\[/ { in_section = ($0 == "[" want "]"); next }
    in_section && $0 !~ /^#/ && NF >= 2 { print $1" "$2 }
' "$LIST" | sort -u)"

if [ -z "$recorded" ]; then
    echo "FATAL: section [$section] of $LIST is missing or empty. An empty allow-list would make this check"
    echo "       pass on any graph at all, which is worse than not running it."
    exit 1
fi

# The actual set, from cargo's own view of the RELEASE graph for THIS host's default target.
if ! actual_raw="$(cargo tree --locked -p tokengen --edges normal 2>/dev/null)"; then
    echo "FATAL: 'cargo tree' failed; cannot determine the shipped graph, so this check must not pass."
    exit 1
fi
actual="$(printf '%s\n' "$actual_raw" \
    | grep -oE '[a-z0-9_-]+ v[0-9]+\.[0-9]+\.[0-9]+' \
    | grep -v '^tokengen ' \
    | grep -v '^tokengen-sys ' \
    | sed 's/ v/ /' \
    | sort -u)"

if [ -z "$actual" ]; then
    echo "FATAL: the shipped graph came back EMPTY. That means the parse failed, not that the tool has no"
    echo "       dependencies — it links getrandom and zeroize at minimum. A check that passes on a failed"
    echo "       parse proves nothing."
    exit 1
fi

echo "F3.6 shipped-dependency check — platform section [$section] ($(uname -s))"
echo
echo "  recorded:"
printf '%s\n' "$recorded" | sed 's/^/    /'
echo "  actual (release graph):"
printf '%s\n' "$actual" | sed 's/^/    /'
echo

if [ "$recorded" = "$actual" ]; then
    echo "F3.6 shipped-dependency check: PASS — the shipped graph matches the [$section] allow-list exactly"
    exit 0
fi

echo "F3.6 shipped-dependency check: FAIL — the shipped graph differs from the [$section] allow-list"
echo
echo "  in the graph but NOT recorded (a new dependency):"
comm -13 <(printf '%s\n' "$recorded") <(printf '%s\n' "$actual") | sed 's/^/    + /'
echo "  recorded but NOT in the graph (removed, or the wrong section):"
comm -23 <(printf '%s\n' "$recorded") <(printf '%s\n' "$actual") | sed 's/^/    - /'
echo
echo "  A new crate is code the tool links and that G11-G13 must cover. If the addition is intended, record"
echo "  an amendment justifying it against G11-G13 and update $LIST in the same commit."
exit 1
