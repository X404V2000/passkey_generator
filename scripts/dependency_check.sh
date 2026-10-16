#!/usr/bin/env bash
#
# F3.6 — shipped-dependency check.
#
# Asserts that the crates COMPILED INTO A RELEASE BUILD match the recorded allow-list exactly.
#
# Why this is the highest-value check in F3.6: G11-G13 are claims about what the TOOL does, but the real
# attack surface is the code the tool LINKS. A dependency that writes a cache file, reads %APPDATA%, or
# touches a registry would violate G11-G13 without a single line of this repository changing. A filesystem
# diff catches that only if it watches the right path at the right moment; this catches it at REVIEW TIME,
# deterministically, on all three platforms, before the code ever runs.
#
# ADDING A DEPENDENCY: add it to scripts/shipped-deps.txt in the same commit as the amendment that justifies
# it against G11-G13. If you have not written that amendment, the failure is the point.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LIST="scripts/shipped-deps.txt"

if [ ! -f "$LIST" ]; then
    echo "FATAL: $LIST is missing. This check cannot assert an allow-list that does not exist."
    exit 1
fi

# The recorded set: local crates excluded (they are this repository, not third-party code).
recorded="$(grep -v '^#' "$LIST" | grep -v '^[[:space:]]*$' | awk '{print $1" "$2}' | sort -u)"

# The actual set, from cargo's own view of the RELEASE graph.
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
    echo "       dependencies — it links libc. A check that passes on a failed parse proves nothing."
    exit 1
fi

echo "F3.6 shipped-dependency check"
echo
echo "  recorded:"
printf '%s\n' "$recorded" | sed 's/^/    /'
echo "  actual (release graph):"
printf '%s\n' "$actual" | sed 's/^/    /'
echo

if [ "$recorded" = "$actual" ]; then
    echo "F3.6 shipped-dependency check: PASS — the shipped graph matches the allow-list exactly"
    exit 0
fi

echo "F3.6 shipped-dependency check: FAIL — the shipped graph differs from the allow-list"
echo
echo "  added by this change:"
comm -13 <(printf '%s\n' "$recorded") <(printf '%s\n' "$actual") | sed 's/^/    + /'
echo "  removed by this change:"
comm -23 <(printf '%s\n' "$recorded") <(printf '%s\n' "$actual") | sed 's/^/    - /'
echo
echo "  A new crate is code the tool links and that G11-G13 must cover. If the addition is intended,"
echo "  record an amendment justifying it against G11-G13 and update $LIST in the same commit."
exit 1
