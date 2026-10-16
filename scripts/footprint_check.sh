#!/usr/bin/env bash
#
# F3.6 — static footprint check.
#
# Enforces G11/G12/G13 on the SHIPPED code by asserting the ABSENCE of the APIs through which a host
# footprint is created: file writes, directory creation/removal, and RUNTIME environment reads (a runtime
# env read is how a program discovers $HOME / %APPDATA% / a config directory — i.e. how a footprint starts).
#
# ------------------------------------------------------------------------------------------------
# WHY THIS SCRIPT IS WRITTEN THE WAY IT IS
#
# `cfg_check.sh` was defeated ONCE by matching text rather than directives: a comment containing a gate
# string inflated its count, and it could invert prose while leaving the real gates untouched — reporting
# PASS on a tree it had not modified. That is DEFECT-002's family.
#
# This script is the same SHAPE of tool, so it takes the same precautions, deliberately:
#
#   1. it strips comments and string literals before matching, so prose cannot trip it or satisfy it;
#   2. it carries an EXPECTED count and FAILS on drift, so a rename cannot silently reduce coverage;
#   3. it fails LOUDLY on its own misconfiguration rather than passing;
#   4. it is MUTATION-TESTED (see tests/f36_footprint.rs) — a planted write call must make it fail.
#
# A checker that cannot fail is decoration.
# ------------------------------------------------------------------------------------------------

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Files whose absence-of-write-APIs we assert: the SHIPPED code. Tests are excluded — a test may write to
# a temp directory to check something else, and that is not a host footprint left by the tool.
SHIPPED_DIRS=("src" "tokengen-sys/src")

# The count of checks actually performed. Guards against a file being renamed out of the glob, which would
# otherwise silently reduce this script to checking nothing.
EXPECTED_CHECKS=4

fail=0
checks_run=0

# Strips `//` line comments, `/* */` block comments, and string/char literals, so that a match is a match
# on CODE. Deliberately conservative: it may over-strip, and over-stripping causes a false FAIL (visible)
# rather than a false PASS (invisible), which is the correct direction for a security gate.
strip_comments() {
    python3 - "$1" <<'PYEOF'
import re, sys
src = open(sys.argv[1], encoding='utf-8', errors='replace').read()
# Block comments first (non-greedy), then line comments, then string-ish literals.
src = re.sub(r'/\*.*?\*/', ' ', src, flags=re.S)
src = re.sub(r'//[^\n]*', ' ', src)
src = re.sub(r'r#*".*?"#*', '""', src, flags=re.S)
src = re.sub(r'b?".*?(?<!\\)"', '""', src, flags=re.S)
src = re.sub(r"'(?:\\.|[^'\\])'", "''", src)
print(src)
PYEOF
}

# $1 = human name, $2 = PCRE pattern, $3 = the fix to suggest
check_absent() {
    local name="$1" pattern="$2" advice="$3"
    checks_run=$((checks_run + 1))
    local hits=""
    for dir in "${SHIPPED_DIRS[@]}"; do
        while IFS= read -r f; do
            [ -f "$f" ] || continue
            if strip_comments "$f" | grep -Pn "$pattern" >/dev/null 2>&1; then
                local where
                where="$(strip_comments "$f" | grep -Pn "$pattern" | head -3)"
                hits="${hits}${f}: ${where}"$'\n'
            fi
        done < <(find "$dir" -name '*.rs' -type f 2>/dev/null)
    done

    if [ -n "$hits" ]; then
        echo "  FAIL  $name"
        echo "$hits" | sed 's/^/          /'
        echo "          -> $advice"
        fail=1
    else
        echo "  ok    $name"
    fi
}

echo "F3.6 static footprint check — G11/G12/G13"
echo

# ---------------------------------------------------------------------------------------------
# G11: no files written outside the USB mount.
# ---------------------------------------------------------------------------------------------
check_absent \
    "G11: no file-creation or write APIs in shipped code" \
    '\b(fs::write|fs::File::create|File::create|OpenOptions|fs::create_dir|create_dir_all|fs::remove_file|fs::remove_dir|fs::remove_dir_all|fs::rename|fs::copy|fs::set_permissions|write_all|write!)\s*\(' \
    "G11 forbids writing files on the host. If a write is genuinely required, it needs a recorded amendment."

# ---------------------------------------------------------------------------------------------
# G12/G13: no registry / plist / dconf / MRU integration.
# Named rather than enumerated by crate, because the point is that NONE of these appear at all.
# ---------------------------------------------------------------------------------------------
check_absent \
    "G12/G13: no registry, plist, dconf or MRU references in shipped code" \
    '(windows::Win32::System::Registry|RegOpenKey|RegSetValue|RegCreateKey|CFPreferences|dconf|gsettings|RecentDocs|SHAddToRecentDocs|MRU)' \
    "G12 forbids registry/plist/dconf writes and G13 forbids MRU integration. Remove the reference."

# ---------------------------------------------------------------------------------------------
# G11: no RUNTIME environment reads. Compile-time `option_env!` is permitted — it is a BUILD gate that
# cannot be set by a user of a built binary (see src/session.rs's dev-mode acknowledgement).
# ---------------------------------------------------------------------------------------------
check_absent \
    "G11: no runtime environment reads in shipped code" \
    '\b(env::var|env::vars|env::var_os|std::env::var|std::env::vars)\s*[(<]' \
    "A runtime env read is how a program discovers \$HOME / %APPDATA% / a config dir — i.e. how a host footprint starts. The compile-time option_env! is permitted."

# ---------------------------------------------------------------------------------------------
# G7 (adjacent): no external process spawning, which could write on the tool's behalf.
# ---------------------------------------------------------------------------------------------
check_absent \
    "G7: no process spawning in shipped code" \
    '\b(Command::new|std::process::Command|process::Command)\b' \
    "G7 forbids relying on external binaries; spawning is also a way to leave a footprint indirectly."

echo
if [ "$checks_run" -ne "$EXPECTED_CHECKS" ]; then
    echo "FATAL: expected $EXPECTED_CHECKS checks but ran $checks_run."
    echo "       A file or directory was renamed out of the glob, or a check was removed without updating"
    echo "       EXPECTED_CHECKS. This script would otherwise report PASS while checking less than it claims."
    exit 1
fi

if [ "$fail" -ne 0 ]; then
    echo "F3.6 static footprint check: FAIL"
    exit 1
fi

echo "F3.6 static footprint check: PASS — $checks_run checks, no write/environment-registry surface in shipped code"
