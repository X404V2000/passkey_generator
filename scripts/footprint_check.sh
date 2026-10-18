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

# Files whose absence-of-write-APIs we assert: the SHIPPED LIBRARY code.
SHIPPED_DIRS=("src" "tokengen-sys/src")

# ------------------------------------------------------------------------------------------------
# THE BINARY EXCLUSION — DECLARED, PRINTED AND COUNTED (F4 blueprint §7, criterion 5)
#
# `tokengen-cli/` is DELIBERATELY NOT SCANNED, and the reason matters:
#
#   G11 says "zero FILES written outside the USB mount". A binary writing to the TERMINAL is not writing a
#   file — it is what a CLI exists to do. Scanning it would produce a guaranteed FAIL on `print!`, and a
#   gate that always fails is a gate that gets disabled.
#
# WHAT THIS EXCLUSION DOES COST, stated so nobody has to infer it: the binary's own behaviour is NOT covered
# by the static check. A `std::fs::write` added to `tokengen-cli/` would NOT be caught here. That is covered
# by F3.6's BEHAVIOURAL test instead, which runs the binary and diffs the watched paths — weaker than a
# static guarantee, and the honest form of the claim.
#
# WHY IT IS WRITTEN THIS WAY: before F4, the exclusion was ACCIDENTAL — the glob simply did not reach
# `tokengen-cli/`. An accidental exclusion is indistinguishable from a forgotten one, and that is exactly
# where a check quietly becomes hollow. It is now declared here, PRINTED by the script, and ASSERTED below,
# so a future directory cannot join the exclusion by being forgotten.
EXCLUDED_DIRS=("tokengen-cli")
# Every directory in the workspace that contains Rust source, so a NEW crate cannot slip past both the
# scan and this declaration. If someone adds a crate, this list must be updated deliberately.
KNOWN_CRATE_DIRS=("src" "tokengen-sys/src" "tokengen-cli/src")

# The count of checks actually performed. Guards against a file being renamed out of the glob, which would
# otherwise silently reduce this script to checking nothing.
EXPECTED_CHECKS=4

fail=0
checks_run=0

# Strip ONLY `#!`/`#` attribute lines? No — strip NOTHING. Match the raw text.
#
# ------------------------------------------------------------------------------------------------
# THIS USED TO STRIP COMMENTS AND STRING LITERALS WITH REGEXES, AND THAT WAS DEFEATED.
#
# Found by Grace attacking her own brief's case A2: an order-dependent regex stripper DESYNCHRONISES on
# valid Rust. One line:
#
#     pub fn p() { let c = '"'; std::fs::write("/tmp/c", b"x").ok(); }
#
# The string-literal rule ran before the char-literal rule, treated the double quote INSIDE '\"' as the
# opening of a string, and consumed up to the next double quote — which sat inside the write's argument
# list. Observed transformation:
#
#     after str : pub fn p() { let c = '""/tmp/c""x").ok(); }
#                                       ^^^^^^^^^^^^^ the call head `std::fs::write(` is GONE
#
# So a write call could be HIDDEN by writing `'"'` earlier on the same line. That is a false PASS, which
# is the dangerous direction.
#
# THE FIX IS NOT A BETTER REGEX. Any regex approximating Rust's lexical grammar will desynchronise
# somewhere, and each patch invites the next bypass. So this strips NOTHING and matches the raw source.
#
# The cost is false FAILS: a comment or a string that mentions `fs::write` now trips the check. That is the
# SURVIVABLE direction — a false FAIL is visible, blocks the build, and is fixed by rewording a comment; a
# false PASS ships a tool that writes to the host. Where a legitimate mention must exist (an explanatory
# comment in shipped code), the right response is to move the explanation out of `src/` or to reword it —
# not to make the checker blind again.
# ------------------------------------------------------------------------------------------------
strip_comments() {
    cat "$1"
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
echo "  scanned:  ${SHIPPED_DIRS[*]}"
echo "  excluded: ${EXCLUDED_DIRS[*]}  (terminal writes are not file writes; see the header)"
echo

# Every known crate directory must be either scanned or explicitly excluded. A new crate that is neither
# would be silently ignored — the accidental-exclusion failure this block exists to prevent.
for dir in "${KNOWN_CRATE_DIRS[@]}"; do
    known=0
    for s_dir in "${SHIPPED_DIRS[@]}"; do [ "$s_dir" = "$dir" ] && known=1; done
    for e_dir in "${EXCLUDED_DIRS[@]}"; do [ "$e_dir/src" = "$dir" ] && known=1; done
    if [ "$known" -eq 0 ]; then
        echo "FATAL: crate directory '$dir' is neither scanned nor explicitly excluded."
        echo "       Add it to SHIPPED_DIRS (it is library code) or to EXCLUDED_DIRS with a reason in the"
        echo "       header. An unclassified crate is an accidental exclusion."
        exit 1
    fi
done

# ---------------------------------------------------------------------------------------------
# G11: no files written outside the USB mount.
# ---------------------------------------------------------------------------------------------
# Matching REFERENCES, not only calls.
#
# The first version of this pattern required a following `(`, so it matched CALL EXPRESSIONS. That was
# defeated by ordinary Rust that never writes the call form at the point of capability:
#
#     let w = std::fs::write;              // capability acquired
#     w("/tmp/q", b"r").ok();              // used through an alias — pattern never sees `fs::write(`
#
#     use std::fs::write as stealth_write; // alias introduced at the use site
#     stealth_write("/tmp/a", b"b").ok();
#
#     let f = std::fs::File::create;      // same shape for File::create
#
# Found by attacking my own checker before asking Grace to. The lesson is the same one this project keeps
# relearning: a probe narrower than the claim it supports. The claim was "no write capability in shipped
# code"; the probe was "no write CALL". Those are different, and the gap was exploitable with normal code.
#
# So the pattern now matches the NAMES wherever they appear — as a call target, as a value, or in a
# `use ... as` alias — which is the conservative direction: an unused import is a false FAIL (visible and
# trivial to fix), while a bypassed alias is a false PASS (invisible and dangerous).
check_absent \
    "G11: no file-creation or write capability in shipped code (calls, references, and aliases)" \
    '(std::fs::write|fs::write|std::fs::File::create|fs::File::create|File::create|File::options|fs::File::options|OpenOptions|std::fs::create_dir|fs::create_dir|create_dir_all|std::fs::remove_file|fs::remove_file|std::fs::remove_dir|fs::remove_dir|remove_dir_all|std::fs::rename|fs::rename|std::fs::copy|fs::copy|std::fs::set_permissions|fs::set_permissions|std::fs::hard_link|fs::hard_link|std::fs::soft_link|fs::soft_link|std::fs::set_file_times|fs::set_file_times|std::io::Write|std::io::copy|io::copy|BufWriter|write_all|write!|writeln!|write_fmt|write_str)' \
    "G11 forbids writing files on the host. If a write is genuinely required, it needs a recorded amendment. Note this matches REFERENCES and ALIASES too, so 'let w = std::fs::write' is caught."

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
# Same correction as the write check: match the NAME, not the call, so an alias cannot slip past. The
# compile-time `option_env!` remains permitted — it is a BUILD gate a user of a built binary cannot set.
check_absent \
    "G11: no runtime environment access in shipped code (calls, references, and aliases)" \
    '(std::env::var|env::var|env::vars|env::var_os|env::var_os|std::env::args|env::args)' \
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
