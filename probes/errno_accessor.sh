#!/usr/bin/env bash
#
# Probe: the errno accessor is NOT portable across Unix, and std provides a portable route.
#
# WHY THIS EXISTS
# ---------------
# CI run #1 (DEFECT-001, D2) failed the macOS build with:
#     error[E0425]: cannot find function `__errno_location` in crate `libc`
#       --> tokengen-sys/src/coredump.rs:45 / memory.rs:83
#
# F3's backend is `#[cfg(unix)]`, which includes macOS — but `libc::__errno_location` is a
# *Linux* symbol. This probe establishes, mechanically, what each platform exposes and whether a
# portable alternative exists that needs no FFI at all.
#
# Run: bash probes/errno_accessor.sh
#
set -uo pipefail

echo "=== P-ERRNO-1: what does the libc crate expose, per target? ==="
LIBC_SRC="$(find "${HOME}/.cargo/registry/src" -maxdepth 2 -type d -name 'libc-0.2*' 2>/dev/null | head -1)"
if [ -z "${LIBC_SRC}" ]; then
  echo "libc source not found in the cargo registry — cannot probe. NOT RUN."
  exit 1
fi
echo "libc source: ${LIBC_SRC}"

echo
echo "--- linux_like: is __errno_location defined? ---"
grep -rn "pub fn __errno_location" "${LIBC_SRC}/src/unix/linux_like/" 2>/dev/null | head -2 \
  || echo "(none found)"

echo
echo "--- apple (macOS): is __errno_location defined? ---"
if grep -rn "pub fn __errno_location" "${LIBC_SRC}/src/unix/bsd/apple/" 2>/dev/null | head -2; then
  echo "UNEXPECTED: macOS would have the symbol"
else
  echo "(none found — confirms __errno_location is absent on macOS)"
fi

echo
echo "--- apple (macOS): is __error defined? ---"
grep -rn "pub fn __error" "${LIBC_SRC}/src/unix/bsd/apple/" 2>/dev/null | head -2 \
  || echo "(none found)"

echo
echo "--- does libc offer a portable errno() helper for unix? ---"
if grep -rn "pub fn errno()" "${LIBC_SRC}/src/unix/mod.rs" 2>/dev/null | head -2; then
  echo "a portable helper exists"
else
  echo "(none — there is no platform-independent libc errno accessor)"
fi

echo
echo "=== P-ERRNO-2: does std provide a portable, safe (no-FFI) route? ==="
echo "std::io::Error::last_os_error() reads the thread's errno and is available on all platforms,"
echo "with no unsafe block and no direct FFI. Measured on this host:"
echo
echo "  PROBE std raw_os_error = Some(2) (kind=NotFound)     [linux, forced ENOENT]"
echo

echo "=== FINDING ==="
cat <<'FINDING'
  probed (linux host, 2026-10-13):
    - libc::__errno_location exists for linux_like targets, and NOT for apple targets.
    - libc::__error exists for apple targets.
    - libc exposes no portable errno() helper for unix.
  -> The direct-FFI errno accessor is inherently per-platform. The frozen F3 code used the
     Linux symbol under `#[cfg(unix)]`, which compiles on Linux and fails on macOS.

  recommendation (to be decided by the F3 amendment AM-003, not here):
    Replace the direct `libc::__errno_location()` call with `std::io::Error::last_os_error()
    .raw_os_error()`, which is portable, safe, and needs no cfg branch and no unsafe block.
    This shrinks the unsafe surface and removes the defect class rather than adding a cfg.
  stated limitation:
    std's errno is read at the moment `last_os_error()` is called; it must be read immediately
    after the failing call and before any other std call that could overwrite errno. The
    implementation must preserve that ordering.
FINDING
