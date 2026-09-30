"""
Linux process hardening and memory protection primitives.

Implements defense-in-depth against local memory extraction, core dumps,
debugger injection (ptrace), and /proc/<pid>/mem snooping.
"""

import ctypes
import os
import sys
from typing import Any, Dict

try:
    import resource
except ImportError:
    resource = None

# Linux prctl constants from <sys/prctl.h>
PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4
PR_SET_NAME = 15
PR_GET_NAME = 16
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39

_libc = None
try:
    _libc = ctypes.CDLL(None)
    if hasattr(_libc, "prctl"):
        _libc.prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        _libc.prctl.restype = ctypes.c_int
except Exception:
    _libc = None


def disable_core_dumps() -> bool:
    """
    Disable core dump creation via RLIMIT_CORE.
    Prevents crash dumps from writing sensitive heap memory to disk.
    """
    if resource is not None:
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            return True
        except (ValueError, OSError):
            return False
    return False


def set_non_dumpable() -> bool:
    """
    Disable process dumpability using Linux prctl(PR_SET_DUMPABLE, 0).
    
    Security effects:
    1. Prevents other processes running under the same UID from reading /proc/<pid>/mem.
    2. Blocks ptrace(PTRACE_ATTACH) debugging attacks.
    3. Changes /proc/<pid>/ ownership to root:root to disallow unauthorized snooping.
    """
    if _libc is not None and hasattr(_libc, "prctl"):
        try:
            res = _libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
            return res == 0
        except Exception:
            return False
    return False


def set_no_new_privs() -> bool:
    """
    Enforce PR_SET_NO_NEW_PRIVS to prevent any execution from gaining
    elevated privileges (e.g. via setuid binaries).
    """
    if _libc is not None and hasattr(_libc, "prctl"):
        try:
            res = _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            return res == 0
        except Exception:
            return False
    return False


def set_process_name(name: str = "passkey-gen") -> bool:
    """
    Normalize process name in /proc/<pid>/comm.
    """
    if _libc is not None and hasattr(_libc, "prctl"):
        try:
            name_bytes = name.encode("ascii")[:15] + b"\x00"
            res = _libc.prctl(PR_SET_NAME, ctypes.cast(name_bytes, ctypes.c_void_p).value, 0, 0, 0)
            return res == 0
        except Exception:
            return False
    return False


def get_dumpable_status() -> int:
    """
    Query dumpable status (0 = non-dumpable / secure, 1 = dumpable / insecure).
    """
    if _libc is not None and hasattr(_libc, "prctl"):
        try:
            return _libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)
        except Exception:
            return -1
    return -1


def harden_process() -> Dict[str, bool]:
    """
    Apply full suite of process-level defenses.
    """
    results = {
        "core_dumps_disabled": disable_core_dumps(),
        "non_dumpable": set_non_dumpable(),
        "no_new_privs": set_no_new_privs(),
        "process_name_set": set_process_name("passkey-gen"),
    }
    return results


def check_security_status() -> Dict[str, Any]:
    """
    Inspect the current running process security posture.
    """
    status: Dict[str, Any] = {}
    
    # 1. Core dump limit
    if resource is not None:
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
            status["rlimit_core"] = f"soft={soft}, hard={hard}"
            status["core_dumps_disabled"] = (soft == 0 and hard == 0)
        except Exception as e:
            status["rlimit_core"] = str(e)
            status["core_dumps_disabled"] = False
    else:
        status["core_dumps_disabled"] = False

    # 2. Dumpable flag
    dumpable = get_dumpable_status()
    status["dumpable_flag"] = dumpable
    status["ptrace_protected"] = (dumpable == 0)

    # 3. No new privs
    if _libc is not None and hasattr(_libc, "prctl"):
        try:
            nnp = _libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
            status["no_new_privs"] = (nnp == 1)
        except Exception:
            status["no_new_privs"] = False
    else:
        status["no_new_privs"] = False

    # 4. Memory lock availability
    if _libc is not None and hasattr(_libc, "mlock"):
        status["mlock_available"] = True
    else:
        status["mlock_available"] = False

    return status
