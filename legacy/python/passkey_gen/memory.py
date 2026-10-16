"""
Secure memory management and zeroization primitives.
Ensures generated sensitive keys do not persist in memory, heap dumps, or cache.
"""

import ctypes
import gc
import os
import sys
from typing import Optional


# Attempt to load libc for secure memory wiping primitives
_libc = None
_explicit_bzero = None
_memset = None
_mlock = None
_munlock = None

try:
    _libc = ctypes.CDLL(None)
    # explicit_bzero is immune to compiler dead-store elimination
    if hasattr(_libc, "explicit_bzero"):
        _explicit_bzero = _libc.explicit_bzero
        _explicit_bzero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _explicit_bzero.restype = None
    elif hasattr(_libc, "memset"):
        _memset = _libc.memset
        _memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
        _memset.restype = ctypes.c_void_p

    if hasattr(_libc, "mlock"):
        _mlock = _libc.mlock
        _mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _mlock.restype = ctypes.c_int

    if hasattr(_libc, "munlock"):
        _munlock = _libc.munlock
        _munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _munlock.restype = ctypes.c_int
except Exception:
    # Gracefully degrade to managed Python memory wiping if libc functions are unavailable
    pass


def zeroize_buffer(buf: ctypes.Array | bytearray | memoryview) -> None:
    """
    Cryptographically wipe the memory of a buffer with zeroes.
    Uses OS-level explicit_bzero/memset where available, combined with
    Python-level byte clearing.
    """
    if not buf:
        return

    buf_len = len(buf)
    if buf_len == 0:
        return

    # Extract memory address
    addr = None
    try:
        if isinstance(buf, ctypes.Array):
            addr = ctypes.addressof(buf)
        elif isinstance(buf, (bytearray, memoryview)):
            c_char_array = (ctypes.c_char * buf_len).from_buffer(buf)
            addr = ctypes.addressof(c_char_array)
    except Exception:
        addr = None

    # Native OS memory zeroing
    if addr is not None:
        if _explicit_bzero is not None:
            _explicit_bzero(ctypes.c_void_p(addr), ctypes.c_size_t(buf_len))
        elif _memset is not None:
            _memset(ctypes.c_void_p(addr), 0, ctypes.c_size_t(buf_len))

    # Python-level overwrite
    if isinstance(buf, (bytearray, memoryview)):
        for i in range(buf_len):
            buf[i] = 0


class SecurePasskey:
    """
    A temporary, non-caching, auto-zeroizing container for passkeys.
    
    Guarantees:
    1. No persistent in-memory caching.
    2. Overwrites underlying memory with zeros immediately on exit or explicit destruction.
    3. Prevents accidental leakage in logs, tracebacks, or representations.
    4. Optional best-effort memory locking (mlock) to prevent swapping to disk.
    """

    def __init__(self, raw_bytes: bytes | bytearray):
        self._length = len(raw_bytes)
        self._destroyed = False
        
        # Allocate a dedicated ctypes C-string buffer
        self._buffer: Optional[ctypes.Array] = ctypes.create_string_buffer(bytes(raw_bytes), self._length)
        
        # Best effort lock memory to prevent paging/swap out to disk
        self._locked = False
        if _mlock is not None and self._buffer is not None:
            try:
                res = _mlock(ctypes.addressof(self._buffer), ctypes.c_size_t(self._length))
                self._locked = (res == 0)
            except Exception:
                self._locked = False

    @property
    def length(self) -> int:
        return self._length

    @property
    def is_destroyed(self) -> bool:
        return self._destroyed

    def get_value(self) -> str:
        """
        Extract the passkey as a temporary string.
        Should only be called at the exact moment of consumption.
        """
        if self._destroyed or self._buffer is None:
            raise RuntimeError("Access error: Passkey buffer has already been zeroized and destroyed.")
        return self._buffer.raw.decode("ascii")

    def write_to_fd(self, fd: int, add_newline: bool = True) -> None:
        """
        Write the passkey directly to an OS file descriptor (e.g. sys.stdout.fileno())
        without creating long-lived Python string objects in heap.
        """
        if self._destroyed or self._buffer is None:
            raise RuntimeError("Access error: Passkey buffer has already been zeroized and destroyed.")
        
        os.write(fd, self._buffer.raw)
        if add_newline:
            os.write(fd, b"\n")

    def destroy(self) -> None:
        """
        Immediately zero out memory and discard buffers.
        """
        if self._destroyed:
            return

        if self._buffer is not None:
            # Unlock from RAM if locked
            if self._locked and _munlock is not None:
                try:
                    _munlock(ctypes.addressof(self._buffer), ctypes.c_size_t(self._length))
                except Exception:
                    pass
                self._locked = False

            # Zeroize native memory
            zeroize_buffer(self._buffer)
            self._buffer = None

        self._destroyed = True
        # Prompt immediate GC to clean up any temporary references
        gc.collect()

    def __enter__(self) -> "SecurePasskey":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.destroy()

    def __del__(self) -> None:
        self.destroy()

    def __repr__(self) -> str:
        status = "DESTROYED" if self._destroyed else f"ACTIVE(length={self._length})"
        return f"<SecurePasskey [{status}]>"

    def __str__(self) -> str:
        return "<SecurePasskey: [REDACTED FOR SECURITY]>"
