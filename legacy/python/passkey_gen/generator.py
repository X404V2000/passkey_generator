"""
Cryptographically secure passkey generator.

Key architectural features:
1. Hardware / Kernel OS CSPRNG source (os.urandom / getrandom).
2. Elimination of modulo bias via rejection sampling.
3. Completely stateless: zero caching, zero memoization, zero global history.
4. Secure memory encapsulation: results are returned as zeroizable SecurePasskey objects.
"""

import math
import os
from typing import Union

from passkey_gen.charsets import CharsetPreset, get_charset
from passkey_gen.memory import SecurePasskey


# Security bounds
MIN_PASSKEY_LENGTH = 8
MAX_PASSKEY_LENGTH = 65536
DEFAULT_PRESET_LENGTHS = (32, 64)


class PasskeyGenerator:
    """
    Stateless cryptographically secure passkey generator.
    """

    def __init__(self):
        # Explicitly ensure no persistent caching attributes exist
        pass

    @staticmethod
    def calculate_entropy_bits(length: int, charset_size: int) -> float:
        """
        Calculate the information-theoretic entropy of the passkey in bits.
        H = length * log2(|charset|)
        """
        if charset_size <= 1 or length <= 0:
            return 0.0
        return length * math.log2(charset_size)

    def generate(
        self,
        length: int = 32,
        charset: Union[CharsetPreset, str] = CharsetPreset.ALPHANUMERIC,
    ) -> SecurePasskey:
        """
        Generate a cryptographically secure passkey of the specified length.
        
        Guarantees:
        - Modulo bias is 100% eliminated using rejection sampling.
        - The generated secret is returned in a SecurePasskey container that wipes
          itself from memory when closed or explicitly destroyed.
        - Does not cache, log, or persist the generated passkey.
        """
        if not isinstance(length, int) or isinstance(length, bool):
            raise TypeError(f"Length must be an integer, got {type(length).__name__}")

        if length < MIN_PASSKEY_LENGTH:
            raise ValueError(f"Passkey length must be at least {MIN_PASSKEY_LENGTH} characters for adequate security.")

        if length > MAX_PASSKEY_LENGTH:
            raise ValueError(f"Passkey length cannot exceed {MAX_PASSKEY_LENGTH} characters.")

        alphabet = get_charset(charset)
        charset_bytes = alphabet.encode("ascii")
        num_chars = len(charset_bytes)

        # Modulo bias elimination:
        # Compute the largest multiple of num_chars that fits in a single byte (256)
        # Any random byte >= limit is rejected and resampled to guarantee uniform distribution.
        limit = 256 - (256 % num_chars)

        output_buffer = bytearray(length)
        chars_collected = 0

        # Draw OS entropy in batches for efficiency while remaining strictly constant-bias
        batch_size = max(length * 2, 64)

        try:
            while chars_collected < length:
                random_bytes = os.urandom(batch_size)
                for b in random_bytes:
                    if b < limit:
                        output_buffer[chars_collected] = charset_bytes[b % num_chars]
                        chars_collected += 1
                        if chars_collected == length:
                            break

            # Encapsulate immediately in SecurePasskey container
            passkey = SecurePasskey(output_buffer)
            return passkey

        finally:
            # Zero out intermediate temporary bytearray to ensure no lingering plaintext
            for i in range(len(output_buffer)):
                output_buffer[i] = 0
            del output_buffer
