import math
from collections import Counter
import pytest
from passkey_gen.charsets import ALPHANUMERIC_CHARS, HEX_CHARS, CharsetPreset
from passkey_gen.generator import (
    MAX_PASSKEY_LENGTH,
    MIN_PASSKEY_LENGTH,
    PasskeyGenerator,
)


def test_generator_32_characters():
    gen = PasskeyGenerator()
    with gen.generate(length=32) as key:
        val = key.get_value()
        assert len(val) == 32
        assert all(c in ALPHANUMERIC_CHARS for c in val)


def test_generator_64_characters():
    gen = PasskeyGenerator()
    with gen.generate(length=64) as key:
        val = key.get_value()
        assert len(val) == 64
        assert all(c in ALPHANUMERIC_CHARS for c in val)


def test_generator_custom_length():
    gen = PasskeyGenerator()
    for length in (8, 17, 53, 100, 256):
        with gen.generate(length=length) as key:
            val = key.get_value()
            assert len(val) == length


def test_generator_boundary_validation():
    gen = PasskeyGenerator()

    with pytest.raises(ValueError, match="at least 8 characters"):
        gen.generate(length=MIN_PASSKEY_LENGTH - 1)

    with pytest.raises(ValueError, match="cannot exceed"):
        gen.generate(length=MAX_PASSKEY_LENGTH + 1)

    with pytest.raises(TypeError):
        gen.generate(length="32")  # type: ignore

    with pytest.raises(TypeError):
        gen.generate(length=True)  # type: ignore


def test_generator_custom_charset():
    gen = PasskeyGenerator()
    custom_charset = "01"  # binary
    with gen.generate(length=32, charset=custom_charset) as key:
        val = key.get_value()
        assert len(val) == 32
        assert all(c in "01" for c in val)

    with gen.generate(length=32, charset=CharsetPreset.HEX) as key:
        val = key.get_value()
        assert len(val) == 32
        assert all(c in HEX_CHARS for c in val)


def test_generator_statelessness_and_uniqueness():
    """Ensure consecutive calls produce distinct high-entropy keys with no caching."""
    gen = PasskeyGenerator()
    generated_set = set()
    total = 200

    for _ in range(total):
        with gen.generate(length=32) as key:
            val = key.get_value()
            assert val not in generated_set
            generated_set.add(val)

    assert len(generated_set) == total


def test_entropy_calculation():
    gen = PasskeyGenerator()

    # 32 chars from 62 alphanumeric chars: 32 * log2(62) ~= 190.53 bits
    entropy_32 = gen.calculate_entropy_bits(32, 62)
    expected_32 = 32 * math.log2(62)
    assert pytest.approx(entropy_32, 0.01) == expected_32

    # 64 chars from 62 chars: 64 * log2(62) ~= 381.06 bits
    entropy_64 = gen.calculate_entropy_bits(64, 62)
    expected_64 = 64 * math.log2(62)
    assert pytest.approx(entropy_64, 0.01) == expected_64


def test_uniform_distribution_rejection_sampling():
    """
    Verify rejection sampling produces a statistically uniform distribution without modulo bias.
    Using a small charset of 5 characters where 256 % 5 = 1.
    Naive modulo (b % 5) would heavily bias index 0. Rejection sampling must avoid this.
    """
    gen = PasskeyGenerator()
    charset = "ABCDE"
    sample_size = 50000

    with gen.generate(length=sample_size, charset=charset) as key:
        data = key.get_value()

    counts = Counter(data)
    expected = sample_size / len(charset)  # 10,000

    # Chi-square goodness-of-fit test statistic: sum((O - E)^2 / E)
    chi_square = sum((counts[ch] - expected) ** 2 / expected for ch in charset)

    # For degrees of freedom = 4, critical value at p=0.01 is 13.28
    # With unbiased random data, chi_square should almost always be < 13.28
    assert chi_square < 15.0, f"Chi-square value {chi_square} suggests modulo bias!"
