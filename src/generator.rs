//! F2 — Charset & Rejection Sampling Key Generator.
//!
//! Turns raw random bytes from [`crate::entropy`] (F1) into uniformly
//! distributed character keys of a caller-specified length and character set.
//!
//! Key generation uses **rejection sampling**, never modulo reduction. See
//! [`generate_key`] for the uniformity argument.

use crate::entropy::{EntropySource, OsEntropy};

/// Size of the entropy batch drawn per rejection-sampling round.
///
/// Any value in `1..=256` is correct; this choice only affects how often the
/// operating system is called. It is an implementation detail and does not
/// influence the distribution of the output.
const ENTROPY_BATCH_SIZE: usize = 32;

/// A character set used for key generation.
///
/// The set is stored as a sequence of unique bytes. Duplicates are a
/// programming error and MUST be rejected at construction time.
pub struct Charset {
    // Private: callers cannot observe or mutate the bytes, which keeps the
    // uniqueness and non-emptiness guarantees established in `new` intact.
    bytes: Vec<u8>,
}

impl Charset {
    /// Construct a charset from a byte slice.
    ///
    /// Returns `Err(GeneratorError::EmptyCharset)` if the slice is empty.
    /// Returns `Err(GeneratorError::DuplicateByte)` if any byte repeats.
    ///
    /// The bytes are stored exactly as supplied: they are not sorted,
    /// trimmed, normalized, or silently deduplicated.
    pub fn new(bytes: &[u8]) -> Result<Self, GeneratorError> {
        if bytes.is_empty() {
            return Err(GeneratorError::EmptyCharset);
        }

        // A byte is an index into this table, so 256 entries cover every
        // possible value. O(n) time, O(1) space, and no hashing machinery.
        let mut seen = [false; 256];
        for &byte in bytes {
            if seen[byte as usize] {
                return Err(GeneratorError::DuplicateByte);
            }
            seen[byte as usize] = true;
        }

        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// The lowercase ASCII letters a–z (26 bytes).
    #[must_use]
    pub fn lowercase() -> Self {
        Self::from_known_unique(b"abcdefghijklmnopqrstuvwxyz")
    }

    /// The uppercase ASCII letters A–Z (26 bytes).
    #[must_use]
    pub fn uppercase() -> Self {
        Self::from_known_unique(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    }

    /// The digits 0–9 (10 bytes).
    #[must_use]
    pub fn digits() -> Self {
        Self::from_known_unique(b"0123456789")
    }

    /// The standard symbol set: `!@#$%^&*()-_=+[]{}<>?/|~` (24 bytes).
    #[must_use]
    pub fn symbols() -> Self {
        Self::from_known_unique(b"!@#$%^&*()-_=+[]{}<>?/|~")
    }

    /// Length of the charset in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True if the charset has zero bytes.
    ///
    /// A successfully constructed `Charset` is never empty, but this method is
    /// provided for API completeness and to satisfy clippy's `len_without_is_empty`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Look up the byte at `idx`.
    ///
    /// `generate_key` only ever calls this with `idx < self.len()`, so the
    /// bound is guaranteed by the algorithm rather than checked here.
    fn byte_at(&self, idx: usize) -> u8 {
        self.bytes[idx]
    }

    /// Build a charset from a literal whose uniqueness is guaranteed by its
    /// own definition, bypassing the `Result` of [`Charset::new`].
    ///
    /// The named constructors are compile-time constants with no duplicates,
    /// so propagating a `Result` to callers would be infallible in practice.
    fn from_known_unique(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }
}

/// Error type for all key-generation failures.
#[derive(Debug)]
pub enum GeneratorError {
    /// The charset was empty.
    EmptyCharset,
    /// The charset contained a duplicate byte.
    DuplicateByte,
    /// The underlying entropy source failed.
    Entropy(crate::entropy::EntropyError),
    /// The requested length was zero.
    ZeroLength,
}

/// Generate a random key of `length` characters drawn uniformly from
/// `charset`, using `entropy` as the source of randomness.
///
/// Uses rejection sampling: bytes that would introduce modulo bias are
/// discarded and re-drawn. The output is uniformly distributed over all keys
/// of the requested length and charset.
///
/// Returns `Err(GeneratorError::ZeroLength)` if `length == 0`.
/// Returns `Err(GeneratorError::Entropy(_))` if the OS CSPRNG fails.
pub fn generate_key<S: EntropySource>(
    entropy: &S,
    charset: &Charset,
    length: usize,
) -> Result<Vec<u8>, GeneratorError> {
    if length == 0 {
        return Err(GeneratorError::ZeroLength);
    }

    // `charset.len()` is 1..=256: `Charset` rejects empty input and a byte
    // slice cannot hold more than 256 distinct values.
    let n = charset.len();
    debug_assert!(n > 0 && n <= 256, "Charset invariant violated");

    // Accept bytes in [0, limit). If n divides 256 then limit == 256 and no
    // byte is ever rejected.
    let limit = 256 - (256 % n);

    let mut out = Vec::with_capacity(length);
    let mut buf = [0u8; ENTROPY_BATCH_SIZE];

    while out.len() < length {
        entropy.fill(&mut buf).map_err(GeneratorError::Entropy)?;

        for &byte in &buf {
            if (byte as usize) < limit {
                // Safe: `byte < limit` and `limit % n == 0`, so `byte % n < n`
                // and the result is uniform over [0, n).
                out.push(charset.byte_at((byte as usize) % n));

                if out.len() == length {
                    break;
                }
            }
        }
    }

    Ok(out)
}

/// Convenience wrapper: generate a key using the OS CSPRNG.
///
/// Equivalent to `generate_key(&OsEntropy::new(), charset, length)`.
pub fn generate_key_os(charset: &Charset, length: usize) -> Result<Vec<u8>, GeneratorError> {
    generate_key(&OsEntropy::new(), charset, length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::EntropyError;
    use std::cell::Cell;

    /// Entropy source that replays a caller-supplied script of batches.
    ///
    /// `batches[k]` is the content of the destination buffer on the k-th
    /// `fill` call. Each batch is written cyclically across the buffer, so a
    /// single-element batch fills every slot with that byte. Once the batch
    /// list is exhausted the final batch repeats, which keeps generation
    /// terminating for tests that only care about the leading draws.
    ///
    /// Modelling entropy as *per-fill batches* (rather than a flat byte
    /// sequence) is what lets the rejection tests be exact: a caller can force
    /// an entire 32-byte batch to be rejected and specify precisely what the
    /// next draw contains.
    ///
    /// `Cell` provides interior mutability because [`EntropySource::fill`]
    /// takes `&self`; this keeps the mock free of `unsafe` and of runtime
    /// borrow checking.
    struct MockEntropy {
        batches: Vec<Vec<u8>>,
        calls: Cell<usize>,
    }

    impl MockEntropy {
        /// Mock that emits `batch` on every `fill` call.
        fn always(batch: &[u8]) -> Self {
            Self::scripted(&[batch])
        }

        /// Mock whose every emitted byte is `value`.
        fn repeating(value: u8) -> Self {
            Self::always(&[value])
        }

        /// Mock that emits `batches[k]` on the k-th `fill` call, repeating the
        /// last batch thereafter.
        fn scripted(batches: &[&[u8]]) -> Self {
            assert!(!batches.is_empty(), "mock script must not be empty");

            let batches: Vec<Vec<u8>> = batches
                .iter()
                .map(|batch| {
                    assert!(!batch.is_empty(), "mock batch must not be empty");
                    batch.to_vec()
                })
                .collect();

            Self {
                batches,
                calls: Cell::new(0),
            }
        }

        /// How many times `fill` has been called.
        fn calls(&self) -> usize {
            self.calls.get()
        }
    }

    impl EntropySource for MockEntropy {
        fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError> {
            if buf.is_empty() {
                return Ok(());
            }

            let call = self.calls.get();
            self.calls.set(call + 1);

            // Clamp to the final batch once the script is exhausted.
            let batch = &self.batches[call.min(self.batches.len() - 1)];

            for (offset, slot) in buf.iter_mut().enumerate() {
                *slot = batch[offset % batch.len()];
            }

            Ok(())
        }
    }

    #[test]
    fn charset_rejects_empty() {
        assert!(matches!(
            Charset::new(&[]),
            Err(GeneratorError::EmptyCharset)
        ));
    }

    #[test]
    fn charset_rejects_duplicates() {
        assert!(matches!(
            Charset::new(b"aab"),
            Err(GeneratorError::DuplicateByte)
        ));
    }

    #[test]
    fn charset_builders_correct() {
        let builders = [
            (Charset::lowercase(), 26usize),
            (Charset::uppercase(), 26),
            (Charset::digits(), 10),
            (Charset::symbols(), 24),
        ];

        for (charset, expected_len) in builders {
            assert_eq!(charset.len(), expected_len);
            assert!(!charset.is_empty());

            let mut seen = [false; 256];
            for &byte in &charset.bytes {
                assert!(!seen[byte as usize], "duplicate byte in builder");
                seen[byte as usize] = true;
            }
        }

        assert_eq!(Charset::symbols().bytes, b"!@#$%^&*()-_=+[]{}<>?/|~");
    }

    #[test]
    fn generate_rejects_zero_length() {
        let mock = MockEntropy::repeating(0);
        let charset = Charset::lowercase();
        assert!(matches!(
            generate_key(&mock, &charset, 0),
            Err(GeneratorError::ZeroLength)
        ));
    }

    #[test]
    fn generate_produces_requested_length() {
        let charset = Charset::lowercase();
        for length in [1usize, 32, 256] {
            let mock = MockEntropy::always(&[0, 1, 2, 3, 4, 5, 6, 7]);
            let key = generate_key(&mock, &charset, length);
            assert!(key.is_ok());
            if let Ok(key) = key {
                assert_eq!(key.len(), length);
            }
        }
    }

    #[test]
    fn generate_uses_only_charset_bytes() {
        let charset = Charset::lowercase();
        for _ in 0..1000 {
            if let Ok(key) = generate_key_os(&charset, 64) {
                assert_eq!(key.len(), 64);
                for byte in key {
                    assert!(byte.is_ascii_lowercase());
                }
            }
        }
    }

    #[test]
    fn generate_propagates_entropy_error() {
        struct FailingEntropy;

        impl EntropySource for FailingEntropy {
            fn fill(&self, _buf: &mut [u8]) -> Result<(), EntropyError> {
                Err(EntropyError::OsFailure(getrandom::Error::UNSUPPORTED))
            }
        }

        let charset = Charset::lowercase();
        assert!(matches!(
            generate_key(&FailingEntropy, &charset, 8),
            Err(GeneratorError::Entropy(_))
        ));
    }

    #[test]
    fn generate_rejects_biased_bytes() {
        // Proof that rejection sampling is implemented, not modulo reduction.
        //
        // n = 6 -> 256 % 6 == 4, so limit = 252. Bytes in [252, 256) MUST be
        // discarded; bytes in [0, 252) MUST be accepted.
        //
        // The script leads with 255 and 252 — both rejected — then 1, which is
        // accepted and maps to index 1 % 6 == 1 -> b'b'.
        //
        // This discriminates the two implementations:
        //   rejection: 255 discarded, 252 discarded, 1 accepted -> b'b'
        //   modulo:    255 accepted -> charset[255 % 6] = charset[3] -> b'd'
        //
        // The expected outputs differ, so a modulo implementation cannot pass.
        let charset = Charset::new(b"abcdef");
        assert!(charset.is_ok());
        let Ok(charset) = charset else { return };

        let mock = MockEntropy::always(&[255, 252, 1]);
        let key = generate_key(&mock, &charset, 1);

        assert!(key.is_ok());
        if let Ok(key) = key {
            assert_eq!(key.len(), 1);
            assert_eq!(key[0], b'b', "rejection sampling derived the wrong index");
        }
    }

    #[test]
    fn generate_redraws_when_entire_batch_is_rejected() {
        // n = 255 -> 256 % 255 == 1, so limit = 255. Only byte 255 is rejected.
        // The first `fill` therefore yields 32 unusable bytes and the loop must
        // draw again; the second `fill` supplies an accepted byte, 254.
        //
        // Build a 255-byte charset: the 254 values 0..=253 plus 254.
        let mut bytes: Vec<u8> = (0u8..=253).collect();
        bytes.push(254);
        assert_eq!(bytes.len(), 255);

        let charset = Charset::new(&bytes);
        assert!(charset.is_ok());
        let Ok(charset) = charset else { return };

        // Batch 1 is entirely 255 (every byte rejected); batch 2 supplies 254.
        let mock = MockEntropy::scripted(&[&[255], &[254]]);
        let key = generate_key(&mock, &charset, 1);

        assert!(key.is_ok());
        if let Ok(key) = key {
            assert_eq!(key.len(), 1);
            // 254 < 255 is accepted; 254 % 255 == 254 -> charset[254] == 254.
            assert_eq!(key[0], 254);
        }

        // The first batch was entirely rejected, so a second draw was required.
        assert!(
            mock.calls() >= 2,
            "rejected batch must trigger another entropy draw"
        );
    }

    #[test]
    fn generate_no_reuse() {
        let charset = Charset::lowercase();
        let first = generate_key_os(&charset, 64);
        let second = generate_key_os(&charset, 64);
        assert!(first.is_ok() && second.is_ok());
        if let (Ok(first), Ok(second)) = (first, second) {
            assert_ne!(first, second);
        }
    }

    #[test]
    fn generate_key_os_matches_generate_key() {
        let charset = Charset::digits();

        let convenience = generate_key_os(&charset, 16);
        let explicit = generate_key(&OsEntropy::new(), &charset, 16);

        assert!(convenience.is_ok() && explicit.is_ok());
        if let (Ok(convenience), Ok(explicit)) = (convenience, explicit) {
            assert_eq!(convenience.len(), 16);
            assert_eq!(explicit.len(), 16);
            for byte in convenience.iter().chain(explicit.iter()) {
                assert!(byte.is_ascii_digit());
            }
        }
    }
}
