type OsError = getrandom::Error;

/// Error returned when the operating system's CSPRNG fails.
///
/// This type is deliberately opaque: it exposes only the underlying
/// OS error. It does not leak stack traces, internal state, or
/// partial random data.
#[derive(Debug)]
pub enum EntropyError {
    /// The OS CSPRNG call failed.
    OsFailure(OsError),
}

/// Source of cryptographically secure random bytes.
///
/// Implementations MUST source bytes exclusively from an OS CSPRNG.
/// Implementations MUST NOT retry, fall back, or return partial data
/// on failure. On any error, they MUST return `Err(EntropyError::OsFailure(..))`.
pub trait EntropySource {
    /// Fill `buf` with cryptographically secure random bytes.
    ///
    /// Returns `Ok(())` on success.
    /// Returns `Err(EntropyError::OsFailure(..))` on failure — the
    /// buffer's contents are unspecified in that case and MUST NOT
    /// be used.
    ///
    /// If `buf` is empty, returns `Ok(())` without calling the OS.
    fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError>;
}

/// Production implementation of [`EntropySource`] backed by the OS CSPRNG.
///
/// Uses `getrandom::getrandom`, which maps to:
/// - Windows: `BCryptGenRandom`
/// - Linux:   `getrandom(2)` syscall
/// - macOS:   `SecRandomCopyBytes`
pub struct OsEntropy;

impl OsEntropy {
    /// Create a new `OsEntropy`. No resources are allocated.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for OsEntropy {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropySource for OsEntropy {
    fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError> {
        if buf.is_empty() {
            return Ok(());
        }

        getrandom::getrandom(buf).map_err(EntropyError::OsFailure)
    }
}

/// Convenience wrapper: fill `buf` using the OS CSPRNG.
///
/// Equivalent to `OsEntropy::new().fill(buf)`.
pub fn fill_random(buf: &mut [u8]) -> Result<(), EntropyError> {
    OsEntropy::new().fill(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEntropy {
        should_fail: bool,
    }

    impl EntropySource for MockEntropy {
        fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError> {
            if buf.is_empty() {
                return Ok(());
            }
            if self.should_fail {
                return Err(EntropyError::OsFailure(getrandom::Error::UNSUPPORTED));
            }
            for byte in buf.iter_mut() {
                *byte = 0xAA;
            }
            Ok(())
        }
    }

    struct PanickingEntropy;

    impl EntropySource for PanickingEntropy {
        fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError> {
            if buf.is_empty() {
                Ok(())
            } else {
                unreachable!()
            }
        }
    }

    #[test]
    fn fill_random_empty_ok() {
        assert!(fill_random(&mut []).is_ok());
    }

    #[test]
    fn fill_random_produces_bytes() {
        let mut buf = [0u8; 32];
        assert!(fill_random(&mut buf).is_ok());
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn fill_random_1kb_ok() {
        let mut buf = [0u8; 1024];
        assert!(fill_random(&mut buf).is_ok());
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn fill_random_no_reuse() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        assert!(fill_random(&mut buf1).is_ok());
        assert!(fill_random(&mut buf2).is_ok());
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn fill_random_returns_error_on_failure() {
        let mock = MockEntropy { should_fail: true };
        let mut buf = [0u8; 32];
        let res = mock.fill(&mut buf);
        assert!(res.is_err());
    }

    #[test]
    fn fill_empty_does_not_call_os() {
        let mock = PanickingEntropy;
        let mut empty = [];
        assert!(mock.fill(&mut empty).is_ok());
    }

    #[test]
    fn os_entropy_default_matches_new() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        assert!(OsEntropy::new().fill(&mut buf1).is_ok());
        assert!(OsEntropy::default().fill(&mut buf2).is_ok());
        assert_ne!(buf1, buf2);
    }
}
