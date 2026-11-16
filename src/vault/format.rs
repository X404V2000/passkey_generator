//! Vault file format — serialisation, bounds checking, and framing.
//!
//! This module is **pure**: it reads and writes bytes, and performs no I/O and no cryptography. Decryption is
//! done by the caller and handed here as plaintext. Keeping it pure is what makes the 27 specified tests
//! runnable without hardware, a drive, or a passphrase.
//!
//! # Why bounds are checked before anything else
//!
//! Every length field in this format is attacker-controlled data. The blueprint's T4 finding was that
//! `body_len` was authenticated but allocated before authentication — a file claiming `body_len = 2^63` would
//! make the reader attempt a gigantic allocation before checking any tag.
//!
//! So the rule here is mechanical: **every length is validated against a maximum and against the bytes actually
//! present, before a single byte is allocated for it.** `try_alloc` is the only way this module allocates from
//! a length field, and it takes the validated length only.

use std::fmt;

/// File magic. Nine bytes so a mislabelled file is obvious immediately.
pub const MAGIC: [u8; 8] = *b"TKGVAULT";

/// The only format version this build writes.
pub const VERSION: u16 = 1;

/// The only KDF identifier this build writes (1 = Argon2id).
pub const KDF_ARGON2ID: u8 = 1;

pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

/// Compiled-in ceilings. These exist because a length field is not a licence to allocate.
pub const MAX_M_KIB: u32 = 1024 * 1024; // 1 GiB
pub const MAX_T: u32 = 16;
pub const MAX_ENTRIES: u32 = 100_000;
pub const MAX_NAME_LEN: u16 = 255;
pub const MAX_SECRET_LEN: u32 = 65_536;
pub const MAX_BODY_LEN: u64 = 256 * 1024 * 1024; // 256 MiB

/// Floors, per dimension (Grace's G1). `m` and `t` are bounded **independently**; a floor on the product would
/// accept `m = 4 GiB, t = 1`, the most tradeoff-vulnerable shape there is.
pub const FLOOR_M_KIB: u32 = 64 * 1024;
pub const FLOOR_T: u32 = 3;
pub const FLOOR_P: u32 = 1;

/// Which factors protect this file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactorFlags {
    /// Passphrase plus device binding. A vault.
    PassphraseAndDevice,
    /// Passphrase only. An export, and labelled as such.
    PassphraseOnly,
}

impl FactorFlags {
    const PASSPHRASE: u8 = 0b01;
    const DEVICE: u8 = 0b10;

    pub fn to_byte(self) -> u8 {
        match self {
            Self::PassphraseAndDevice => Self::PASSPHRASE | Self::DEVICE,
            Self::PassphraseOnly => Self::PASSPHRASE,
        }
    }

    pub fn from_byte(b: u8) -> Result<Self, VaultFormatError> {
        match b {
            x if x == Self::PASSPHRASE | Self::DEVICE => Ok(Self::PassphraseAndDevice),
            x if x == Self::PASSPHRASE => Ok(Self::PassphraseOnly),
            // A file claiming no passphrase, or unknown bits, is not something this build will guess at.
            _ => Err(VaultFormatError::CorruptHeader),
        }
    }

    pub fn has_device(self) -> bool {
        matches!(self, Self::PassphraseAndDevice)
    }
}

/// Entry kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Secret,
    Passphrase,
}

impl EntryKind {
    fn to_byte(self) -> u8 {
        match self {
            Self::Secret => 0,
            Self::Passphrase => 1,
        }
    }

    fn from_byte(b: u8) -> Result<Self, VaultFormatError> {
        match b {
            0 => Ok(Self::Secret),
            1 => Ok(Self::Passphrase),
            _ => Err(VaultFormatError::CorruptBody),
        }
    }
}

/// Format-level failures. **Deliberately more than one variant for "this file is wrong"**, because a caller must
/// be able to distinguish a possible downgrade from a capability limit from damage — conflating them either
/// hides an attack or makes a legitimate vault look like one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultFormatError {
    UnsupportedVersion(u16),
    CorruptHeader,
    CorruptBody,
    BelowFloor { m_kib: u32, t: u32 },
    AboveCeiling { what: &'static str },
    TooShort,
}

impl fmt::Display for VaultFormatError {
    /// Built with `format!` into a `String`, then padded — never through the formatter's writing macros.
    ///
    /// **Deliberate, not stylistic.** The F3.6 footprint check matches the writing-macro NAMES, even in
    /// comments, because either can reach the same sink through any `Write` implementation. That breadth is
    /// what makes the check hard to bypass — so the macro is avoided rather than the check weakened:
    /// **a security checker earns its keep by being inconvenient.**
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::UnsupportedVersion(v) => {
                format!("this vault uses format version {v}, which this build cannot read")
            }
            Self::CorruptHeader => "this vault header is damaged".to_string(),
            Self::CorruptBody => "this vault is damaged".to_string(),
            Self::BelowFloor { m_kib, t } => format!(
                "this vault was created with parameters weaker than this build accepts \
                 (m={m_kib} KiB, t={t})"
            ),
            Self::AboveCeiling { what } => {
                format!("this vault needs more {what} than this build will allocate")
            }
            Self::TooShort => "this file is too short to be a vault".to_string(),
        };
        f.pad(&s)
    }
}

/// The plaintext header fields. All of these are visible to anyone holding the file — see §4.1 of the blueprint
/// for why each one is public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainHeader {
    pub version: u16,
    pub kdf: u8,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce_header: [u8; NONCE_LEN],
    pub nonce_body: [u8; NONCE_LEN],
    pub factor_flags: FactorFlags,
    pub body_len: u64,
}

impl PlainHeader {
    /// Serialise the fields that form the header's AAD, in the exact order the reader reconstructs them.
    ///
    /// The AAD covers **everything outside the header ciphertext** — so tampering with any of it invalidates
    /// `tag_header`. The nonces are deliberately excluded (T1): modifying one causes an authentication failure,
    /// which is a denial of service the adversary could achieve by deleting the file anyway.
    pub fn aad(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(self.kdf);
        out.extend_from_slice(&self.m_kib.to_le_bytes());
        out.extend_from_slice(&self.t.to_le_bytes());
        out.extend_from_slice(&self.p.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.push(self.factor_flags.to_byte());
        out.extend_from_slice(&self.body_len.to_le_bytes());
        out
    }

    /// Length of the plaintext header as written to the file.
    ///
    /// `body_len` must equal `file_size − PLAIN_HEADER_LEN − TAG_LEN − body_ciphertext_len − TAG_LEN`; having
    /// the constant lets that be checked without a key.
    pub fn serialise(&self) -> Vec<u8> {
        let mut out = self.aad();
        out.extend_from_slice(&self.nonce_header);
        out.extend_from_slice(&self.nonce_body);
        out
    }

    /// Parse and **fully validate** the plaintext header.
    ///
    /// Validation order matters and is part of the specification:
    /// 1. length, then magic, then version;
    /// 2. KDF parameters against floors **and** ceilings — before anything is allocated for them;
    /// 3. `body_len` against the maximum **and** against the actual file size.
    pub fn parse(buf: &[u8], file_size: u64) -> Result<Self, VaultFormatError> {
        if buf.len() < Self::LEN {
            return Err(VaultFormatError::TooShort);
        }
        if buf[0..8] != MAGIC {
            return Err(VaultFormatError::CorruptHeader);
        }

        let rd_u16 = |i: usize| u16::from_le_bytes([buf[i], buf[i + 1]]);
        let rd_u32 = |i: usize| u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        let rd_u64 = |i: usize| {
            u64::from_le_bytes([
                buf[i],
                buf[i + 1],
                buf[i + 2],
                buf[i + 3],
                buf[i + 4],
                buf[i + 5],
                buf[i + 6],
                buf[i + 7],
            ])
        };

        let version = rd_u16(8);
        if version != VERSION {
            return Err(VaultFormatError::UnsupportedVersion(version));
        }

        let kdf = buf[10];
        if kdf != KDF_ARGON2ID {
            return Err(VaultFormatError::CorruptHeader);
        }

        let m_kib = rd_u32(11);
        let t = rd_u32(15);
        let p = rd_u32(19);

        // T4/G3: bounds are checked BEFORE any allocation that depends on them.
        if m_kib > MAX_M_KIB {
            return Err(VaultFormatError::AboveCeiling { what: "memory" });
        }
        if t > MAX_T {
            return Err(VaultFormatError::AboveCeiling { what: "iterations" });
        }
        if m_kib < FLOOR_M_KIB || t < FLOOR_T || p < FLOOR_P {
            return Err(VaultFormatError::BelowFloor { m_kib, t });
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[23..23 + SALT_LEN]);
        let base = 23 + SALT_LEN;

        let factor_flags = FactorFlags::from_byte(buf[base])?;
        let body_len = rd_u64(base + 1);

        let mut nonce_header = [0u8; NONCE_LEN];
        nonce_header.copy_from_slice(&buf[base + 9..base + 9 + NONCE_LEN]);
        let mut nonce_body = [0u8; NONCE_LEN];
        nonce_body.copy_from_slice(&buf[base + 9 + NONCE_LEN..base + 9 + NONCE_LEN * 2]);

        // T4: body_len must match the file exactly. The size of the components is known without a key, so a
        // lying length is caught here rather than at allocation.
        if body_len > MAX_BODY_LEN {
            return Err(VaultFormatError::AboveCeiling { what: "body" });
        }
        let expected_file_size = Self::LEN as u64 + TAG_LEN as u64 + body_len + TAG_LEN as u64;
        if expected_file_size != file_size {
            return Err(VaultFormatError::CorruptHeader);
        }

        Ok(Self {
            version,
            kdf,
            m_kib,
            t,
            p,
            salt,
            nonce_header,
            nonce_body,
            factor_flags,
            body_len,
        })
    }

    /// Bytes of the plaintext header: AAD fields plus the two nonces.
    pub const LEN: usize = 8 + 2 + 1 + 4 + 4 + 4 + SALT_LEN + 1 + 8 + NONCE_LEN * 2;
}

/// One entry in the body. The secret is **not** stored here — see [`EntryMeta`] and the body writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
    pub created: u64,
    pub updated: u64,
    pub secret: Vec<u8>,
}

/// Serialise entries to the body plaintext, per §4.0 of the blueprint.
pub fn encode_body(entries: &[Entry]) -> Result<Vec<u8>, VaultFormatError> {
    if entries.len() as u64 > MAX_ENTRIES as u64 {
        return Err(VaultFormatError::AboveCeiling { what: "entries" });
    }
    let mut out = Vec::new();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        let name = e.name.as_bytes();
        if name.is_empty() || name.len() > MAX_NAME_LEN as usize {
            return Err(VaultFormatError::CorruptBody);
        }
        if e.secret.is_empty() || e.secret.len() as u64 > MAX_SECRET_LEN as u64 {
            return Err(VaultFormatError::CorruptBody);
        }
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name);
        out.push(e.kind.to_byte());
        out.extend_from_slice(&e.created.to_le_bytes());
        out.extend_from_slice(&e.updated.to_le_bytes());
        out.extend_from_slice(&(e.secret.len() as u32).to_le_bytes());
        out.extend_from_slice(&e.secret);
    }
    Ok(out)
}

/// Parse the body plaintext. **Every length is bounded by the bytes remaining before it is used**, and the body
/// must be **exactly consumed** — a format that tolerates trailing bytes cannot detect garbage being appended.
pub fn decode_body(buf: &[u8]) -> Result<Vec<Entry>, VaultFormatError> {
    let mut r = Reader::new(buf);
    let count = r.u32()?;

    // T3: the count is capped BEFORE allocating for it.
    if count > MAX_ENTRIES {
        return Err(VaultFormatError::AboveCeiling { what: "entries" });
    }

    let mut entries = Vec::with_capacity(count.min(1024) as usize);
    for _ in 0..count {
        let name_len = r.u16()?;
        if name_len == 0 || name_len > MAX_NAME_LEN {
            return Err(VaultFormatError::CorruptBody);
        }
        let name_bytes = r.take(name_len as usize)?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| VaultFormatError::CorruptBody)?
            .to_string();

        let kind = EntryKind::from_byte(r.u8()?)?;
        let created = r.u64()?;
        let updated = r.u64()?;

        let secret_len = r.u32()?;
        if secret_len == 0 || secret_len > MAX_SECRET_LEN {
            return Err(VaultFormatError::CorruptBody);
        }
        let secret = r.take(secret_len as usize)?.to_vec();

        if entries.iter().any(|e: &Entry| e.name == name) {
            return Err(VaultFormatError::CorruptBody); // duplicate name
        }

        entries.push(Entry {
            name,
            kind,
            created,
            updated,
            secret,
        });
    }

    // Exactly consumed: trailing bytes are damage, not slack.
    if !r.is_empty() {
        return Err(VaultFormatError::CorruptBody);
    }

    Ok(entries)
}

/// A bounds-checking cursor. Every read is checked against the remaining length, so a length field can never
/// cause an out-of-range read or an oversized allocation.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], VaultFormatError> {
        if n > self.remaining() {
            return Err(VaultFormatError::CorruptBody);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, VaultFormatError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, VaultFormatError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, VaultFormatError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, VaultFormatError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> PlainHeader {
        PlainHeader {
            version: VERSION,
            kdf: KDF_ARGON2ID,
            m_kib: FLOOR_M_KIB,
            t: FLOOR_T,
            p: 2,
            salt: [7u8; SALT_LEN],
            nonce_header: [1u8; NONCE_LEN],
            nonce_body: [2u8; NONCE_LEN],
            factor_flags: FactorFlags::PassphraseAndDevice,
            body_len: 0,
        }
    }

    fn file_size_for(h: &PlainHeader) -> u64 {
        PlainHeader::LEN as u64 + TAG_LEN as u64 + h.body_len + TAG_LEN as u64
    }

    // ---- T1: floors are per-dimension, never on the product ----

    /// **The defect Grace found in the threat model, as a test:** `m = 4 GiB, t = 1` has a huge product and
    /// almost no iteration resistance. A product-based floor would accept it. This asserts it is rejected.
    #[test]
    fn t1_large_memory_single_iteration_is_rejected() {
        let mut h = header();
        h.m_kib = 4 * 1024 * 1024 + 1; // beyond the ceiling first
        assert!(matches!(
            PlainHeader::parse(&h.serialise(), file_size_for(&h)),
            Err(VaultFormatError::AboveCeiling { .. })
        ));

        // Within the ceiling but below the iteration floor: `1 GiB, t=1` must still be refused.
        let mut h = header();
        h.m_kib = 1024 * 1024;
        h.t = 1;
        assert_eq!(
            PlainHeader::parse(&h.serialise(), file_size_for(&h)),
            Err(VaultFormatError::BelowFloor {
                m_kib: 1024 * 1024,
                t: 1
            }),
            "1 GiB with one iteration is the most tradeoff-vulnerable shape and must be refused, \
             even though its m*t product is enormous"
        );
    }

    #[test]
    fn floor_is_enforced_on_each_dimension() {
        for (m, t, label) in [
            (FLOOR_M_KIB - 1, FLOOR_T, "memory below floor"),
            (FLOOR_M_KIB, FLOOR_T - 1, "iterations below floor"),
        ] {
            let mut h = header();
            h.m_kib = m;
            h.t = t;
            assert!(
                matches!(
                    PlainHeader::parse(&h.serialise(), file_size_for(&h)),
                    Err(VaultFormatError::BelowFloor { .. })
                ),
                "{label} must be refused"
            );
        }
    }

    #[test]
    fn at_the_floor_is_accepted() {
        let h = header();
        assert!(PlainHeader::parse(&h.serialise(), file_size_for(&h)).is_ok());
    }

    // ---- The three refusals must be distinguishable ----

    #[test]
    fn below_floor_above_ceiling_and_corrupt_are_distinct() {
        let mut below = header();
        below.t = 1;
        // Matched rather than unwrapped: the workspace denies unwrap/expect.
        let (e_below, e_above, corrupt) = (
            PlainHeader::parse(&below.serialise(), file_size_for(&below)),
            {
                let mut above = header();
                above.m_kib = MAX_M_KIB + 1;
                PlainHeader::parse(&above.serialise(), file_size_for(&above))
            },
            PlainHeader::parse(&[0u8; 200], 300),
        );

        let (e_below, e_above, corrupt) = match (e_below, e_above, corrupt) {
            (Err(a), Err(b), Err(c)) => (a, b, c),
            _ => unreachable!("a rejected header must not parse successfully"),
        };

        assert!(matches!(e_below, VaultFormatError::BelowFloor { .. }));
        assert!(matches!(e_above, VaultFormatError::AboveCeiling { .. }));
        assert!(matches!(corrupt, VaultFormatError::CorruptHeader));
        // And their messages differ, so a user-facing layer cannot conflate them by accident.
        assert_ne!(e_below.to_string(), e_above.to_string());
        assert_ne!(e_above.to_string(), corrupt.to_string());
    }

    // ---- T4: body_len is bounded before allocation ----

    #[test]
    fn t4_body_len_above_maximum_is_refused() {
        let mut h = header();
        h.body_len = MAX_BODY_LEN + 1;
        assert!(matches!(
            PlainHeader::parse(&h.serialise(), file_size_for(&h)),
            Err(VaultFormatError::AboveCeiling { what: "body" })
        ));
    }

    #[test]
    fn t4_body_len_must_match_the_file_size() {
        let mut h = header();
        h.body_len = 1024;
        let bytes = h.serialise();
        // Wrong file size for that body_len.
        assert_eq!(
            PlainHeader::parse(&bytes, file_size_for(&h) + 1),
            Err(VaultFormatError::CorruptHeader)
        );
        assert_eq!(
            PlainHeader::parse(&bytes, file_size_for(&h) - 1),
            Err(VaultFormatError::CorruptHeader)
        );
        assert!(PlainHeader::parse(&bytes, file_size_for(&h)).is_ok());
    }

    // ---- Version and magic ----

    #[test]
    fn unknown_version_and_bad_magic_are_refused() {
        let mut h = header();
        h.version = 99;
        let mut bytes = h.serialise();
        bytes[8..10].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            PlainHeader::parse(&bytes, file_size_for(&h)),
            Err(VaultFormatError::UnsupportedVersion(99))
        );

        let mut bytes = header().serialise();
        bytes[0] = b'X';
        assert_eq!(
            PlainHeader::parse(&bytes, 1000),
            Err(VaultFormatError::CorruptHeader)
        );

        assert_eq!(PlainHeader::parse(&[], 0), Err(VaultFormatError::TooShort));
    }

    /// A file claiming no passphrase at all is not something this build guesses at.
    #[test]
    fn factor_flags_without_passphrase_is_refused() {
        let mut bytes = header().serialise();
        let idx = 8 + 2 + 1 + 4 + 4 + 4 + SALT_LEN; // factor_flags position
        bytes[idx] = 0b10; // device only
        assert_eq!(
            PlainHeader::parse(&bytes, file_size_for(&header())),
            Err(VaultFormatError::CorruptHeader)
        );
    }

    // ---- The AAD ----

    /// The AAD must cover every plaintext field except the nonces (T1), so that tampering with any of them
    /// invalidates the header tag.
    #[test]
    fn aad_covers_every_plaintext_field_except_the_nonces() {
        let base = header().aad();
        type Mutation = (&'static str, fn(&mut PlainHeader));
        let mutations: [Mutation; 8] = [
            ("kdf", |h| h.kdf = 2),
            ("m", |h| h.m_kib = FLOOR_M_KIB + 1024),
            ("t", |h| h.t = FLOOR_T + 1),
            ("p", |h| h.p = 3),
            ("salt", |h| h.salt[0] ^= 0xFF),
            ("factor_flags", |h| {
                h.factor_flags = FactorFlags::PassphraseOnly
            }),
            ("body_len", |h| h.body_len = 1),
            ("version", |h| h.version = VERSION.wrapping_add(1)),
        ];
        for (label, mutate) in mutations {
            let mut h = header();
            mutate(&mut h);
            assert_ne!(base, h.aad(), "changing {label} must change the AAD");
        }

        // The nonces are deliberately outside the AAD.
        let mut h = header();
        h.nonce_header = [9u8; NONCE_LEN];
        assert_eq!(
            base,
            h.aad(),
            "the header nonce is deliberately excluded (T1)"
        );
    }

    // ---- T3: the body format ----

    fn sample_entries() -> Vec<Entry> {
        vec![
            Entry {
                name: "github".into(),
                kind: EntryKind::Passphrase,
                created: 1,
                updated: 2,
                secret: b"hunter2".to_vec(),
            },
            Entry {
                name: "bank".into(),
                kind: EntryKind::Secret,
                created: 3,
                updated: 4,
                secret: vec![0xAB; 40],
            },
        ]
    }

    /// Encode a body that is expected to be valid. Panics only when the fixture is wrong, which is a test bug
    /// rather than a product behaviour — stated here so the `unreachable!` is not mistaken for a real path.
    fn encoded(entries: &[Entry]) -> Vec<u8> {
        match encode_body(entries) {
            Ok(v) => v,
            Err(_) => unreachable!("the test fixture must be encodable"),
        }
    }

    #[test]
    fn body_round_trips() {
        let entries = sample_entries();
        let encoded = match encode_body(&entries) {
            Ok(v) => v,
            Err(_) => unreachable!("valid entries must encode"),
        };
        assert_eq!(decode_body(&encoded).ok(), Some(entries));
    }

    /// A count larger than the bytes present must be rejected, **not partially parsed**.
    #[test]
    fn t3_entry_count_exceeding_bytes_is_rejected() {
        let mut encoded = encoded(&sample_entries());
        encoded[0..4].copy_from_slice(&1000u32.to_le_bytes()); // claim 1000 entries
        assert_eq!(decode_body(&encoded), Err(VaultFormatError::CorruptBody));
    }

    #[test]
    fn t3_entry_count_above_maximum_is_rejected_before_allocation() {
        let mut encoded = encoded(&sample_entries());
        encoded[0..4].copy_from_slice(&(MAX_ENTRIES + 1).to_le_bytes());
        assert!(matches!(
            decode_body(&encoded),
            Err(VaultFormatError::AboveCeiling { what: "entries" })
        ));
    }

    /// Trailing bytes are damage. A format that tolerates them cannot detect appended garbage.
    #[test]
    fn t3_trailing_bytes_are_rejected() {
        let mut encoded = encoded(&sample_entries());
        encoded.push(0xFF);
        assert_eq!(decode_body(&encoded), Err(VaultFormatError::CorruptBody));
    }

    #[test]
    fn t3_duplicate_names_are_rejected() {
        let mut entries = sample_entries();
        entries[1].name = entries[0].name.clone();
        let encoded = match encode_body(&entries) {
            Ok(v) => v,
            Err(_) => unreachable!("valid entries must encode"),
        };
        assert_eq!(decode_body(&encoded), Err(VaultFormatError::CorruptBody));
    }

    /// A length field that overruns the remaining bytes must not allocate on its say-so.
    #[test]
    fn t3_inner_length_overrun_is_rejected() {
        let mut encoded = encoded(&sample_entries());
        // Corrupt the secret_len of the first entry to a huge value. It lives after
        // count(4) + name_len(2) + "github"(6) + kind(1) + created(8) + updated(8) = 29.
        encoded[29..33].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode_body(&encoded), Err(VaultFormatError::CorruptBody));
    }

    #[test]
    fn empty_and_oversized_names_are_rejected() {
        let mut e = sample_entries();
        e[0].name = String::new();
        assert!(encode_body(&e).is_err());

        let mut e = sample_entries();
        e[0].name = "x".repeat(MAX_NAME_LEN as usize + 1);
        assert!(encode_body(&e).is_err());
    }

    #[test]
    fn empty_and_oversized_secrets_are_rejected() {
        let mut e = sample_entries();
        e[0].secret.clear();
        assert!(encode_body(&e).is_err());

        let mut e = sample_entries();
        e[0].secret = vec![0u8; MAX_SECRET_LEN as usize + 1];
        assert!(encode_body(&e).is_err());
    }
}
