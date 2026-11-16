//! The vault: store, manage, protect and display secrets (T-0004, blueprint `docs/F5_VAULT_BLUEPRINT.md`).
//!
//! # Layout
//!
//! * [`format`] — the file format, framing and bounds checking. **Pure**: no I/O, no cryptography.
//! * `crypto` — key derivation and AEAD (added next).
//! * `store` — the atomic write sequence (added after that).
//!
//! Each layer is added with its own tests before the next is started, so a defect is attributed to the layer
//! that caused it rather than to "the vault".

pub mod format;
