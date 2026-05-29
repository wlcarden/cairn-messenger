// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Error types for `cairn-crypto`.
//!
//! Per D0018 §4.2 discipline: error variants carry indices, lengths, and
//! type tags only — never `Vec<u8>` or `&[u8]` payloads. This prevents
//! secret-leak vectors through error-propagation logging.
//!
//! Each error type is `#[derive(thiserror::Error, Debug)]` for compatibility
//! with the workspace error-handling discipline.

use thiserror::Error;

/// Top-level error type re-exported from the crate root.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// Wraps a signing operation failure.
    #[error("sign: {0}")]
    Sign(#[from] SignError),
    /// Wraps a verification operation failure.
    #[error("verify: {0}")]
    Verify(#[from] VerifyError),
    /// Wraps a key-agreement failure.
    #[error("agree: {0}")]
    Agree(#[from] AgreeError),
    /// Wraps an HKDF derivation failure.
    #[error("hkdf: {0}")]
    Hkdf(#[from] HkdfError),
    /// Wraps an AEAD encryption or decryption failure.
    #[error("aead: {0}")]
    Aead(#[from] AeadError),
    /// CSPRNG failure (typically OS entropy source unavailable).
    #[error("CSPRNG failure")]
    Rng,
}

/// Errors from Ed25519 signing operations.
///
/// Variants carry no byte payloads — only metadata (lengths, type tags).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SignError {
    /// The payload is too large to sign.
    ///
    /// Ed25519's signing operation hashes the payload internally and has no
    /// inherent payload-size limit at the protocol level, but Cairn imposes a
    /// hard limit at the application layer to bound resource use.
    #[error("payload too large: {got_bytes} bytes (max {max_bytes})")]
    PayloadTooLarge {
        /// Number of bytes in the payload.
        got_bytes: usize,
        /// Cairn's hard limit per the application layer.
        max_bytes: usize,
    },
}

/// Errors from X25519 key-agreement operations.
///
/// All variants carry no byte payloads — only metadata.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AgreeError {
    /// The X25519 key agreement was non-contributory.
    ///
    /// Per D0018 §1.2 discipline and the vodozemac 2026 audit finding, every
    /// X25519 ECDH must call `was_contributory()` on the resulting shared
    /// secret and reject the agreement if the check returns `false`. A
    /// non-contributory result indicates the peer's public key was in the
    /// curve's small subgroup, producing a zero shared secret. This is
    /// either a malformed key or a deliberate small-subgroup attack.
    #[error("X25519 key agreement was non-contributory (peer key in small subgroup)")]
    NonContributory,
}

/// Errors from HKDF-SHA256 derivation operations.
///
/// All variants carry no byte payloads — only metadata (requested length,
/// max length).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HkdfError {
    /// The requested output keying material length exceeds the HKDF
    /// per-PRK ceiling.
    ///
    /// Per RFC 5869 §2.3, the maximum OKM length is `255 * HashLen`. For
    /// HKDF-SHA256 this is `255 * 32 = 8160` bytes. Callers requesting more
    /// must run a second extract-then-expand or use a chained scheme.
    #[error("HKDF output too long: {got_bytes} bytes (max {max_bytes})")]
    OutputTooLong {
        /// Number of bytes the caller requested.
        got_bytes: usize,
        /// Per-PRK ceiling for HKDF-SHA256 expansion.
        max_bytes: usize,
    },
}

/// Errors from `XChaCha20`-`Poly1305` AEAD operations.
///
/// Decryption returns a uniform `DecryptFailed` for any failure mode
/// (truncated ciphertext, wrong tag, wrong key, wrong nonce, wrong AAD).
/// Per D0006 / D0018 §1.4, decryption failure modes must NOT be
/// distinguishable to a caller — distinguishability constitutes an error
/// oracle exploitable by an active adversary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AeadError {
    /// The plaintext exceeds the `XChaCha20` per-encryption ceiling.
    ///
    /// Single-encryption plaintext is bounded by `ChaCha20`'s
    /// `(2^32 - 1)`-block keystream. The `aead` module exposes
    /// `MAX_PLAINTEXT_LEN` for reference.
    #[error("AEAD payload too large: {got_bytes} bytes (max {max_bytes})")]
    PayloadTooLarge {
        /// Plaintext length submitted to encrypt.
        got_bytes: usize,
        /// Per-encryption ceiling for `XChaCha20`-`Poly1305`.
        max_bytes: usize,
    },
    /// Decryption failed. Uniform across all failure modes (truncation,
    /// wrong tag, wrong key, wrong nonce, wrong AAD).
    #[error("AEAD decryption failed")]
    DecryptFailed,
    /// Encrypt-side internal failure from the underlying AEAD primitive.
    ///
    /// Practically unreachable: `XChaCha20`-`Poly1305` encryption does not
    /// fail for any well-formed input that passes the size check. This
    /// variant exists to satisfy the `Result` type from the underlying
    /// `Aead` trait without resorting to `unwrap`.
    #[error("AEAD internal encrypt failure")]
    InternalEncrypt,
}

/// Errors from Ed25519 verification operations.
///
/// All verification failures are uniformly an opaque `Invalid` variant. This
/// matches the cryptographic discipline that signature-verification failure
/// modes must not be observably distinguishable to a caller (no error oracle).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// The signature did not verify against the public key.
    ///
    /// This variant deliberately carries no further information about why
    /// verification failed. Per D0006, signature verification failures must not
    /// be distinguishable by error type (no malformed-signature vs
    /// invalid-signature distinction).
    #[error("signature verification failed")]
    Invalid,
}
