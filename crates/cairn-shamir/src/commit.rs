// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! BLAKE3 commit-of-secret for Shamir reconstruction integrity.
//!
//! Each Shamir [`crate::share::Share`] is accompanied by a
//! [`Commitment`] — a 32-byte BLAKE3-derived digest of the original
//! secret. At reconstruction time, the candidate secret reconstructed
//! from the shares is re-committed and compared against the stored
//! commitment in constant time. Any mismatch causes the reconstruction
//! to be rejected per D0018 §3.4.
//!
//! ## Why BLAKE3 `derive_key` mode
//!
//! BLAKE3's `derive_key` mode is purpose-designed for context-separated
//! key derivation: the context string is mixed into the hash state via
//! a fixed-position key-derivation domain tag, and the output is
//! cryptographically separated from `hash()` and `keyed_hash()` outputs
//! on the same input bytes.
//!
//! For a commit-of-secret, `derive_key` is structurally appropriate:
//!
//! - **Domain separation**: the context string [`COMMIT_CONTEXT`]
//!   ensures no other BLAKE3 invocation in Cairn (or the wider
//!   ecosystem) can collide with this commitment.
//! - **Constant time**: BLAKE3 itself runs in constant time across the
//!   secret-bearing input bytes.
//! - **Pre-image resistance**: with the secret being 256 bits of
//!   entropy and the output being 256 bits, brute-forcing a matching
//!   secret from the commitment alone is infeasible.
//!
//! ## What `Commitment` does NOT provide
//!
//! - **Hiding from offline-search**: the commitment binds to a specific
//!   secret; an adversary who guesses the secret can verify the guess
//!   against the commitment. Cairn's recovery model assumes the
//!   secret-bearing space is large enough (256 bits) that brute force
//!   is infeasible — but a low-entropy "secret" (e.g., a 4-digit PIN)
//!   would be brute-forceable against a published commitment. The
//!   Shamir layer assumes its input is high-entropy keying material.
//! - **Repudiation of malicious peers**: the commitment detects that
//!   reconstruction failed; it does NOT identify which share(s) were
//!   wrong. Cairn's trust-graph layer surfaces that attribution
//!   separately (D0006 §6).
//!
//! ## Constant-time comparison discipline
//!
//! [`Commitment::ct_eq`] uses `subtle::ConstantTimeEq` rather than
//! `PartialEq`. The `PartialEq` impl uses constant-time comparison
//! internally; do NOT rely on `==` collapsing into early-out byte
//! comparison.

use subtle::ConstantTimeEq;

/// Domain-separation context for the Shamir commit-of-secret per
/// BLAKE3's `derive_key` mode. Versioned (`v1`) to allow future revisions
/// to coexist with stored shares from earlier versions.
pub const COMMIT_CONTEXT: &str = "Cairn Shamir commit-of-secret v1";

/// Length of a [`Commitment`] in bytes (= BLAKE3 output length).
pub const COMMITMENT_LEN: usize = 32;

/// A BLAKE3-derived commitment of a Shamir secret.
///
/// Constructed via [`Self::for_secret`]. Compared via [`Self::ct_eq`]
/// or the `==` operator (which uses constant-time comparison
/// internally).
#[derive(Clone, Copy)]
pub struct Commitment {
    bytes: [u8; COMMITMENT_LEN],
}

impl Commitment {
    /// Compute the commitment for `secret_bytes` using BLAKE3
    /// `derive_key` mode with the context [`COMMIT_CONTEXT`].
    #[must_use]
    pub fn for_secret(secret_bytes: &[u8]) -> Self {
        let bytes = blake3::derive_key(COMMIT_CONTEXT, secret_bytes);
        Self { bytes }
    }

    /// Construct from raw commitment bytes (e.g., loaded from storage).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; COMMITMENT_LEN]) -> Self {
        Self { bytes }
    }

    /// Return the raw commitment bytes for storage / transmission.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; COMMITMENT_LEN] {
        self.bytes
    }

    /// Constant-time comparison of two commitments.
    ///
    /// Preferred over `==` in security-sensitive paths even though the
    /// `PartialEq` impl is also constant-time — making the discipline
    /// explicit at the call site documents the security requirement.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl PartialEq for Commitment {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for Commitment {}

impl core::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ShamirCommitment({:02x}{:02x}{:02x}{:02x}…)",
            self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism_same_secret_same_commitment() {
        let secret = b"a 32-byte secret string ----- ok";
        let a = Commitment::for_secret(secret);
        let b = Commitment::for_secret(secret);
        assert!(a.ct_eq(&b));
        assert_eq!(a, b);
    }

    #[test]
    fn different_secrets_different_commitments() {
        let a = Commitment::for_secret(b"secret one");
        let b = Commitment::for_secret(b"secret two");
        assert!(!a.ct_eq(&b));
        assert_ne!(a, b);
    }

    #[test]
    fn empty_secret_commits_distinctly() {
        // An empty input still produces a commitment (the BLAKE3
        // derive_key chain runs on zero bytes). The result is distinct
        // from the commit of any non-empty input.
        let empty = Commitment::for_secret(b"");
        let non_empty = Commitment::for_secret(b"x");
        assert!(!empty.ct_eq(&non_empty));
    }

    #[test]
    fn from_bytes_round_trip() {
        let original = Commitment::for_secret(b"round trip");
        let bytes = original.to_bytes();
        let reconstructed = Commitment::from_bytes(bytes);
        assert!(original.ct_eq(&reconstructed));
    }

    #[test]
    fn debug_redacts_most_bytes() {
        let c = Commitment::for_secret(b"check debug format");
        let debug_str = format!("{c:?}");
        // Only the first 4 bytes appear in the Debug output; the rest
        // are redacted with an ellipsis.
        assert!(debug_str.starts_with("ShamirCommitment("));
        assert!(debug_str.contains('…'));
    }

    /// Cross-check against an externally-computed BLAKE3 `derive_key`
    /// output. The known-answer is computed via `blake3::derive_key`
    /// directly (independent of our `Commitment::for_secret` path),
    /// guarding against accidental refactor regressions.
    #[test]
    fn matches_blake3_derive_key_directly() {
        let secret = b"reference secret bytes ------- ok";
        let ours = Commitment::for_secret(secret);
        let theirs = blake3::derive_key(COMMIT_CONTEXT, secret);
        assert_eq!(ours.to_bytes(), theirs);
    }
}
