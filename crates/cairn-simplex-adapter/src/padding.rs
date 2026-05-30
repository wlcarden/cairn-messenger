// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Size-bin padding per D0026 §4.
//!
//! ## Bucket policy
//!
//! Cairn message envelopes pad to one of these byte buckets BEFORE
//! SMP wrapping:
//!
//! ```text
//! 256, 1024, 4096, 16384, 65536
//! ```
//!
//! A payload of N bytes pads to the smallest bucket ≥ N. Payloads
//! exceeding 65536 bytes transmit at their natural size with no
//! padding (the outlier-defeats-bucket case is documented per D0026
//! §4.1).
//!
//! ## Why before SMP wrapping
//!
//! Per D0026 §4.2: padding occurs at the Cairn envelope level so the
//! double-ratchet sees a padded plaintext. The wire ciphertext leak
//! visible to SMP servers carries only the bucket size, not the
//! true message size. Padding after SMP wrapping would let the
//! unpadded ciphertext size leak through the ratchet — defeating
//! the purpose.
//!
//! ## What this does not defend against
//!
//! Per D0026 §4.3: a traffic-analysis-capable adversary at the
//! global passive level can correlate timing of messages across
//! queues. Per-message size is one input, not the only one. The
//! buckets defend against per-message fingerprinting; they do NOT
//! defend against traffic-flow analysis (which falls under the Tor
//! threat model per design brief §3.3).

/// Power-of-2 size-bin buckets per D0026 §4.1.
///
/// The buckets MUST stay sorted ascending; [`select_bucket`] relies
/// on that ordering to find the smallest bucket ≥ payload length.
pub const SIZE_BUCKETS: &[usize] = &[256, 1024, 4096, 16384, 65536];

/// The largest bucket; payloads exceeding this transmit at natural
/// size per D0026 §4.1.
pub const LARGEST_BUCKET: usize = 65536;

/// Select the smallest bucket ≥ `payload_len`.
///
/// Returns `None` if `payload_len > LARGEST_BUCKET` — the caller
/// treats that as "transmit at natural size, no padding" per D0026
/// §4.1's outlier-defeats-bucket disclosure.
#[must_use]
pub fn select_bucket(payload_len: usize) -> Option<usize> {
    SIZE_BUCKETS
        .iter()
        .copied()
        .find(|&bucket| bucket >= payload_len)
}

/// Compute the number of random padding bytes required to reach the
/// configured bucket from `payload_len`.
///
/// Returns `0` for payloads larger than [`LARGEST_BUCKET`] (no
/// padding; the natural size leaks per D0026 §4.1's documented
/// outlier case).
#[must_use]
pub fn padding_bytes_required(payload_len: usize) -> usize {
    select_bucket(payload_len).map_or(0, |bucket| bucket.saturating_sub(payload_len))
}

/// Generate a fresh padding byte buffer per D0026 §4.1 + D0018 §1.7.
///
/// Uses workspace `getrandom` for the random source — same CSPRNG
/// the rest of the workspace uses for nonces + key material.
///
/// # Errors
///
/// Propagates any [`getrandom::Error`] from the CSPRNG (extremely
/// unusual; surfaces only on the rare platform CSPRNG failures
/// `getrandom` documents).
pub fn generate_padding(padding_len: usize) -> Result<Vec<u8>, getrandom::Error> {
    let mut buf = vec![0u8; padding_len];
    if padding_len > 0 {
        getrandom::getrandom(&mut buf)?;
    }
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn select_bucket_returns_256_for_tiny_payloads() {
        assert_eq!(select_bucket(0), Some(256));
        assert_eq!(select_bucket(1), Some(256));
        assert_eq!(select_bucket(100), Some(256));
        assert_eq!(select_bucket(256), Some(256));
    }

    #[test]
    fn select_bucket_returns_1024_for_257_to_1024() {
        assert_eq!(select_bucket(257), Some(1024));
        assert_eq!(select_bucket(500), Some(1024));
        assert_eq!(select_bucket(1024), Some(1024));
    }

    #[test]
    fn select_bucket_returns_4096_for_1025_to_4096() {
        assert_eq!(select_bucket(1025), Some(4096));
        assert_eq!(select_bucket(3000), Some(4096));
        assert_eq!(select_bucket(4096), Some(4096));
    }

    #[test]
    fn select_bucket_returns_16384_for_4097_to_16384() {
        assert_eq!(select_bucket(4097), Some(16384));
        assert_eq!(select_bucket(10_000), Some(16384));
        assert_eq!(select_bucket(16_384), Some(16384));
    }

    #[test]
    fn select_bucket_returns_65536_for_16385_to_65536() {
        assert_eq!(select_bucket(16_385), Some(65536));
        assert_eq!(select_bucket(50_000), Some(65536));
        assert_eq!(select_bucket(65_536), Some(65536));
    }

    #[test]
    fn select_bucket_returns_none_for_oversize_payloads() {
        // D0026 §4.1's documented outlier case: payloads >
        // LARGEST_BUCKET transmit at natural size with no padding.
        assert_eq!(select_bucket(65_537), None);
        assert_eq!(select_bucket(100_000), None);
        assert_eq!(select_bucket(1_000_000), None);
    }

    #[test]
    fn padding_bytes_required_for_each_bucket_boundary() {
        // Exactly-at-bucket payloads need 0 padding.
        assert_eq!(padding_bytes_required(256), 0);
        assert_eq!(padding_bytes_required(1024), 0);
        assert_eq!(padding_bytes_required(4096), 0);
        assert_eq!(padding_bytes_required(16_384), 0);
        assert_eq!(padding_bytes_required(65_536), 0);
    }

    #[test]
    fn padding_bytes_required_reaches_bucket_from_below() {
        assert_eq!(padding_bytes_required(0), 256);
        assert_eq!(padding_bytes_required(100), 256 - 100);
        assert_eq!(padding_bytes_required(257), 1024 - 257);
        assert_eq!(padding_bytes_required(4097), 16384 - 4097);
    }

    #[test]
    fn padding_bytes_required_is_zero_for_oversize() {
        // Outlier payloads do not pad per §4.1.
        assert_eq!(padding_bytes_required(70_000), 0);
        assert_eq!(padding_bytes_required(1_000_000), 0);
    }

    #[test]
    fn generate_padding_produces_requested_length() {
        for len in [0usize, 1, 256, 1024, 65_536] {
            let buf = generate_padding(len).unwrap();
            assert_eq!(buf.len(), len, "padding length must equal requested");
        }
    }

    #[test]
    fn generate_padding_is_nondeterministic() {
        // Two calls with non-trivial length produce different bytes
        // (with overwhelming probability). Pins the CSPRNG path.
        let a = generate_padding(256).unwrap();
        let b = generate_padding(256).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn generate_padding_zero_length_is_empty() {
        let buf = generate_padding(0).unwrap();
        assert!(buf.is_empty());
    }
}
