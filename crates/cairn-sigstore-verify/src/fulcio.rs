// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Fulcio CA trust-root validation per D0024 §2.
//!
//! ## v1 skeleton status
//!
//! The cert-chain validator returns [`SigstoreVerifyError::NetworkUnreached`]
//! pending the x509-parser workspace pin + Fulcio body landing per
//! D0024 §6.5 + §10. When the body lands, the function:
//!
//! 1. Parses the signing certificate from DER bytes.
//! 2. Validates the chain to the pinned Fulcio root per D0024 §2.
//! 3. Checks the cert's `NotBefore` / `NotAfter` window includes
//!    the Rekor-attested signing time.
//! 4. Extracts the OIDC `iss` + `email` claims from the cert's
//!    Subject Alternative Name + custom extensions per Sigstore's
//!    documented schema.
//! 5. Compares the extracted claims against the pinned project
//!    config; surfaces [`SigstoreVerifyError::OidcIssuerMismatch`]
//!    / [`SigstoreVerifyError::OidcEmailMismatch`] on a mismatch.

use crate::error::SigstoreVerifyError;

/// Stub for the Fulcio cert-chain validator per D0024 §2.
///
/// v1 skeleton always returns
/// [`SigstoreVerifyError::NetworkUnreached`].
///
/// # Errors
///
/// - [`SigstoreVerifyError::NetworkUnreached`] (skeleton only;
///   replaced by [`SigstoreVerifyError::FulcioChainInvalid`] /
///   [`SigstoreVerifyError::OidcIssuerMismatch`] /
///   [`SigstoreVerifyError::OidcEmailMismatch`] /
///   [`SigstoreVerifyError::FulcioCertExpiredAtSigningTime`] once
///   the body lands)
#[allow(
    clippy::missing_const_for_fn,
    reason = "stub; the real body will not be const once x509-parser lands"
)]
pub fn validate_cert_chain(
    _signing_cert_der: &[u8],
    _pinned_root_pem: &[u8],
    _expected_oidc_issuer: &str,
    _expected_oidc_email: &str,
    _rekor_signing_time_unix: u64,
) -> Result<(), SigstoreVerifyError> {
    Err(SigstoreVerifyError::NetworkUnreached)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn validate_cert_chain_returns_network_unreached_in_skeleton() {
        let result = validate_cert_chain(
            b"placeholder-cert-der",
            b"placeholder-root-pem",
            "https://accounts.example.org",
            "maintainer@cairn-project.org",
            1_700_000_000,
        );
        assert!(matches!(result, Err(SigstoreVerifyError::NetworkUnreached)));
    }
}
