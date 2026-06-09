// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Pinned Sigstore trust anchors (D0042 §5) — feature-gated behind
//! `pinned-anchors`.
//!
//! The real, individually attacker-unforgeable Sigstore trust material
//! captured for Cairn's release-verification path, exposed as named PEM
//! `&str` constants so a future production/staging verifier can be built
//! from compiled-in values rather than caller-supplied roots. Each
//! constant is the *same byte stream* as the corresponding `tests/vectors/`
//! file (via [`include_str!`]), so there is one canonical copy: the
//! committed vector and the pinned anchor cannot drift, and the existing
//! real-vector tests (`sct_vector.rs`, `fulcio_staging_vector.rs`,
//! `rekor_staging_vector.rs`) already prove these exact bytes verify
//! against genuine log signatures.
//!
//! ## What is real here — and what is NOT (the honest gaps)
//!
//! These anchors are **individually** real and verified. **Both**
//! environments now have a coherent transparency triple (Fulcio + CT +
//! Rekor) — staging from sigstage, production from the public production
//! logs. None of this silently becomes the shipped production root — see the
//! tripwire note below.
//!
//! | Anchor                          | Environment | Status |
//! |---------------------------------|-------------|--------|
//! | [`PROD_FULCIO_CHAIN_PEM`]       | production  | real   |
//! | [`PROD_CTLOG_PUBKEY_PEM`]       | production  | real   |
//! | [`PROD_REKOR_PUBKEY_PEM`]       | production  | real   |
//! | [`STAGING_FULCIO_CHAIN_PEM`]    | staging     | real   |
//! | [`STAGING_CTLOG_PUBKEY_PEM`]    | staging     | real   |
//! | [`STAGING_REKOR_PUBKEY_PEM`]    | staging     | real   |
//!
//! Coherent same-environment sets exercised today:
//!
//! - **Staging Fulcio chain + CT-log key + Rekor key** — all from sigstage.
//!   The Fulcio chain validates a real staging leaf
//!   (`tests/fulcio_staging_vector.rs`); the CT key verifies a real staging
//!   leaf's embedded SCT (`tests/staging_sct_vector.rs`, re-bound here by
//!   `staging_ctlog_anchor_verifies_real_staging_sct`); the Rekor key
//!   verifies a staging inclusion proof (`tests/rekor_staging_vector.rs`).
//! - **Production Fulcio chain + CT-log key + Rekor key** — from the public
//!   production logs (the same GHA signing event). The CT key verifies the
//!   GHA leaf's embedded SCT (re-bound by
//!   `prod_ctlog_anchor_verifies_real_gha_sct`, and end-to-end by
//!   `tests/sct_vector.rs`); the Rekor key verifies that event's real
//!   inclusion proof (`tests/rekor_production_vector.rs`).
//!
//! What is still **absent**, and why a shipped *production* verifier cannot
//! yet be assembled purely from these constants — every transparency anchor
//! capturable from public logs is now pinned, so what remains is
//! signing-run / governance / funding work, not log captures:
//!
//! - **No production OIDC identity.** The project's real maintainer/CI
//!   signing identity (`iss` + SAN) is a phase-3 governance decision
//!   (D0024 §1.1); it is also a per-release config value, not a pinned root.
//! - **No Sigsum release-log key or witness pool.** Those stay synthetic
//!   placeholders until the log + witnesses are recruited (D0042 §8,
//!   funding-gated).
//!
//! ## Relationship to the production tripwire
//!
//! This module is intentionally **separate** from cairn-uniffi's
//! `PRODUCTION_ROOTS` (D0041 §6.1), which stays `None`. These constants do
//! **not** silently become the shipped trust root: assembling a coherent
//! root set (one environment, with its matching CT key, Rekor key, OIDC
//! identity, and Sigsum anchors) remains phase-3 work. They are pinned now
//! so the real values are version-controlled under a stable API with their
//! provenance and gaps documented in one place.

/// Production Sigstore Fulcio CA chain (PEM).
///
/// The `sigstore-intermediate` intermediate followed by the self-signed
/// `sigstore` root, from the production `trusted_root.json` (the
/// sigstore/root-signing TUF target). The intermediate is the issuer of
/// GitHub Actions keyless precerts, so this is the chain the embedded-SCT
/// path (D0042 §6.5) walks to find the precert issuer whose SPKI hash binds
/// the SCT's `issuer_key_hash`.
pub const PROD_FULCIO_CHAIN_PEM: &str =
    include_str!("../tests/vectors/fulcio-gha/fulcio-chain.pem");

/// Production CT-log public key (ECDSA P-256 SPKI, PEM).
///
/// Its `SHA-256(SPKI)` equals the SCT's CT-log id `dd3d306a…`. Verifies the
/// embedded SCT on a production GitHub Actions Fulcio leaf (RFC 6962 §3.2 /
/// D0042 §6.5).
pub const PROD_CTLOG_PUBKEY_PEM: &str =
    include_str!("../tests/vectors/fulcio-gha/ctlog-pubkey.pem");

/// Production Rekor log public key (ECDSA P-256 SPKI, PEM).
///
/// From `GET https://rekor.sigstore.dev/api/v1/log/publicKey` — the key
/// that signs each production shard's C2SP checkpoint (D0024 §3). Verifies a
/// real production Rekor inclusion proof's signed tree head
/// (`tests/rekor_production_vector.rs`, a 25-node audit path).
pub const PROD_REKOR_PUBKEY_PEM: &str =
    include_str!("../tests/vectors/rekor-production/log-publickey.pem");

/// Staging Sigstore Fulcio trust bundle (PEM).
///
/// The self-signed `O=sigstore.dev, CN=sigstore` staging root plus the
/// staging `sigstore-intermediate`, from `fulcio.sigstage.dev`. Passed as
/// the pinned root PEM to [`crate::validate_cert_chain`] for a staging leaf.
pub const STAGING_FULCIO_CHAIN_PEM: &str =
    include_str!("../tests/vectors/fulcio-staging/root-chain.pem");

/// Staging Rekor log public key (ECDSA P-256 SPKI, PEM).
///
/// From `GET https://rekor.sigstage.dev/api/v1/log/publicKey` — the key
/// that signs each staging shard's C2SP checkpoint (D0024 §3). Verifies a
/// staging Rekor inclusion proof's signed tree head.
pub const STAGING_REKOR_PUBKEY_PEM: &str =
    include_str!("../tests/vectors/rekor-staging/log-publickey.pem");

/// Staging CT-log public key (ECDSA P-256 SPKI, PEM).
///
/// The staging CT log active from 2026-01-14 (`log_id` `3e607153…a6b6`),
/// extracted from the staging `trusted_root.json`. Its `SHA-256(SPKI)`
/// equals the embedded SCT's `log_id` on a real staging Fulcio leaf, so it
/// verifies that leaf's SCT (RFC 6962 §3.2 / D0042 §6.5) — the staging
/// counterpart to [`PROD_CTLOG_PUBKEY_PEM`].
pub const STAGING_CTLOG_PUBKEY_PEM: &str =
    include_str!("../tests/vectors/fulcio-staging-sct/ctlog-pubkey.pem");

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good pinned anchors; a parse/verify panic IS the failure signal that an anchor was corrupted"
)]
mod tests {
    use super::*;
    use crate::verify_embedded_sct;
    use x509_parser::pem::Pem;

    /// The real production GHA leaf whose embedded SCT the production CT
    /// key must verify (the same fixture `sct_vector.rs` uses).
    const GHA_LEAF_PEM: &str = include_str!("../tests/vectors/fulcio-gha/leaf-cert.pem");
    /// The real staging Fulcio leaf whose embedded SCT the staging CT key
    /// must verify (the same fixture `staging_sct_vector.rs` uses).
    const STAGING_LEAF_PEM: &str =
        include_str!("../tests/vectors/fulcio-staging-sct/leaf-cert.pem");

    /// Decode the `n`-th PEM block of `pem` to DER, or panic.
    fn nth_der(pem: &str, n: usize) -> Vec<u8> {
        Pem::iter_from_buffer(pem.as_bytes())
            .nth(n)
            .expect("pem block present")
            .expect("pem block parses")
            .contents
    }

    #[test]
    fn every_anchor_pem_decodes() {
        // Each constant must be a well-formed PEM whose first block parses
        // — a corrupted include path or truncated capture fails here.
        assert!(!nth_der(PROD_FULCIO_CHAIN_PEM, 0).is_empty());
        assert!(!nth_der(PROD_FULCIO_CHAIN_PEM, 1).is_empty()); // intermediate + root
        assert!(!nth_der(PROD_CTLOG_PUBKEY_PEM, 0).is_empty());
        assert!(!nth_der(PROD_REKOR_PUBKEY_PEM, 0).is_empty());
        assert!(!nth_der(STAGING_FULCIO_CHAIN_PEM, 0).is_empty());
        assert!(!nth_der(STAGING_FULCIO_CHAIN_PEM, 1).is_empty()); // intermediate + root
        assert!(!nth_der(STAGING_REKOR_PUBKEY_PEM, 0).is_empty());
        assert!(!nth_der(STAGING_CTLOG_PUBKEY_PEM, 0).is_empty());
    }

    #[test]
    fn prod_fulcio_and_staging_fulcio_certs_parse_as_x509() {
        use x509_parser::prelude::{FromDer as _, X509Certificate};
        for (pem, label) in [
            (PROD_FULCIO_CHAIN_PEM, "prod"),
            (STAGING_FULCIO_CHAIN_PEM, "staging"),
        ] {
            for (i, block) in Pem::iter_from_buffer(pem.as_bytes()).enumerate() {
                let der = block.expect("pem parses").contents;
                X509Certificate::from_der(&der)
                    .unwrap_or_else(|e| panic!("{label} fulcio cert {i} parses as X.509: {e:?}"));
            }
        }
    }

    #[test]
    fn prod_ctlog_anchor_verifies_real_gha_sct() {
        // The self-validating bind: the BAKED production CT-key constant,
        // with the BAKED production Fulcio intermediate (chain block 0),
        // must verify the real GHA leaf's embedded SCT. If either constant
        // were swapped or corrupted, the real CT-log signature would not
        // verify and this fails closed — proving the pinned anchors ARE the
        // material that verifies, not a look-alike.
        let leaf = nth_der(GHA_LEAF_PEM, 0);
        let intermediate = nth_der(PROD_FULCIO_CHAIN_PEM, 0);
        let ctlog = nth_der(PROD_CTLOG_PUBKEY_PEM, 0);
        verify_embedded_sct(&leaf, &intermediate, &ctlog)
            .expect("pinned production CT anchor must verify the real GHA leaf SCT");
    }

    #[test]
    fn staging_ctlog_anchor_verifies_real_staging_sct() {
        // The staging counterpart bind: the BAKED staging CT-key constant,
        // with the BAKED staging Fulcio intermediate (chain block 0), must
        // verify the real staging leaf's embedded SCT — the same
        // fail-closed self-validation as the production case, proving the
        // staging anchor triple is internally consistent.
        let leaf = nth_der(STAGING_LEAF_PEM, 0);
        let intermediate = nth_der(STAGING_FULCIO_CHAIN_PEM, 0);
        let ctlog = nth_der(STAGING_CTLOG_PUBKEY_PEM, 0);
        verify_embedded_sct(&leaf, &intermediate, &ctlog)
            .expect("pinned staging CT anchor must verify the real staging leaf SCT");
    }
}
