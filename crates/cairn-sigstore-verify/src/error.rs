// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Typed error surface per D0024 §7 + D0018 §4.2.
//!
//! Discipline: every variant carries indices, lengths, type tags, or
//! small numeric values only. No `Vec<u8>`, no `&[u8]`, no peer-
//! supplied strings beyond the project-pinned OIDC `iss` / `email`
//! values that the verifier compares against (those are project-
//! owned config, not peer-controlled).
//!
//! The variant set splits failure modes by layer so the caller can
//! distinguish Fulcio / OIDC / Rekor / manifest / Sigsum side
//! failures — same orthogonality discipline as D0023 §6.2's
//! ChainLink / SigsumInclusion split.

use thiserror::Error;

/// Top-level error type for `cairn-sigstore-verify`, re-exported from
/// the crate root.
///
/// `#[non_exhaustive]` per D0018 §4.2.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SigstoreVerifyError {
    /// Underlying network failure (timeout, connection-reset, HTTP
    /// 5xx) after the retry budget was exhausted. `retry_budget_used`
    /// names how many retries were consumed before giving up.
    #[error("sigstore-verify: network failure after {retry_budget_used} retries")]
    Network {
        /// Number of retries consumed before the error surfaced.
        retry_budget_used: u8,
    },

    /// Placeholder for the network-bound surfaces that aren't
    /// implemented yet. v1 skeleton ships with the testable load-
    /// bearing primitives (manifest schema, error surface, the
    /// async client handle) + this stub; the actual HTTP exercise
    /// against Rekor + Fulcio lands when CI grows a wiremock
    /// harness OR an opt-in integration-test flag against the real
    /// Rekor endpoint per D0024 §10.
    #[error("sigstore-verify: network surface not yet implemented (v1 skeleton)")]
    NetworkUnreached,

    /// The Fulcio-issued signing certificate did not chain to the
    /// pinned Fulcio root per D0024 §2.
    #[error("sigstore-verify: fulcio cert chain did not validate to the pinned root")]
    FulcioChainInvalid,

    /// The Fulcio signing certificate's validity window did not
    /// include the Rekor-attested signing time per D0024 §2.1.
    #[error("sigstore-verify: fulcio cert was not valid at the Rekor-attested signing time")]
    FulcioCertExpiredAtSigningTime,

    /// The OIDC `iss` claim in the Fulcio cert did not match the
    /// pinned issuer URL per D0024 §1.1.
    #[error("sigstore-verify: oidc issuer claim did not match the pinned issuer")]
    OidcIssuerMismatch,

    /// The OIDC `email` claim in the Fulcio cert did not match the
    /// pinned developer identity per D0024 §1.1.
    #[error("sigstore-verify: oidc email claim did not match the pinned developer identity")]
    OidcEmailMismatch,

    /// The SAN identity in the Fulcio cert did not match the pinned
    /// non-email identity — the CI workflow **URI** identity per D0042 §6.4
    /// (`https://github.com/ORG/REPO/.github/workflows/…@REF`).
    #[error("sigstore-verify: oidc SAN identity did not match the pinned CI workflow identity")]
    OidcIdentityMismatch,

    /// The Fulcio cert carried no embedded Signed Certificate Timestamp
    /// (`1.3.6.1.4.1.11129.2.4.2`) — CT-log inclusion is unproven
    /// (D0042 §6.5).
    #[error("sigstore-verify: fulcio cert has no embedded SCT")]
    SctMissing,

    /// No embedded SCT verified against the pinned CT-log key — a
    /// malformed SCT, an unpinned CT log, or a bad SCT signature over the
    /// reconstructed precert (RFC 6962 §3.2; D0042 §6.5).
    #[error("sigstore-verify: embedded SCT did not verify against the pinned CT-log key")]
    SctVerifyFailed,

    /// The Rekor inclusion proof's Merkle path did not verify per
    /// D0024 §3.
    #[error("sigstore-verify: rekor inclusion proof Merkle path did not verify")]
    RekorInclusionProofVerifyFailed,

    /// The Rekor signed checkpoint did not verify against the
    /// pinned Rekor public key per D0024 §3.
    #[error("sigstore-verify: rekor signed checkpoint did not verify against the pinned key")]
    RekorCheckpointVerifyFailed,

    /// A Rekor log-entry HTTP response (online mode per D0024 §6.4)
    /// could not be parsed into a `RekorBundle`: malformed JSON,
    /// missing inclusion-proof fields, bad hex/base64, or a malformed
    /// signed-checkpoint note line. Distinct from
    /// [`SigstoreVerifyError::RekorInclusionProofVerifyFailed`] /
    /// [`SigstoreVerifyError::RekorCheckpointVerifyFailed`], which are
    /// cryptographic-verification failures over a well-formed bundle.
    #[error("sigstore-verify: malformed rekor log-entry response")]
    RekorResponseMalformed,

    /// The release manifest's `prior_release_hash` does not
    /// reference the expected predecessor per D0024 §4.2's
    /// rollback-resistance property.
    #[error("sigstore-verify: manifest prior_release_hash did not match the expected predecessor")]
    ManifestPriorHashMismatch,

    /// The release manifest's `COSE_Sign1` signature did not
    /// verify against the Fulcio-issued public key per D0024 §4.
    #[error("sigstore-verify: manifest signature did not verify against the Fulcio cert pubkey")]
    ManifestSignatureVerifyFailed,

    /// The release manifest's canonical-CBOR decode failed. Either
    /// schema drift or tamper past the Sigstore check.
    #[error("sigstore-verify: release manifest canonical-CBOR decode failed")]
    ManifestDecodeFailed,

    /// A serialized [`crate::ReleaseBundle`] (or its nested
    /// [`crate::RekorBundle`] / Sigsum emitted-leaf) failed canonical-CBOR
    /// decode: malformed CBOR, wrong type tags, or a wrong-length
    /// fixed-width field. This is the offline-install wire format
    /// (D0024 §6.4) the release producer writes and the client reads
    /// before `verify_release`. Distinct from
    /// [`Self::ManifestDecodeFailed`] (the inner manifest payload) and
    /// [`Self::RekorResponseMalformed`] (the online Rekor HTTP shape).
    #[error("sigstore-verify: release bundle canonical-CBOR decode failed")]
    ReleaseBundleDecodeFailed,

    /// Underlying Sigsum-anchored release-log verification failed;
    /// the wrapped Sigsum error pinpoints the specific cause.
    #[error("sigstore-verify: sigsum release-log failure: {0}")]
    SigsumReleaseLog(#[from] cairn_sigsum_client::SigsumError),

    /// Underlying storage failure (for caching previously-verified
    /// releases per D0024 §6.4's offline mode).
    #[error("sigstore-verify: storage failure: {0}")]
    Storage(#[from] cairn_storage::StorageError),
}
