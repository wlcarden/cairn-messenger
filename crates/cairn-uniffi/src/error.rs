// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! The FFI error facade per D0027 §3.
//!
//! UniFFI requires exported fallible functions to return
//! `Result<_, E>` where `E` derives `uniffi::Error`. The workspace's
//! typed errors (`SigsumError`, `StorageError`, `TrustGraphError`,
//! `SimplexAdapterError`, `TorTransportError`, `SigstoreVerifyError`)
//! are NOT directly exported. Instead this module defines
//! [`CairnFfiError`] — a curated, flattened facade whose variants are
//! a TYPE-TAG mapping of the source errors.
//!
//! ## Why a flat mapping, not `#[from]`-nesting (the security point)
//!
//! Per D0027 §3.2 (the most security-relevant gap D0020 §3 leaves
//! open): if `CairnFfiError` wrapped the source errors (`#[from]
//! SigsumError`), UniFFI would lower the source error's `Display`
//! string to Kotlin — reopening the no-error-oracle hole (D0018 §4.2)
//! at exactly the boundary an attacker probes. The flat mapping
//! reproduces only the type-tag + the bounded scalars the source
//! error already exposes; it DISCARDS the source payload. No
//! `Vec<u8>`, no peer-supplied string, no nested source `Display`
//! crosses to Kotlin.
//!
//! ## Forward-compat
//!
//! Every source error is `#[non_exhaustive]`, so each mapping `match`
//! carries a wildcard arm → [`CairnFfiError::UnmappedInternal`]. A
//! future source variant this build does not explicitly map degrades
//! to `UnmappedInternal` rather than failing to compile or leaking a
//! default `Display` — same posture as D0023's `TrustGraphStoreUnknown`
//! sentinel.
//!
//! ## v1 skeleton status
//!
//! `CairnFfiError` is a plain enum here. The `#[derive(uniffi::Error)]`
//! attribute lands behind the `uniffi-bindings` feature per D0027 §8;
//! the mapping logic + its no-error-oracle discipline are plain Rust
//! and fully tested without UniFFI.

use cairn_identity::IdentityError;
use cairn_recovery::RecoveryError;
use cairn_sigstore_verify::SigstoreVerifyError;
use cairn_sigsum_client::SigsumError;
use cairn_simplex_adapter::SimplexAdapterError;
use cairn_storage::StorageError;
use cairn_tor_transport::TorTransportError;
use cairn_trust_graph::TrustGraphError;
use thiserror::Error;

/// The curated Kotlin-facing error facade per D0027 §3.
///
/// `#[non_exhaustive]` so adding facade variants later is not a
/// breaking change for Rust consumers. The `Display` strings are
/// Cairn-authored — type-tag + bounded scalars only, never a source
/// `Display`, never a `Vec<u8>`, never a peer-supplied string.
///
/// When the `uniffi-bindings` feature lands this enum additionally
/// derives `uniffi::Error` per D0027 §8.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Error))]
#[non_exhaustive]
pub enum CairnFfiError {
    // === Cross-cutting ===
    /// A network-bound surface is not yet implemented (v1 skeleton)
    /// or the operation is offline. Distinct so the shell can render
    /// "connecting / unavailable" vs. a hard failure.
    #[error("cairn: network surface unreached")]
    NetworkUnreached,
    /// Network failure after the retry budget was exhausted.
    #[error("cairn: network failure after {retry_budget_used} retries")]
    Network {
        /// Retries consumed before surfacing.
        retry_budget_used: u8,
    },

    // === Identity / trust-graph / capability ===
    /// An Ed25519 signature did not verify (envelope, op, token, or
    /// device-token binding).
    #[error("cairn: signature verify failed")]
    SignatureVerifyFailed,
    /// A capability token did not authorize the attempted operation.
    #[error("cairn: capability not authorized")]
    CapabilityNotAuthorized,
    /// A trust-graph chain-link structural check failed (genesis,
    /// prior-hash, pair, timestamp, or empty chain).
    #[error("cairn: trust-graph chain invalid")]
    ChainInvalid,
    /// Canonical-CBOR / schema decode failed, or a structural field
    /// was malformed. Covers the various "malformed bytes" source
    /// variants without leaking which byte.
    #[error("cairn: malformed data")]
    MalformedData,

    // === Storage ===
    /// The requested storage record was not found.
    #[error("cairn: storage record not found")]
    StorageRecordNotFound,
    /// Storage AEAD verification failed (wrong key, tamper, or AAD
    /// mismatch — uniform per D0018 §1.4).
    #[error("cairn: storage decrypt failed")]
    StorageDecryptFailed,
    /// Any other storage failure (open, migration, mutex-poison,
    /// truncation, encode). Flattened — the shell's response is the
    /// same: surface "local data error", do not retry blindly.
    #[error("cairn: storage failure")]
    StorageFailure,

    // === Transparency: Sigsum ===
    /// Fewer witnesses than the threshold (pool-too-small at config
    /// time, or insufficient cosignatures at verify time).
    #[error("cairn: sigsum witness threshold not met: {valid} valid, {required} required")]
    SigsumWitnessThreshold {
        /// Witnesses that were valid / configured.
        valid: u8,
        /// Witnesses required by the threshold.
        required: u8,
    },
    /// A Sigsum inclusion / consistency / cosignature verification
    /// failed.
    #[error("cairn: sigsum verify failed")]
    SigsumVerifyFailed,
    /// The Sigsum log presented a split view (tree-size regression or
    /// same-size-different-root). Halt per D0023 §7.1.
    #[error("cairn: sigsum split-view detected")]
    SigsumSplitView,

    // === Transparency: Sigstore ===
    /// The Fulcio cert's OIDC identity claims did not match the
    /// pinned issuer / email per D0024 §1.
    #[error("cairn: sigstore identity mismatch")]
    SigstoreIdentityMismatch,
    /// The Fulcio cert chain did not validate to the pinned root /
    /// was expired at signing time per D0024 §2.
    #[error("cairn: sigstore cert chain invalid")]
    SigstoreChainInvalid,
    /// A Rekor inclusion / checkpoint / manifest-signature
    /// verification failed per D0024 §3-§4.
    #[error("cairn: sigstore verify failed")]
    SigstoreVerifyFailed,

    // === Messaging (SimpleX adapter) ===
    /// The SimpleX Chat CLI sidecar is unavailable or misbehaving, or
    /// a connection was not found (D0026 §9 sidecar-layer variants).
    #[error("cairn: SimpleX sidecar failure")]
    SidecarFailure,
    /// A received Cairn message envelope failed verification
    /// (signature, AAD domain tag, or decode) per D0026 §9.
    #[error("cairn: message envelope verify failed")]
    EnvelopeVerifyFailed,
    /// The peer's envelope chain has a gap — a message is missing
    /// between the last-observed and the current one per D0026 §9.
    #[error(
        "cairn: envelope chain gap: last observed msg #{last_observed_message_number}, current #{observed_message_number}"
    )]
    EnvelopeChainGap {
        /// Last in-order message number observed.
        last_observed_message_number: u64,
        /// Message number the just-received envelope claims.
        observed_message_number: u64,
    },

    // === Transport (Tor) ===
    /// The C-Tor ForegroundService has not finished bootstrapping, or
    /// no bridge bootstrapped (D0025 §6 bootstrap-layer variants).
    #[error("cairn: tor bootstrap incomplete")]
    TorBootstrapIncomplete,
    /// A Tor connection failed (host resolution, refused/reset,
    /// control-port protocol, stream-closed) per D0025 §6.
    #[error("cairn: tor connection failed")]
    TorConnectionFailed,

    // === Recovery (Shamir master reconstruction) ===
    /// A recovery operation failed: the supplied shares did not
    /// reconstruct to the committed master secret (wrong / insufficient
    /// shares), or the resulting master attestation could not be
    /// signed. Distinct from `MalformedData` so the high-stakes
    /// recovery UI can render "recovery failed — check your shares"
    /// rather than a generic decode error.
    #[error("cairn: recovery reconstruction failed")]
    RecoveryFailed,

    // === Catch-all ===
    /// A source-error variant this build does not explicitly map
    /// (absorbs each source's `#[non_exhaustive]` future variants).
    #[error("cairn: unmapped internal error")]
    UnmappedInternal,
}

impl From<SigsumError> for CairnFfiError {
    fn from(e: SigsumError) -> Self {
        match e {
            SigsumError::NetworkUnreached => Self::NetworkUnreached,
            SigsumError::Network { retry_budget_used } => Self::Network { retry_budget_used },
            SigsumError::WitnessPoolTooSmall {
                configured,
                minimum,
            } => Self::SigsumWitnessThreshold {
                valid: configured,
                required: minimum,
            },
            SigsumError::InsufficientWitnessCosignatures {
                valid, required, ..
            } => Self::SigsumWitnessThreshold { valid, required },
            SigsumError::CosignatureVerifyFailed { .. }
            | SigsumError::InclusionProofVerifyFailed
            | SigsumError::ConsistencyProofVerifyFailed { .. } => Self::SigsumVerifyFailed,
            SigsumError::LogTreeSizeRegression { .. } | SigsumError::LogSplitView { .. } => {
                Self::SigsumSplitView
            }
            SigsumError::WitnessConfigParse
            | SigsumError::MalformedResponse
            | SigsumError::MalformedCacheRecord
            | SigsumError::Encode(_) => Self::MalformedData,
            SigsumError::Storage(_) => Self::StorageFailure,
            // TrustGraphStoreUnknown + any future variant.
            _ => Self::UnmappedInternal,
        }
    }
}

impl From<StorageError> for CairnFfiError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::RecordNotFound { .. } => Self::StorageRecordNotFound,
            StorageError::DecryptFailed => Self::StorageDecryptFailed,
            // OpenFailed / KeyProvider / CanonicalEncode /
            // UnsupportedRecordVersion / UnexpectedRecordLength /
            // CiphertextTruncated / MigrationFailed / MutexPoisoned +
            // any future variant.
            _ => Self::StorageFailure,
        }
    }
}

impl From<TrustGraphError> for CairnFfiError {
    fn from(e: TrustGraphError) -> Self {
        match e {
            // A capability-token verification failure is an authenticity
            // failure of the contact's authorization — the device-key sig,
            // the token issuer, or the token structure did not validate.
            // It MUST surface as a verification failure (NOT UnmappedInternal),
            // so the shell renders "invalid authorization", not a generic
            // internal error. The wrapped IdentityError sub-reason is
            // collapsed per the no-error-oracle discipline (D0027 §3.2).
            TrustGraphError::SignatureVerifyFailed
            | TrustGraphError::DeviceTokenMismatch
            | TrustGraphError::CapabilityTokenVerify(_) => Self::SignatureVerifyFailed,
            TrustGraphError::CapabilityNotAuthorized { .. } => Self::CapabilityNotAuthorized,
            TrustGraphError::ChainGenesisNotEmpty { .. }
            | TrustGraphError::ChainPriorHashMismatch { .. }
            | TrustGraphError::ChainPairMismatch { .. }
            | TrustGraphError::ChainTimestampRegression { .. }
            | TrustGraphError::ChainEmpty => Self::ChainInvalid,
            // A canonical-encode fault is a serialization failure; collapse
            // it to the malformed-data bucket alongside the decode faults
            // (the encode/decode direction is internal detail to hide).
            TrustGraphError::MalformedPayload
            | TrustGraphError::CanonicalEncode(_)
            | TrustGraphError::InvalidPubkeyLength { .. }
            | TrustGraphError::InvalidPubkey
            | TrustGraphError::UnknownOpType { .. }
            | TrustGraphError::UnknownStrength { .. }
            | TrustGraphError::MissingRequiredField { .. }
            | TrustGraphError::IntegerOutOfRange => Self::MalformedData,
            // A hardware-signer failure when minting (D0035 §4) + forward-compat
            // for a future #[non_exhaustive] variant: an environment/internal
            // fault, not an authenticity failure of received data. The mint path
            // (`TrustGraphHandle`) preserves the original callback `CairnFfiError`
            // directly, so `ExternalSignerFailed` only reaches here if raised
            // outside that path.
            _ => Self::UnmappedInternal,
        }
    }
}

impl From<cairn_trust_graph::StoreError> for CairnFfiError {
    fn from(err: cairn_trust_graph::StoreError) -> Self {
        use cairn_trust_graph::StoreError;
        match err {
            // Delegate to the existing typed-error facades so the
            // storage-vs-decode/encode distinction maps consistently.
            StoreError::Storage(e) => Self::from(e),
            StoreError::Decode(e) | StoreError::Encode(e) => Self::from(e),
            // Forward-compat: a future #[non_exhaustive] store variant.
            _ => Self::UnmappedInternal,
        }
    }
}

impl From<IdentityError> for CairnFfiError {
    fn from(e: IdentityError) -> Self {
        match e {
            // Authenticity failures of the capability token (bad signature
            // or wrong issuer) collapse to a single verification-failure
            // tag per the no-error-oracle discipline (D0027 §3.2).
            IdentityError::SignatureVerifyFailed | IdentityError::IssuerMismatch => {
                Self::SignatureVerifyFailed
            }
            // Data-shape faults (malformed CBOR, bad pubkey, encode fault,
            // out-of-range expiry) collapse to the malformed-data tag.
            IdentityError::MalformedPayload
            | IdentityError::CanonicalEncode(_)
            | IdentityError::InvalidPubkeyLength { .. }
            | IdentityError::InvalidPubkey
            | IdentityError::ExpiryOutOfRange => Self::MalformedData,
            // Forward-compat + a hardware-signer failure signing the self-token
            // (D0035 §4); the mint path preserves the original callback error,
            // so `ExternalSignerFailed` only reaches here if raised outside it.
            _ => Self::UnmappedInternal,
        }
    }
}

impl From<RecoveryError> for CairnFfiError {
    fn from(e: RecoveryError) -> Self {
        match e {
            // The recovery operation itself failed: the shares did not
            // reconstruct to the committed secret, or signing the fresh
            // master attestation failed. A distinct, high-stakes tag.
            RecoveryError::ShamirReconstruct(_) | RecoveryError::SignFailed => Self::RecoveryFailed,
            // The verify path: the attestation signature did not verify
            // or the master pubkey did not match.
            RecoveryError::SignatureVerifyFailed | RecoveryError::MasterPubkeyMismatch => {
                Self::SignatureVerifyFailed
            }
            // Data-shape faults (malformed CBOR, bad pubkey, encode
            // fault, out-of-range timestamp). The re-split's fresh-split step
            // (D0040 §5 / 3c) joins here: its dominant failure is invalid
            // caller-supplied parameters (`new_threshold` / `new_num_shares`
            // out of range), which is the same "you passed something malformed"
            // category — and it stays DISTINCT from a reconstruct failure
            // (ShamirReconstruct → RecoveryFailed, the user-actionable
            // "wrong/insufficient cards" case), which is the distinction the
            // separate ShamirSplit variant exists to preserve.
            RecoveryError::MalformedPayload
            | RecoveryError::CanonicalEncode(_)
            | RecoveryError::InvalidPubkeyLength { .. }
            | RecoveryError::InvalidPubkey
            | RecoveryError::TimestampOutOfRange
            | RecoveryError::ShamirSplit(_) => Self::MalformedData,
            // Forward-compat only (RecoveryError is #[non_exhaustive]).
            _ => Self::UnmappedInternal,
        }
    }
}

impl From<SimplexAdapterError> for CairnFfiError {
    fn from(e: SimplexAdapterError) -> Self {
        // De-opaque the cause (D0018 §4.2): the coarse public variant below
        // deliberately hides WHICH adapter step failed from a remote attacker,
        // but that distinction (e.g. SidecarUnavailable vs SidecarProtocol vs
        // ConnectionNotFound, all → SidecarFailure) is exactly what makes
        // on-device debugging tractable. Log it on the developer channel only —
        // `debug!` is compiled out of release, so the public error surface
        // stays an oracle-free coarse enum. This is the single chokepoint every
        // messaging op funnels through (`map_err(CairnFfiError::from)`).
        log::debug!("cairn-ffi: SimplexAdapterError -> facade | cause: {e}");
        match e {
            SimplexAdapterError::NetworkUnreached => Self::NetworkUnreached,
            SimplexAdapterError::Network { retry_budget_used } => {
                Self::Network { retry_budget_used }
            }
            SimplexAdapterError::SidecarUnavailable
            | SimplexAdapterError::SidecarProtocol
            | SimplexAdapterError::ConnectionNotFound => Self::SidecarFailure,
            SimplexAdapterError::EnvelopeSignatureVerifyFailed
            | SimplexAdapterError::EnvelopeDecodeFailed
            | SimplexAdapterError::EnvelopeDomainTagMismatch => Self::EnvelopeVerifyFailed,
            SimplexAdapterError::EnvelopeChainGap {
                last_observed_message_number,
                observed_message_number,
            } => Self::EnvelopeChainGap {
                last_observed_message_number,
                observed_message_number,
            },
            SimplexAdapterError::PaddingMalformed | SimplexAdapterError::Envelope(_) => {
                Self::MalformedData
            }
            SimplexAdapterError::Storage(_) => Self::StorageFailure,
            _ => Self::UnmappedInternal,
        }
    }
}

impl From<TorTransportError> for CairnFfiError {
    fn from(e: TorTransportError) -> Self {
        match e {
            TorTransportError::NetworkUnreached => Self::NetworkUnreached,
            TorTransportError::Network { retry_budget_used } => Self::Network { retry_budget_used },
            TorTransportError::BootstrapIncomplete
            | TorTransportError::AllBridgesFailed { .. }
            | TorTransportError::BridgeBootstrapFailed { .. } => Self::TorBootstrapIncomplete,
            TorTransportError::HostResolutionFailed
            | TorTransportError::ConnectionRefused
            | TorTransportError::ControlPortProtocol
            | TorTransportError::StreamClosed { .. } => Self::TorConnectionFailed,
            TorTransportError::BridgeManifestParse => Self::MalformedData,
            // OnionServiceHostingDeferred (v1.5; should not reach
            // Kotlin in v1) + any future variant.
            _ => Self::UnmappedInternal,
        }
    }
}

impl From<SigstoreVerifyError> for CairnFfiError {
    fn from(e: SigstoreVerifyError) -> Self {
        match e {
            SigstoreVerifyError::NetworkUnreached => Self::NetworkUnreached,
            SigstoreVerifyError::Network { retry_budget_used } => {
                Self::Network { retry_budget_used }
            }
            SigstoreVerifyError::OidcIssuerMismatch | SigstoreVerifyError::OidcEmailMismatch => {
                Self::SigstoreIdentityMismatch
            }
            SigstoreVerifyError::FulcioChainInvalid
            | SigstoreVerifyError::FulcioCertExpiredAtSigningTime => Self::SigstoreChainInvalid,
            SigstoreVerifyError::RekorInclusionProofVerifyFailed
            | SigstoreVerifyError::RekorCheckpointVerifyFailed
            | SigstoreVerifyError::ManifestPriorHashMismatch
            | SigstoreVerifyError::ManifestSignatureVerifyFailed => Self::SigstoreVerifyFailed,
            SigstoreVerifyError::ManifestDecodeFailed => Self::MalformedData,
            SigstoreVerifyError::SigsumReleaseLog(_) => Self::SigsumVerifyFailed,
            SigstoreVerifyError::Storage(_) => Self::StorageFailure,
            _ => Self::UnmappedInternal,
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    // === SigsumError mapping ===

    #[test]
    fn sigsum_network_unreached_maps_distinctly() {
        assert_eq!(
            CairnFfiError::from(SigsumError::NetworkUnreached),
            CairnFfiError::NetworkUnreached
        );
    }

    #[test]
    fn sigsum_insufficient_cosignatures_carries_scalars() {
        let mapped = CairnFfiError::from(SigsumError::InsufficientWitnessCosignatures {
            valid: 1,
            required: 2,
            pool_size: 3,
        });
        assert_eq!(
            mapped,
            CairnFfiError::SigsumWitnessThreshold {
                valid: 1,
                required: 2
            }
        );
    }

    #[test]
    fn sigsum_split_view_variants_collapse() {
        assert_eq!(
            CairnFfiError::from(SigsumError::LogSplitView { tree_size: 99 }),
            CairnFfiError::SigsumSplitView
        );
        assert_eq!(
            CairnFfiError::from(SigsumError::LogTreeSizeRegression {
                cached_tree_size: 10,
                fetched_tree_size: 5
            }),
            CairnFfiError::SigsumSplitView
        );
    }

    #[test]
    fn sigsum_storage_does_not_recurse_into_nested_error() {
        // The whole point of the flat mapping: Storage(_) collapses to
        // StorageFailure WITHOUT lowering the nested StorageError's
        // Display. We can only assert the mapping target here; the
        // no-recursion property is structural (the arm binds `_`).
        let mapped = CairnFfiError::from(SigsumError::Storage(StorageError::DecryptFailed));
        assert_eq!(mapped, CairnFfiError::StorageFailure);
    }

    // === StorageError mapping ===

    #[test]
    fn storage_record_not_found_maps_distinctly() {
        assert_eq!(
            CairnFfiError::from(StorageError::RecordNotFound {
                category: "messages"
            }),
            CairnFfiError::StorageRecordNotFound
        );
    }

    #[test]
    fn storage_decrypt_failed_maps_distinctly() {
        assert_eq!(
            CairnFfiError::from(StorageError::DecryptFailed),
            CairnFfiError::StorageDecryptFailed
        );
    }

    #[test]
    fn storage_other_variants_collapse_to_failure() {
        assert_eq!(
            CairnFfiError::from(StorageError::MutexPoisoned),
            CairnFfiError::StorageFailure
        );
        assert_eq!(
            CairnFfiError::from(StorageError::UnsupportedRecordVersion { got: 9 }),
            CairnFfiError::StorageFailure
        );
    }

    // === TrustGraphError mapping ===

    #[test]
    fn trust_graph_signature_failures_collapse() {
        assert_eq!(
            CairnFfiError::from(TrustGraphError::SignatureVerifyFailed),
            CairnFfiError::SignatureVerifyFailed
        );
        assert_eq!(
            CairnFfiError::from(TrustGraphError::DeviceTokenMismatch),
            CairnFfiError::SignatureVerifyFailed
        );
    }

    #[test]
    fn trust_graph_chain_failures_collapse_to_chain_invalid() {
        assert_eq!(
            CairnFfiError::from(TrustGraphError::ChainEmpty),
            CairnFfiError::ChainInvalid
        );
        assert_eq!(
            CairnFfiError::from(TrustGraphError::ChainPriorHashMismatch { index: 2 }),
            CairnFfiError::ChainInvalid
        );
    }

    #[test]
    fn trust_graph_capability_token_verify_maps_to_signature_failed() {
        // Regression: a capability-token verification failure must NOT
        // degrade to UnmappedInternal (it did before — the shell would
        // have rendered an invalid contact authorization as a generic
        // internal error). It is an authenticity failure → collapses to
        // SignatureVerifyFailed, sub-reason hidden per D0027 §3.2.
        assert_eq!(
            CairnFfiError::from(TrustGraphError::CapabilityTokenVerify(
                cairn_identity::IdentityError::IssuerMismatch
            )),
            CairnFfiError::SignatureVerifyFailed
        );
    }

    // === IdentityError mapping (direct source per D0027 §2.2 revision) ===

    #[test]
    fn identity_auth_failures_collapse_to_signature_failed() {
        assert_eq!(
            CairnFfiError::from(IdentityError::SignatureVerifyFailed),
            CairnFfiError::SignatureVerifyFailed
        );
        assert_eq!(
            CairnFfiError::from(IdentityError::IssuerMismatch),
            CairnFfiError::SignatureVerifyFailed
        );
    }

    #[test]
    fn identity_data_faults_collapse_to_malformed_data() {
        assert_eq!(
            CairnFfiError::from(IdentityError::MalformedPayload),
            CairnFfiError::MalformedData
        );
        assert_eq!(
            CairnFfiError::from(IdentityError::ExpiryOutOfRange),
            CairnFfiError::MalformedData
        );
    }

    // === RecoveryError mapping (eighth source per D0027 §2.2) ===

    #[test]
    fn recovery_sign_failure_maps_to_recovery_failed() {
        // The reconstruction path (ShamirReconstruct -> RecoveryFailed)
        // is covered end-to-end in recovery.rs; here the sibling
        // SignFailed source confirms the RecoveryFailed bucket.
        assert_eq!(
            CairnFfiError::from(RecoveryError::SignFailed),
            CairnFfiError::RecoveryFailed
        );
    }

    #[test]
    fn recovery_verify_failures_collapse_to_signature_failed() {
        assert_eq!(
            CairnFfiError::from(RecoveryError::SignatureVerifyFailed),
            CairnFfiError::SignatureVerifyFailed
        );
        assert_eq!(
            CairnFfiError::from(RecoveryError::MasterPubkeyMismatch),
            CairnFfiError::SignatureVerifyFailed
        );
    }

    // === SimplexAdapterError mapping ===

    #[test]
    fn simplex_sidecar_variants_collapse() {
        assert_eq!(
            CairnFfiError::from(SimplexAdapterError::SidecarUnavailable),
            CairnFfiError::SidecarFailure
        );
        assert_eq!(
            CairnFfiError::from(SimplexAdapterError::ConnectionNotFound),
            CairnFfiError::SidecarFailure
        );
    }

    #[test]
    fn simplex_envelope_chain_gap_carries_scalars() {
        let mapped = CairnFfiError::from(SimplexAdapterError::EnvelopeChainGap {
            last_observed_message_number: 4,
            observed_message_number: 6,
        });
        assert_eq!(
            mapped,
            CairnFfiError::EnvelopeChainGap {
                last_observed_message_number: 4,
                observed_message_number: 6
            }
        );
    }

    #[test]
    fn simplex_envelope_verify_variants_collapse() {
        assert_eq!(
            CairnFfiError::from(SimplexAdapterError::EnvelopeSignatureVerifyFailed),
            CairnFfiError::EnvelopeVerifyFailed
        );
        assert_eq!(
            CairnFfiError::from(SimplexAdapterError::EnvelopeDomainTagMismatch),
            CairnFfiError::EnvelopeVerifyFailed
        );
    }

    // === TorTransportError mapping ===

    #[test]
    fn tor_bootstrap_variants_collapse() {
        assert_eq!(
            CairnFfiError::from(TorTransportError::BootstrapIncomplete),
            CairnFfiError::TorBootstrapIncomplete
        );
        assert_eq!(
            CairnFfiError::from(TorTransportError::AllBridgesFailed {
                bridges_attempted: 3
            }),
            CairnFfiError::TorBootstrapIncomplete
        );
    }

    #[test]
    fn tor_connection_variants_collapse() {
        assert_eq!(
            CairnFfiError::from(TorTransportError::ConnectionRefused),
            CairnFfiError::TorConnectionFailed
        );
        assert_eq!(
            CairnFfiError::from(TorTransportError::HostResolutionFailed),
            CairnFfiError::TorConnectionFailed
        );
    }

    #[test]
    fn tor_onion_deferred_maps_to_unmapped_internal() {
        // The v1.5 deferral sentinel should not surface as a real
        // Kotlin-facing error in v1.
        assert_eq!(
            CairnFfiError::from(TorTransportError::OnionServiceHostingDeferred),
            CairnFfiError::UnmappedInternal
        );
    }

    // === SigstoreVerifyError mapping ===

    #[test]
    fn sigstore_oidc_variants_collapse_to_identity_mismatch() {
        assert_eq!(
            CairnFfiError::from(SigstoreVerifyError::OidcIssuerMismatch),
            CairnFfiError::SigstoreIdentityMismatch
        );
        assert_eq!(
            CairnFfiError::from(SigstoreVerifyError::OidcEmailMismatch),
            CairnFfiError::SigstoreIdentityMismatch
        );
    }

    #[test]
    fn sigstore_rekor_variants_collapse_to_verify_failed() {
        assert_eq!(
            CairnFfiError::from(SigstoreVerifyError::RekorCheckpointVerifyFailed),
            CairnFfiError::SigstoreVerifyFailed
        );
    }

    // === No-error-oracle discipline: Display carries no source payload ===

    #[test]
    fn display_strings_carry_only_type_tags_and_scalars() {
        // Spot-check that the facade's Display does not embed any
        // peer-controlled or byte content — only Cairn-authored text +
        // bounded scalars.
        let chain_gap = CairnFfiError::EnvelopeChainGap {
            last_observed_message_number: 4,
            observed_message_number: 6,
        };
        let s = chain_gap.to_string();
        assert!(s.contains("envelope chain gap"));
        assert!(s.contains('4'));
        assert!(s.contains('6'));

        let threshold = CairnFfiError::SigsumWitnessThreshold {
            valid: 1,
            required: 2,
        };
        assert!(threshold.to_string().contains("witness threshold"));
    }
}
