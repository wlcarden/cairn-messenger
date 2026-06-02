// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// Same crate-wide allow as the other integration crates: many
// proper-noun technical terms (UniFFI, Kotlin, StrongBox, SimpleX,
// Sigsum, Sigstore, OIDC, etc.) that would each need backticks.
#![allow(clippy::doc_markdown)]

//! # cairn-uniffi
//!
//! The single FFI boundary crate per
//! [D0027](../../docs/decisions/D0027-cairn-uniffi-crate-surface.md),
//! implementing the FFI architecture decided in
//! [D0020](../../docs/decisions/D0020-integration-architecture.md) §3
//! (UniFFI 0.31.1 + hand-written jni-rs for KeyStore mediation).
//!
//! D0020 §3 owns the FFI-architecture decision; this crate is its
//! crate-surface implementation. No other workspace crate carries
//! `#[uniffi::export]` — the domain crates stay FFI-agnostic so
//! `cairn-cli` + tests consume the same Rust APIs without the FFI
//! layer.
//!
//! ## What this crate implements (D0027)
//!
//! - **Single FFI boundary** (D0027 §1): the curated Kotlin-facing
//!   surface lives here; per-domain modules map 1:1 to the owning
//!   D-docs.
//! - **The opaque-handle vs. plain-record split** (D0027 §2): secret/
//!   capability-bearing types cross as `uniffi::Object` opaque handles
//!   (operation methods only; bytes never lower); public/derived data
//!   crosses as `uniffi::Record`.
//! - **The FFI error facade** (D0027 §3): [`error::CairnFfiError`] is a
//!   FLAT type-tag mapping of the six source typed errors — NOT
//!   `#[from]`-nesting, so no source `Display` string lowers to Kotlin
//!   (the no-error-oracle discipline of D0018 §4.2 reproduced at the
//!   boundary, not bypassed by it).
//! - **NeverExport enforcement** (D0027 §4 / D0020 §3.7):
//!   [`never_export_gate`] carries the compile-time half; the CI
//!   discipline-grep gate carries the other half.
//! - **The hardware-mediation callback** (D0027 §2.3 / D0020 §3.4):
//!   [`hardware::HardwareKeySigner`] — Kotlin signs in StrongBox; only
//!   public bytes return.
//! - **Async export shape** (D0027 §5): the four async I/O surfaces
//!   export as Kotlin `suspend fun`s with a single tokio runtime
//!   registration; sync crypto-core ops export as plain funs.
//!
//! ## Implementation status
//!
//! The pipeline this crate compiles against is up: the
//! `uniffi = "=0.31.1"` workspace pin is present, the
//! cargo-ndk-android-gradle build is validated (D0028), and the
//! UniFFI scaffolding + the representative [`cairn_ffi_abi_version`]
//! export bind end-to-end into the APK. The cross-cutting,
//! security-critical primitives are implemented + tested:
//!
//! - [`error::CairnFfiError`] + the six total flat `From` mappings —
//!   the no-error-oracle boundary discipline (the thing that most
//!   needs to be right before any byte crosses to Kotlin). Derives
//!   `uniffi::Error` under the feature.
//! - [`never_export_gate`] — the compile-time exportability assertion
//!   on every type that crosses the boundary.
//! - [`hardware::HardwareKeySigner`] — the `callback_interface` trait
//!   (D0020 §3.4), with a mock impl proving object-safety.
//!
//! The per-domain `#[uniffi::export]` surface (D0027 §2) fills in
//! behind that proven pipeline, one domain at a time. Landed:
//!
//! - [`trust_graph`] — [`trust_graph_verify_and_classify`] +
//!   [`QuarantineStatusFfi`]: the fused verify-then-classify the
//!   Android shell drives to render trust badges. First per-domain
//!   module (D0027 §8 step 4).
//! - [`identity`] — [`identity_verify_capability_token`] +
//!   [`CapabilityTokenRecord`]: verify-then-decode of a capability
//!   token's public metadata. StrongBox-only (D0027 §2.2 revision):
//!   the op-identity key signs in StrongBox via
//!   [`hardware::HardwareKeySigner`], so there is NO software signing
//!   handle — the module is pure verify/decode over public credentials.
//! - [`recovery`] — [`recovery_reconstruct_and_attest`] +
//!   [`recovery_verify_master_attestation`] ([`ShareRecord`] /
//!   [`MasterAttestationRecord`]): reconstruct the master seed from a
//!   threshold of Shamir shares + attest a new operational identity
//!   (seed reconstructed + zeroized Rust-side, never crossing), plus
//!   hop-#3 master-attestation verify. Completes the sync crypto-core
//!   trio.
//! - [`storage`] — [`StorageHandle`] (the first opaque `uniffi::Object`)
//!   plus the [`StrongBoxKeyMaterial`] callback: the encrypted category
//!   put/get/delete surface. The KEK is derived in Rust (Argon2id) and
//!   never crosses; the callback supplies only the StrongBox material
//!   and the unlock state (D0027 §2.4 resolution).
//! - [`transparency`] — [`SigsumClientHandle`] ([`SigsumLogConfig`] /
//!   [`TreeHeadRecord`]): the **first async** Object. `refresh_tree_head`
//!   / `verify_inclusion` / `emit_op` export as `suspend fun`s
//!   (`#[uniffi::export(async_runtime = "tokio")]` per D0027 §5). It
//!   shares the [`StorageHandle`]'s `Arc<Storage>`; `emit_op` signs the
//!   Sigsum tree-leaf via the [`HardwareKeySigner`] callback (the op key
//!   stays in StrongBox).
//!
//! - [`tor`] — [`TorTransportHandle`] ([`TorControlConfig`] /
//!   [`NetworkStateFfi`]): the C-Tor control plane —
//!   `observe_network_state` / `signal_newnym` / `bootstrap_phase` as
//!   `suspend fun`s. Control plane only; the data-plane `TorStream` is
//!   consumed Rust-side, not crossed.
//!
//! - [`messaging`] — [`SimplexAdapterHandle`] ([`SidecarEndpointConfig`] /
//!   [`MessageSentRecord`] / [`ReceivedMessageRecord`]): the last async
//!   Object. `create_invitation` / `accept_invitation` / `send` / `recv`
//!   export as `suspend fun`s. The device key signs each envelope's
//!   `COSE_Sign1` in StrongBox via the [`HardwareKeySigner`] callback
//!   (bridged into `cairn_simplex_adapter::EnvelopeSigner`; the key never
//!   crosses — D0026 §2.3), and the handle shares the [`StorageHandle`]'s
//!   `Arc<Storage>` for the `MESSAGES` history. `send` / `recv` exercise
//!   the full build → sign → persist path but return `NetworkUnreached`
//!   over the deferred `SimploxideTransport` (D0026 §12) until
//!   `simploxide-client` lands.
//!
//! All seven per-domain modules (D0027 §2) have now landed. The
//! `fuzz_uniffi_boundary` harness (D0018 §5.2) is a follow-up.

pub mod error;
pub mod hardware;
pub mod identity;
pub mod messaging;
pub mod never_export_gate;
pub mod recovery;
pub mod storage;
pub mod tor;
pub mod transparency;
pub mod trust_graph;

// Android-only logcat backend for the `log` facade (D0026 §12 on-device
// observability of the SMP command/event flow). Absent on host builds, where
// the `log` facade stays a no-op.
#[cfg(target_os = "android")]
pub mod android_log;

pub use error::CairnFfiError;
pub use hardware::{AttestationCertificate, HardwareKeySigner, HardwarePublicKey, KeyGenSpec};
pub use identity::{CapabilityTokenRecord, identity_verify_capability_token};
pub use messaging::{
    MessageSentRecord, ReceivedMessageRecord, SidecarEndpointConfig, SimplexAdapterHandle,
};
pub use recovery::{
    MasterAttestationRecord, ShareRecord, recovery_reconstruct_and_attest,
    recovery_verify_master_attestation,
};
pub use storage::{StorageHandle, StrongBoxKeyMaterial};
pub use tor::{NetworkStateFfi, TorControlConfig, TorTransportHandle};
pub use transparency::{SigsumClientHandle, SigsumLogConfig, TreeHeadRecord};
pub use trust_graph::{QuarantineStatusFfi, trust_graph_verify_and_classify};

// UniFFI scaffolding entrypoint per D0027 §5 / D0020 §3.1. Generates
// the FFI scaffolding the Kotlin bindings bind against. Gated on the
// `uniffi-bindings` feature so the default build stays uniffi-free.
#[cfg(feature = "uniffi-bindings")]
uniffi::setup_scaffolding!();

/// The cairn-uniffi ABI version string.
///
/// A representative `#[uniffi::export]` proving the pipeline end-to-end
/// per D0027 §8 (the minimal vertical slice: Rust export →
/// uniffi-bindgen → Kotlin → APK call). The full per-domain export
/// surface (D0027 §2) fills in behind this proven pipeline. Returns the
/// crate version so the Kotlin shell can assert it loaded the expected
/// Rust core at startup.
#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
#[must_use]
pub fn cairn_ffi_abi_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_is_crate_version() {
        assert_eq!(cairn_ffi_abi_version(), env!("CARGO_PKG_VERSION"));
    }
}
