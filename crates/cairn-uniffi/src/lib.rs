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
//! ## Implementation status (v1 skeleton)
//!
//! The load-bearing, security-critical primitives are implemented +
//! tested WITHOUT the UniFFI proc-macro (per D0027 §8):
//!
//! - [`error::CairnFfiError`] + the six total flat `From` mappings —
//!   the no-error-oracle boundary discipline (the thing that most
//!   needs to be right before any byte crosses to Kotlin).
//! - [`never_export_gate`] — the compile-time exportability assertion
//!   on the v1 carrier types.
//! - [`hardware::HardwareKeySigner`] — the callback trait shape +
//!   spec types, with a mock impl proving object-safety.
//!
//! Deferred behind the `uniffi-bindings` feature (lands when the
//! cargo-ndk-android-gradle pipeline is stood up per D0020 §3.10 /
//! D0027 §8):
//!
//! - The `#[derive(uniffi::Error)]` on `CairnFfiError`, the
//!   `#[uniffi::export(callback_interface)]` on `HardwareKeySigner`,
//!   the per-domain `#[uniffi::export]` / `#[uniffi::Object]` /
//!   `#[uniffi::Record]` surface, the UDL generation, the
//!   `uniffi = "=0.31.1"` workspace pin, and the
//!   `fuzz_uniffi_boundary` harness.
//!
//! The skeleton ships the error facade + the NeverExport gate + the
//! trait declarations as the testable primitives; the binding
//! generation is the gated follow-up.

pub mod error;
pub mod hardware;
pub mod never_export_gate;

pub use error::CairnFfiError;
pub use hardware::{AttestationCertificate, HardwareKeySigner, HardwarePublicKey, KeyGenSpec};
