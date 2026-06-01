// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! NeverExport enforcement per D0027 §4 + D0020 §3.7.
//!
//! D0020 §3.7 defines the sealed [`cairn_crypto::never_export::NeverExport`]
//! marker trait; D0020 §3.6 establishes the rule "secret types MUST
//! NOT cross the UniFFI boundary as byte arrays." This module makes
//! the enforcement concrete per D0027 §4:
//!
//! 1. Every secret-bearing type implements `NeverExport` (the impls
//!    live in `cairn-crypto`; this crate consumes the marker).
//! 2. No `NeverExport` type lowers across the boundary — opaque
//!    `uniffi::Object` handles MAY hold one privately (the point), but
//!    it never appears as a `uniffi::Record` field or a `Lower`
//!    argument/return.
//! 3. The enforcement has two layers: a compile-time
//!    [`cairn_crypto::never_export::assert_exportable`] check on the
//!    plain carrier types that DO cross, plus the CI discipline-grep
//!    gate (D0020 §3.11 step 3) that scans the generated UDL +
//!    `#[uniffi::export]` signatures for any `NeverExport` type name
//!    in a lowering position.
//!
//! ## Why the marker trait is necessary but not sufficient
//!
//! The sealed marker prevents external crates from claiming a type is
//! exportable, but it cannot by itself stop a future
//! `#[uniffi::export]` from accidentally lowering a secret — Rust has
//! no stable negative-impl machinery to express "this generic
//! position rejects `T: NeverExport`." The compile-time
//! `assert_exportable` check + the CI grep gate are the executable
//! enforcement. This module carries the compile-time half.
//!
//! ## v1 skeleton scope
//!
//! The plain carrier types that cross the boundary at v1 (public
//! keys + hashes as `Vec<u8>`, message-number counters as `u64`, the
//! facade error as [`crate::error::CairnFfiError`]) are asserted
//! exportable here. The opaque-handle export types
//! (`uniffi::Object`s) land with the binding-generation body per
//! D0027 §8; when they do, each gains its own `assert_exportable`
//! line + the CI grep gate covers the generated UDL.

use cairn_crypto::never_export::assert_exportable;

/// Compile-time assertion that the plain carrier types crossing the
/// FFI boundary at v1 are exportable (i.e., do NOT implement
/// [`cairn_crypto::never_export::NeverExport`]).
///
/// This is a `const fn` whose body is a sequence of
/// [`assert_exportable`] calls; if any listed type were
/// secret-bearing (`NeverExport`), this function would fail to
/// compile. It is invoked from a test (below) + is available for the
/// binding-generation body to extend as opaque-handle export types
/// land.
pub const fn assert_v1_carrier_types_exportable() {
    // Public-key + hash byte carriers (these are PUBLIC values, not
    // secrets — pubkeys + SHA-256 digests).
    assert_exportable::<u8>();
    assert_exportable::<u64>();
    assert_exportable::<Vec<u8>>();
    // The facade error itself crosses as a uniffi::Error; it carries
    // only type-tags + scalars per crate::error.
    assert_exportable::<crate::error::CairnFfiError>();
    // Per-domain export types. Each new module adds its crossing types
    // here so the gate fails to compile if one ever becomes
    // secret-bearing. trust_graph (D0027 §2): the cascade-status enum
    // carries only PUBLIC pubkey bytes + Unix-seconds.
    assert_exportable::<crate::trust_graph::QuarantineStatusFfi>();
    // identity (D0027 §2.2): the capability-token record carries only
    // PUBLIC pubkeys + scope strings + the expiry (no secret; the
    // op-identity key signs in StrongBox, never crossing as bytes).
    assert_exportable::<crate::identity::CapabilityTokenRecord>();
    // recovery (D0027 §2.2): the master-attestation record is all
    // PUBLIC pubkeys + a timestamp. The share record carries a Shamir
    // share value — sensitive but transportable-by-design (a single
    // share is below the reconstruction threshold and is NOT the sealed
    // master secret), so it correctly crosses; the SEED never does.
    assert_exportable::<crate::recovery::MasterAttestationRecord>();
    assert_exportable::<crate::recovery::ShareRecord>();
    // transparency (D0027 §2): the Sigsum config + tree-head records
    // carry only public values (log URL/pubkey/witnesses, tree size +
    // root hash + timestamp). The StrongBox-signed emit key never
    // crosses (it stays behind the HardwareKeySigner callback).
    assert_exportable::<crate::transparency::SigsumLogConfig>();
    assert_exportable::<crate::transparency::TreeHeadRecord>();
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::missing_const_for_fn,
    reason = "these tests assert COMPILE-TIME exportability; a green build IS the assertion. \
              #[test] fns cannot be const (the harness needs regular fns), so the nursery \
              missing_const_for_fn lint is a false positive here."
)]
mod tests {
    use super::*;

    #[test]
    fn v1_carrier_types_are_exportable() {
        // Invoking the const fn exercises every assert_exportable
        // line; the real enforcement is at COMPILE time (a
        // NeverExport type in the list would fail to build), so a
        // green compile of this test IS the assertion. The runtime
        // call confirms the symbol is reachable.
        assert_v1_carrier_types_exportable();
    }

    #[test]
    fn facade_error_is_exportable_not_secret() {
        // CairnFfiError must be lowerable to Kotlin (it is the FFI
        // error type); asserting it is exportable confirms it carries
        // no NeverExport (secret) field.
        assert_exportable::<crate::error::CairnFfiError>();
    }
}
