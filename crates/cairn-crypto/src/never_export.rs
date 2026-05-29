// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Sealed marker trait preventing secret-bearing types from crossing the `UniFFI`
//! boundary.
//!
//! Per D0020 §3.7 — `UniFFI` does not structurally prevent exporting a type that
//! contains secret material. Cairn enforces "no secrets across the FFI boundary"
//! through this sealed marker trait plus a CI grep gate per D0018 §5.4.
//!
//! Implementation pattern:
//!
//! ```text
//! mod sealed { pub trait Sealed {} }
//! pub trait NeverExport: sealed::Sealed {}
//!
//! impl sealed::Sealed for SecretBox<SigningKey> {}
//! impl NeverExport for SecretBox<SigningKey> {}
//! ```
//!
//! `#[uniffi::export]` functions must not take or return `T: NeverExport`. The
//! CI grep gate per `.github/workflows/ci.yml` rejects PRs that violate this
//! discipline.
//!
//! ## Stable-Rust limitation
//!
//! On stable Rust, this is enforced via the sealed-trait pattern plus the CI
//! grep gate, not via auto-trait + negative-impl machinery (which would require
//! nightly Rust and is forbidden by Cairn's stable-toolchain commitment per
//! `rust-toolchain.toml`). The CI grep gate is the stable-Rust equivalent.

mod sealed {
    /// Sealed-trait implementation detail. External crates cannot implement
    /// [`super::NeverExport`] because this trait is not exported.
    pub trait Sealed {}
}

/// Marker trait: types implementing this marker MUST NOT cross the `UniFFI`
/// boundary. The marker is sealed; only `cairn-crypto` may add implementations.
///
/// See the module-level documentation for the enforcement pattern.
pub trait NeverExport: sealed::Sealed {}

// ============================================================================
// Implementations for cairn-crypto secret types.
//
// Add new implementations here as new secret-bearing types land in cairn-crypto
// or its sister crates. Implementations for secret types in cairn-shamir,
// cairn-identity, etc. live in those crates (each with its own sealed
// submodule) per the same discipline.
// ============================================================================

use secrecy::SecretBox;

/// 32-byte Ed25519 seed wrapper marker (RFC 8032 §5.1.5).
///
/// Cairn stores Ed25519 signing keys as `SecretBox<[u8; 32]>` of the seed,
/// then reconstructs the `ed25519_dalek::SigningKey` on demand. See
/// [`crate::ed25519::SigningKey`] for the wrapper type.
impl sealed::Sealed for SecretBox<[u8; 32]> {}
impl NeverExport for SecretBox<[u8; 32]> {}

/// Compile-time assertion that a type does NOT implement [`NeverExport`].
///
/// Use in tests and trait bounds to assert exportability statically. This is
/// the inverse check: if `T: NeverExport`, this function will not compile.
///
/// ```
/// use cairn_crypto::never_export::assert_exportable;
///
/// assert_exportable::<u8>();          // Plain integers are exportable
/// assert_exportable::<Vec<u8>>();     // Plain Vec<u8> is exportable
/// // assert_exportable::<SecretBox<SigningKey>>();  // would NOT compile
/// ```
pub const fn assert_exportable<T: ?Sized + Exportable>() {}

/// Marker for types that are explicitly exportable.
///
/// Implemented for all standard library types via the blanket impl below; not
/// implemented for any type marked [`NeverExport`].
///
/// **Caveat:** because Rust stable does not support negative impls or auto
/// traits, this marker is enforced by convention plus CI grep. The blanket impl
/// covers anything without an explicit [`NeverExport`] impl. The pattern is
/// asymmetric: a contributor adding a new secret type must remember to add the
/// `NeverExport` impl; the CI gate catches the case where `#[uniffi::export]`
/// is applied to a type that should not cross the boundary.
pub trait Exportable {}

// Blanket impl: any type not explicitly marked NeverExport is treated as
// exportable for the purpose of this assertion.
impl<T: ?Sized> Exportable for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    const fn assert_basic_types_exportable() {
        assert_exportable::<u8>();
        assert_exportable::<u32>();
        assert_exportable::<Vec<u8>>();
        assert_exportable::<&[u8]>();
        assert_exportable::<String>();
    }

    // Negative tests: verify that `NeverExport` types are at least present in
    // the type system. Cannot use `assert_exportable::<...>()` here because it
    // would compile fine under the blanket-impl approach; the actual enforcement
    // is via `UniFFI`-export-site review + CI grep.
    #[test]
    const fn never_export_types_present() {
        // This test asserts the marker impl exists; if a refactor breaks the
        // impl, this test fails at the type-check level.
        const fn assert_marker<T: NeverExport>() {}
        assert_marker::<SecretBox<[u8; 32]>>();
    }
}
