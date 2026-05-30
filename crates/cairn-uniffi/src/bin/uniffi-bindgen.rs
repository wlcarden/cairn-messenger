// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! The uniffi-bindgen entrypoint per D0027 §8 / D0020 §3.10.
//!
//! The Android Gradle build (cargo-ndk-android-gradle) invokes this
//! binary to generate the Kotlin bindings from the compiled
//! `cairn_uniffi` library:
//!
//! ```sh
//! cargo run --features uniffi-bindings --bin uniffi-bindgen -- \
//!     generate --library <path-to-libcairn_uniffi.so> \
//!     --language kotlin --out-dir <gradle-generated-src>
//! ```
//!
//! Without the `uniffi-bindings` feature the binary is an inert stub
//! (so a default `cargo build` of the crate does not require uniffi).

#[cfg(feature = "uniffi-bindings")]
fn main() {
    uniffi::uniffi_bindgen_main();
}

#[cfg(not(feature = "uniffi-bindings"))]
fn main() {
    eprintln!(
        "cairn-uniffi: uniffi-bindgen requires the `uniffi-bindings` feature.\n\
         Re-run with: cargo run --features uniffi-bindings --bin uniffi-bindgen -- <args>"
    );
    std::process::exit(1);
}
