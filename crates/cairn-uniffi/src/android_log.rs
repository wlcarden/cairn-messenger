// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Android logcat backend for the `log` facade (D0026 §12 on-device
//! observability).
//!
//! `cairn-simplex-adapter` logs its SMP command/event flow through the `log`
//! facade. On Android, [`init`] installs `android_logger` as the backend so
//! those records reach `logcat` under the tag `CairnRust` — visible alongside
//! the Kotlin shell's `CairnFfi` tag. The facade is a no-op until a backend is
//! installed, so host builds (and the default uniffi build) stay silent.
//!
//! `android_logger` is used (rather than a hand-rolled `__android_log_write`
//! binding) precisely because the workspace **forbids `unsafe`**: the
//! unavoidable liblog FFI is confined to that vetted, android-target-only crate
//! instead of first-party code. Pulled with `default-features = false`, so its
//! transitive surface is just `android_log-sys` + `log` (no `regex`/env-filter
//! tree).

use android_logger::Config;
use log::LevelFilter;

/// Install the logcat backend for the `log` facade. Idempotent by construction
/// (`android_logger::init_once` is backed by a `Once`), so a second call — e.g.
/// a second [`crate::messaging::SimplexAdapterHandle`] — is a no-op. Caps the
/// level at Info (the SMP flow diagnostics are info/warn/error; the `log`
/// crate's `release_max_level_info` feature already drops debug/trace in
/// release builds).
pub fn init() {
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Info)
            .with_tag("CairnRust"),
    );
}
