// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Bridge manifest configuration per D0025 §3 / D0020 §2.4.
//!
//! ## Manifest format
//!
//! ```toml
//! [[bridge]]
//! name = "obfs4"
//! bridge_line = "obfs4 1.2.3.4:443 FINGERPRINT cert=... iat-mode=0"
//!
//! [[bridge]]
//! name = "webtunnel"
//! bridge_line = "webtunnel ..."
//!
//! [[bridge]]
//! name = "snowflake"
//! bridge_line = "snowflake ..."
//! ```
//!
//! Per D0020 §2.4, the bridge manifest is **remote-updateable** — the
//! pluggable-transport viability shifts on a months-scale cat-and-
//! mouse cadence (WebTunnel "key tool in Russia" → "most bridges
//! blocked" in six months; Snowflake DTLS fingerprinting March 2026).
//! A static manifest degrades to unusable under DPI shifts.
//!
//! ## What this module owns vs. does not own (D0025 §3.2)
//!
//! - **Owns:** parsing a *already-verified* manifest into the bridge
//!   list C-Tor's control-port needs to launch Lyrebird with the
//!   right bridge lines; correlating a per-bridge bootstrap failure
//!   back to its manifest index for
//!   [`crate::error::TorTransportError::BridgeBootstrapFailed`].
//! - **Does NOT own:** fetching the manifest, verifying its Sigstore
//!   signature (D0024), checking its Sigsum witness cosignatures
//!   (D0023), or the monotonic-version rollback-resistance check
//!   (D0020 §2.4). This module consumes an already-verified manifest.
//!
//! ## Bridge-line opacity at this layer
//!
//! The crate stores `bridge_line` as an opaque string — the format is
//! whatever C-Tor's control-port + Lyrebird accept. This module does
//! NOT parse the bridge-line into typed fields; that's the C-Tor
//! control-port wrapper's responsibility at integration-cycle commit
//! time.

use serde::{Deserialize, Serialize};

use crate::error::TorTransportError;

/// One bridge entry parsed from the verified bridge manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BridgeEntry {
    /// Transport name (e.g., `"obfs4"`, `"webtunnel"`, `"snowflake"`,
    /// `"meek"`). Operational label only; the bridge-line carries the
    /// actual transport identifier C-Tor + Lyrebird consume.
    pub name: String,
    /// Opaque bridge-line string per C-Tor's bridge syntax. The crate
    /// does NOT parse this further at this layer.
    pub bridge_line: String,
}

/// The parsed (already-verified) bridge manifest per D0025 §3 /
/// D0020 §2.4.
///
/// Discipline: an empty list is permitted (the manifest MAY list no
/// bridges if the deployment connects to Tor directly). When the
/// bridge list is empty, C-Tor bootstraps without bridges; direct-
/// connection Tor is the result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BridgeManifest {
    bridges: Vec<BridgeEntry>,
}

impl BridgeManifest {
    /// Construct an empty manifest (no bridges; direct Tor).
    ///
    /// Equivalent to parsing an empty TOML; useful for tests + for
    /// deployments where direct Tor is acceptable.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            bridges: Vec::new(),
        }
    }

    /// Return the configured bridges in manifest order.
    #[must_use]
    pub fn bridges(&self) -> &[BridgeEntry] {
        &self.bridges
    }

    /// Return the bridge at `index`, if present.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&BridgeEntry> {
        self.bridges.get(index)
    }

    /// Bridge count as a `u8`. The parser accepts up to `u8::MAX`
    /// entries; larger inputs saturate to `u8::MAX` (a manifest with
    /// 255 bridges is operationally absurd).
    #[must_use]
    pub fn len(&self) -> u8 {
        u8::try_from(self.bridges.len()).unwrap_or(u8::MAX)
    }

    /// Return `true` if no bridges are configured. In that case,
    /// C-Tor bootstraps without bridges (direct Tor).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bridges.is_empty()
    }
}

/// Parse a bridge manifest from a (already-verified) TOML config
/// string per D0025 §3.
///
/// An empty input is treated as [`BridgeManifest::empty`] (no bridges
/// configured).
///
/// # Errors
///
/// - [`TorTransportError::BridgeManifestParse`] for any TOML parse
///   failure, missing required field, or malformed bridge entry.
pub fn parse_bridge_manifest(toml_text: &str) -> Result<BridgeManifest, TorTransportError> {
    #[derive(Deserialize, Default)]
    struct Wrapper {
        #[serde(default, rename = "bridge")]
        bridges: Vec<BridgeEntry>,
    }

    let wrapper: Wrapper =
        toml::from_str(toml_text).map_err(|_| TorTransportError::BridgeManifestParse)?;

    Ok(BridgeManifest {
        bridges: wrapper.bridges,
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_manifest_constructor_is_empty() {
        let manifest = BridgeManifest::empty();
        assert!(manifest.is_empty());
        assert_eq!(manifest.len(), 0);
        assert!(manifest.bridges().is_empty());
    }

    #[test]
    fn parse_empty_toml_yields_empty_manifest() {
        let manifest = parse_bridge_manifest("").unwrap();
        assert!(manifest.is_empty());
        assert_eq!(manifest.len(), 0);
    }

    #[test]
    fn parse_three_bridges_succeeds() {
        let toml = r#"
            [[bridge]]
            name = "obfs4"
            bridge_line = "obfs4 1.2.3.4:443 FINGERPRINT cert=abc iat-mode=0"

            [[bridge]]
            name = "webtunnel"
            bridge_line = "webtunnel https://example.org/secret"

            [[bridge]]
            name = "snowflake"
            bridge_line = "snowflake fingerprint=def url=https://snow.example.org"
        "#;
        let manifest = parse_bridge_manifest(toml).unwrap();
        assert_eq!(manifest.len(), 3);
        assert_eq!(manifest.bridges()[0].name, "obfs4");
        assert_eq!(manifest.bridges()[1].name, "webtunnel");
        assert_eq!(manifest.bridges()[2].name, "snowflake");
        assert!(manifest.bridges()[0].bridge_line.starts_with("obfs4 "));
    }

    #[test]
    fn parse_preserves_bridge_order() {
        // The bridge order in the manifest is the order the
        // BridgeBootstrapFailed { bridge_index } variants correlate
        // against per D0025 §6.
        let toml = r#"
            [[bridge]]
            name = "Z-first"
            bridge_line = "z"

            [[bridge]]
            name = "A-second"
            bridge_line = "a"
        "#;
        let manifest = parse_bridge_manifest(toml).unwrap();
        assert_eq!(manifest.get(0).unwrap().name, "Z-first");
        assert_eq!(manifest.get(1).unwrap().name, "A-second");
    }

    #[test]
    fn parse_malformed_toml_rejects() {
        let result = parse_bridge_manifest("not valid toml at all!!!");
        assert!(matches!(
            result,
            Err(TorTransportError::BridgeManifestParse)
        ));
    }

    #[test]
    fn parse_missing_required_field_rejects() {
        // missing `bridge_line`
        let toml = r#"
            [[bridge]]
            name = "obfs4"
        "#;
        let result = parse_bridge_manifest(toml);
        assert!(matches!(
            result,
            Err(TorTransportError::BridgeManifestParse)
        ));
    }

    #[test]
    fn get_out_of_range_returns_none() {
        let manifest = parse_bridge_manifest(
            r#"
            [[bridge]]
            name = "obfs4"
            bridge_line = "obfs4 ..."
        "#,
        )
        .unwrap();
        assert!(manifest.get(0).is_some());
        assert!(manifest.get(1).is_none());
        assert!(manifest.get(99).is_none());
    }
}
