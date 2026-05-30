// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Pluggable transports configuration per D0025 §3.
//!
//! ## Config format
//!
//! ```toml
//! [[transport]]
//! name = "obfs4"
//! bridge_line = "obfs4 1.2.3.4:443 FINGERPRINT cert=... iat-mode=0"
//!
//! [[transport]]
//! name = "webtunnel"
//! bridge_line = "webtunnel ..."
//!
//! [[transport]]
//! name = "snowflake"
//! bridge_line = "snowflake ..."
//! ```
//!
//! Per D0025 §3.1, the file is RELEASE-SCOPED: changes ride Cairn
//! releases. Users do not edit it at runtime. Same posture as the
//! Sigsum witness pool per D0023 §3.3.
//!
//! ## Bridge-line opacity at this layer
//!
//! The crate stores `bridge_line` as an opaque string — the format
//! is whatever Arti's pluggable-transport API accepts. This crate
//! does NOT parse the bridge-line into typed fields; that's Arti's
//! responsibility at integration-cycle commit time. The skeleton's
//! job is to round-trip the config + correlate transport indices to
//! [`crate::error::TorTransportError::PluggableTransportBootstrapFailed`]
//! variants.

use serde::{Deserialize, Serialize};

use crate::error::TorTransportError;

/// One pluggable-transport entry parsed from
/// `pluggable_transports.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PluggableTransportEntry {
    /// Transport name (e.g., `"obfs4"`, `"webtunnel"`, `"snowflake"`).
    /// Operational label only; the bridge-line carries the actual
    /// transport identifier the Arti API consumes.
    pub name: String,
    /// Opaque bridge-line string per Arti's pluggable-transport
    /// API. The crate does NOT parse this further at this layer.
    pub bridge_line: String,
}

/// The parsed pluggable-transports config per D0025 §3.
///
/// Discipline: an empty list is permitted (the caller MAY ship a
/// release with no pluggable transports if the deployment doesn't
/// require them). When the transport list is empty,
/// [`crate::transport::TorTransport::new`] bootstraps Arti without
/// any bridges; direct-connection Tor is the result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PluggableTransportConfig {
    transports: Vec<PluggableTransportEntry>,
}

impl PluggableTransportConfig {
    /// Construct an empty config (no pluggable transports).
    ///
    /// Equivalent to parsing an empty TOML; useful for tests + for
    /// deployments where direct Tor is acceptable.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            transports: Vec::new(),
        }
    }

    /// Return the configured transports in pool order.
    #[must_use]
    pub fn transports(&self) -> &[PluggableTransportEntry] {
        &self.transports
    }

    /// Return the transport at `index`, if present.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&PluggableTransportEntry> {
        self.transports.get(index)
    }

    /// Pool size as a `u8`. The constructor accepts up to `u8::MAX`
    /// entries; larger inputs saturate to `u8::MAX` (which would in
    /// practice never occur — a release with 255 pluggable
    /// transports is operationally absurd).
    #[must_use]
    pub fn len(&self) -> u8 {
        u8::try_from(self.transports.len()).unwrap_or(u8::MAX)
    }

    /// Return `true` if no transports are configured. In that case,
    /// the Arti bootstrap proceeds without bridges.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.transports.is_empty()
    }
}

/// Parse a pluggable-transports config from a TOML config string.
///
/// An empty input is treated as
/// [`PluggableTransportConfig::empty`] (no transports configured).
///
/// # Errors
///
/// - [`TorTransportError::PluggableTransportConfigParse`] for any
///   TOML parse failure, missing required field, or malformed
///   transport entry.
pub fn parse_pluggable_transport_config(
    toml_text: &str,
) -> Result<PluggableTransportConfig, TorTransportError> {
    #[derive(Deserialize, Default)]
    struct Wrapper {
        #[serde(default, rename = "transport")]
        transports: Vec<PluggableTransportEntry>,
    }

    let wrapper: Wrapper =
        toml::from_str(toml_text).map_err(|_| TorTransportError::PluggableTransportConfigParse)?;

    Ok(PluggableTransportConfig {
        transports: wrapper.transports,
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_constructor_is_empty() {
        let cfg = PluggableTransportConfig::empty();
        assert!(cfg.is_empty());
        assert_eq!(cfg.len(), 0);
        assert!(cfg.transports().is_empty());
    }

    #[test]
    fn parse_empty_toml_yields_empty_config() {
        let cfg = parse_pluggable_transport_config("").unwrap();
        assert!(cfg.is_empty());
        assert_eq!(cfg.len(), 0);
    }

    #[test]
    fn parse_three_transports_succeeds() {
        let toml = r#"
            [[transport]]
            name = "obfs4"
            bridge_line = "obfs4 1.2.3.4:443 FINGERPRINT cert=abc iat-mode=0"

            [[transport]]
            name = "webtunnel"
            bridge_line = "webtunnel https://example.org/secret"

            [[transport]]
            name = "snowflake"
            bridge_line = "snowflake fingerprint=def url=https://snow.example.org"
        "#;
        let cfg = parse_pluggable_transport_config(toml).unwrap();
        assert_eq!(cfg.len(), 3);
        assert_eq!(cfg.transports()[0].name, "obfs4");
        assert_eq!(cfg.transports()[1].name, "webtunnel");
        assert_eq!(cfg.transports()[2].name, "snowflake");
        assert!(cfg.transports()[0].bridge_line.starts_with("obfs4 "));
    }

    #[test]
    fn parse_preserves_transport_order() {
        // The transport order in the file is the order the
        // PluggableTransportBootstrapFailed { transport_index }
        // variants correlate against per D0025 §6.
        let toml = r#"
            [[transport]]
            name = "Z-first"
            bridge_line = "z"

            [[transport]]
            name = "A-second"
            bridge_line = "a"
        "#;
        let cfg = parse_pluggable_transport_config(toml).unwrap();
        assert_eq!(cfg.get(0).unwrap().name, "Z-first");
        assert_eq!(cfg.get(1).unwrap().name, "A-second");
    }

    #[test]
    fn parse_malformed_toml_rejects() {
        let result = parse_pluggable_transport_config("not valid toml at all!!!");
        assert!(matches!(
            result,
            Err(TorTransportError::PluggableTransportConfigParse)
        ));
    }

    #[test]
    fn parse_missing_required_field_rejects() {
        // missing `bridge_line`
        let toml = r#"
            [[transport]]
            name = "obfs4"
        "#;
        let result = parse_pluggable_transport_config(toml);
        assert!(matches!(
            result,
            Err(TorTransportError::PluggableTransportConfigParse)
        ));
    }

    #[test]
    fn get_out_of_range_returns_none() {
        let cfg = parse_pluggable_transport_config(
            r#"
            [[transport]]
            name = "obfs4"
            bridge_line = "obfs4 ..."
        "#,
        )
        .unwrap();
        assert!(cfg.get(0).is_some());
        assert!(cfg.get(1).is_none());
        assert!(cfg.get(99).is_none());
    }
}
