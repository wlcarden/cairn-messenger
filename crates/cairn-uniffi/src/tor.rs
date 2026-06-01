// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Tor transport export surface (D0027 §2 — the `tor` module).
//!
//! [`TorTransportHandle`] exposes the C-Tor **control plane** the Android
//! shell needs to drive + display Tor status: observe OS network-state
//! changes (which trigger `SIGNAL NEWNYM` on the Offline→Online edge),
//! request fresh circuits, and read the bootstrap percentage. The async
//! ops export as Kotlin `suspend fun`s (`#[uniffi::export(async_runtime =
//! "tokio")]` per D0027 §5).
//!
//! ## Why no `connect`
//!
//! `cairn_tor_transport::TorTransport::connect` returns a `TorStream`
//! (an `AsyncRead + AsyncWrite` SOCKS5 tunnel). That is data-plane
//! plumbing consumed Rust-side by the messaging adapter — not something
//! the Kotlin shell drives byte-by-byte. So this handle exposes only the
//! control plane; raw stream I/O does not cross the FFI. (If a future
//! need arises, `connect` would return an opaque `TorStream` Object with
//! async read/write methods.)

use std::path::PathBuf;
use std::sync::Arc;

use cairn_tor_transport::{
    NetworkState, RetryBudget, TorTransport, TorTransportConfig, parse_bridge_manifest,
};

use crate::error::CairnFfiError;

/// FFI mirror of `cairn_tor_transport::NetworkState` (D0027 §2.2) — the
/// OS-reported connectivity the shell feeds to the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Enum))]
pub enum NetworkStateFfi {
    /// Full connectivity; circuits may be built + reused.
    Online,
    /// No connectivity; in-flight circuits drop.
    Offline,
    /// Constrained connectivity (e.g. metered cellular); advisory.
    Constrained,
}

impl From<NetworkStateFfi> for NetworkState {
    fn from(state: NetworkStateFfi) -> Self {
        match state {
            NetworkStateFfi::Online => Self::Online,
            NetworkStateFfi::Offline => Self::Offline,
            NetworkStateFfi::Constrained => Self::Constrained,
        }
    }
}

/// Configuration for the Tor control-plane handle (D0027 §2.2).
///
/// All public values. The control-port + SOCKS addresses use the C-Tor
/// loopback defaults (127.0.0.1:9051 / :9050 per D0020 §2); only the
/// SAFECOOKIE auth-cookie path is shell-supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct TorControlConfig {
    /// The already-verified bridge manifest as TOML text (parsed
    /// Rust-side). Empty is valid (no bridges).
    pub bridge_manifest_toml: String,
    /// Filesystem path to the C-Tor control-port SAFECOOKIE auth cookie.
    /// `None` ⇒ control-port commands are no-ops (the handle just tracks
    /// network state) per D0025 §4.1.
    pub control_cookie_path: Option<String>,
    /// Maximum control-port retry attempts (backoff uses the D0025 §5.1
    /// defaults).
    pub max_retries: u8,
}

/// An opaque async handle to the C-Tor control plane (D0027 §2.2).
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Object))]
pub struct TorTransportHandle {
    transport: TorTransport,
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
impl TorTransportHandle {
    /// Construct the control-plane handle from `config`.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `bridge_manifest_toml` is not
    ///   well-formed.
    /// - [`CairnFfiError::TorConnectionFailed`] /
    ///   [`CairnFfiError::TorBootstrapIncomplete`] if the transport cannot
    ///   be constructed.
    #[cfg_attr(feature = "uniffi-bindings", uniffi::constructor)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI constructors take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub fn new(config: TorControlConfig) -> Result<Arc<Self>, CairnFfiError> {
        let bridge_manifest = parse_bridge_manifest(&config.bridge_manifest_toml)
            .map_err(|_| CairnFfiError::MalformedData)?;
        let mut transport = TorTransport::new(TorTransportConfig {
            bridge_manifest,
            default_retry_budget: RetryBudget {
                max_retries: config.max_retries,
                ..RetryBudget::default()
            },
        })
        .map_err(CairnFfiError::from)?;
        if let Some(path) = config.control_cookie_path {
            transport = transport.with_control_cookie_path(PathBuf::from(path));
        }
        Ok(Arc::new(Self { transport }))
    }
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export(async_runtime = "tokio"))]
impl TorTransportHandle {
    /// Report the OS-observed network state. On the Offline→Online edge
    /// this issues `SIGNAL NEWNYM` (fresh circuits) per D0025 §4.1.
    ///
    /// # Errors
    ///
    /// [`CairnFfiError::TorConnectionFailed`] if the control-port NEWNYM
    /// side effect fails.
    pub async fn observe_network_state(&self, state: NetworkStateFfi) -> Result<(), CairnFfiError> {
        self.transport
            .observe_network_state(state.into())
            .await
            .map_err(CairnFfiError::from)
    }

    /// Request fresh Tor circuits (`SIGNAL NEWNYM`). A no-op when no
    /// control cookie is configured.
    ///
    /// # Errors
    ///
    /// [`CairnFfiError::TorConnectionFailed`] if the control-port command
    /// fails (connection / SAFECOOKIE auth / rejection).
    pub async fn signal_newnym(&self) -> Result<(), CairnFfiError> {
        self.transport
            .signal_newnym()
            .await
            .map_err(CairnFfiError::from)
    }

    /// Read the Tor bootstrap percentage (0–100) via the control port.
    ///
    /// # Errors
    ///
    /// [`CairnFfiError::TorConnectionFailed`] /
    /// [`CairnFfiError::TorBootstrapIncomplete`] if the control-port
    /// query fails.
    pub async fn bootstrap_phase(&self) -> Result<u8, CairnFfiError> {
        self.transport
            .bootstrap_phase()
            .await
            .map_err(CairnFfiError::from)
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests assert on known-shape fixtures; index/unwrap panics ARE the failure signal"
)]
mod tests {
    use super::*;

    fn handle_without_cookie() -> Arc<TorTransportHandle> {
        TorTransportHandle::new(TorControlConfig {
            bridge_manifest_toml: String::new(),
            control_cookie_path: None,
            max_retries: 0,
        })
        .unwrap()
    }

    #[test]
    fn network_state_mapping_is_total() {
        assert_eq!(
            NetworkState::from(NetworkStateFfi::Online),
            NetworkState::Online
        );
        assert_eq!(
            NetworkState::from(NetworkStateFfi::Offline),
            NetworkState::Offline
        );
        assert_eq!(
            NetworkState::from(NetworkStateFfi::Constrained),
            NetworkState::Constrained
        );
    }

    #[test]
    fn malformed_bridge_manifest_maps_to_malformed_data() {
        // `matches!` rather than `.unwrap_err()` — the latter needs the
        // Ok type (`Arc<TorTransportHandle>`) to be `Debug`, and the
        // opaque Object intentionally is not.
        let result = TorTransportHandle::new(TorControlConfig {
            bridge_manifest_toml: "this is [ not valid toml".to_string(),
            control_cookie_path: None,
            max_retries: 0,
        });
        assert!(matches!(result, Err(CairnFfiError::MalformedData)));
    }

    #[tokio::test]
    async fn control_ops_without_cookie_are_noops() {
        // With no control cookie, signal_newnym + observe_network_state
        // are no-ops (Ok) — this exercises the async export bridge
        // (tokio runtime + await + state mapping) without a live control
        // port. The real control-port I/O is tested in
        // cairn-tor-transport's control_port.rs harness.
        let handle = handle_without_cookie();
        handle.signal_newnym().await.unwrap();
        handle
            .observe_network_state(NetworkStateFfi::Online)
            .await
            .unwrap();
        handle
            .observe_network_state(NetworkStateFfi::Offline)
            .await
            .unwrap();
    }
}
