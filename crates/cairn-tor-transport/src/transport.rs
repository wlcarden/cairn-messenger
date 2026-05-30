// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Async `TorTransport` surface per D0025 §1 + §5.
//!
//! ## v1 skeleton status
//!
//! The struct + method signatures are defined per the D0025 §1.1
//! API. The network-bound bodies ([`TorTransport::connect`],
//! [`TorTransport::host_onion_service`]) return their typed
//! deferral errors pending the Arti integration body landing per
//! D0025 §10 step 5.
//!
//! What IS implemented + tested in the skeleton:
//!
//! - [`TorTransport::new`] constructor wiring the pluggable-
//!   transport config + the default retry budget.
//! - [`TorTransport::observe_network_state`] real state tracking
//!   per D0025 §4.
//! - [`TorTransport::current_network_state`] + accessor methods.
//! - [`TorTransport::shutdown`] real (no-op in the skeleton since
//!   there is no Arti runtime to wind down; documented to expand
//!   when the body lands).
//!
//! When the network body lands, the [`TorTransport::connect`] body
//! flow per D0025 §1-§5:
//!
//! 1. Bootstrap the Arti client (or reuse the cached bootstrap if
//!    network state is `Online`).
//! 2. Apply the pluggable-transport config per §3.
//! 3. Build a stream to `(target_host, target_port)` via Arti's
//!    `TorClient::connect`.
//! 4. Return the stream as [`TorStream`] (which will expose
//!    `AsyncRead + AsyncWrite` once the body lands).

use std::sync::Mutex;

use cairn_sigsum_client::RetryBudget;

use crate::config::PluggableTransportConfig;
use crate::error::TorTransportError;

/// Network connectivity state observed by the Android shell and
/// signalled to the transport per D0025 §4.
///
/// `#[non_exhaustive]` per D0018 §4.2. The `Constrained` variant is
/// advisory at v1 (the skeleton + initial body treat it as `Online`);
/// v1.5 enhancements may reduce keepalive frequency under
/// constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkState {
    /// Full network connectivity. Bootstrap may run; circuits may
    /// be built and reused.
    Online,
    /// No network connectivity. In-flight circuits drop; bootstrap
    /// retries pause.
    Offline,
    /// Constrained network (e.g., metered cellular). Advisory at v1.
    Constrained,
}

/// Configuration bundle for constructing a [`TorTransport`].
///
/// Builder-pattern is intentional, mirroring D0023 §5's
/// [`cairn_sigsum_client::SigsumClientConfig`].
#[derive(Debug, Clone)]
pub struct TorTransportConfig {
    /// Pluggable-transport config parsed from the release-bundled
    /// `pluggable_transports.toml` per D0025 §3.
    pub pluggable_transports: PluggableTransportConfig,
    /// Default retry budget for outbound + bootstrap operations.
    /// Re-uses the D0023 §5.3 type per D0025 §5.1.
    pub default_retry_budget: RetryBudget,
}

/// An open stream over Tor per D0025 §1.1 + §5.
///
/// In v1 skeleton this type has no public constructor; the only
/// path that constructs a [`TorStream`] is [`TorTransport::connect`],
/// which returns [`TorTransportError::NetworkUnreached`]. The type
/// exists in the public surface so consuming code can name the
/// type's return-type stably across skeleton → implementation
/// transitions.
///
/// When the Arti integration body lands per D0025 §10 step 5,
/// `TorStream` gains `AsyncRead + AsyncWrite` impls + the inner
/// Arti `DataStream`. The public surface API does not change.
#[derive(Debug)]
pub struct TorStream {
    /// Private marker so this type cannot be constructed outside
    /// the crate. The skeleton leaves this empty; the implementation
    /// cycle replaces it with the Arti `DataStream`.
    _private: (),
}

/// Handle for an Arti onion-service host per D0025 §7 (v1.5
/// architectural slot).
///
/// In v1 this type has no public constructor; the only path is
/// [`TorTransport::host_onion_service`], which returns
/// [`TorTransportError::OnionServiceHostingDeferred`].
#[derive(Debug)]
pub struct OnionServiceHandle {
    /// Private marker. See [`TorStream`] for the same skeleton →
    /// implementation pattern.
    _private: (),
}

/// Per-onion-service hosting config per D0025 §7 (v1.5 slot).
///
/// The fields land at v1.5 when the body fills in; for v1, only the
/// type tag is needed so consuming code (a future `cairn-briar-
/// adapter` or equivalent) can compile against the eventual API.
#[derive(Debug, Clone, Default)]
pub struct OnionServiceConfig {
    /// v1: empty; v1.5 fills in with onion-service identity-key
    /// material, virtual-port mappings, etc.
    _v1_5_placeholder: (),
}

/// The async Tor transport handle per D0025 §1 + §5.
///
/// Wraps the pluggable-transport config, the default retry budget,
/// and the observed network state. The Arti client lives behind
/// this handle once the integration body lands; v1 skeleton holds
/// the config + state without an Arti instance.
pub struct TorTransport {
    /// Pluggable-transport config per D0025 §3.
    #[allow(
        dead_code,
        reason = "wired in v1 skeleton; populated for the Arti integration per D0025 §10 step 4"
    )]
    pluggable_transports: PluggableTransportConfig,
    /// Default retry budget per D0025 §5.1 / D0023 §5.3.
    default_retry_budget: RetryBudget,
    /// Currently observed network state per D0025 §4.
    ///
    /// `Mutex<NetworkState>` rather than `Cell<NetworkState>` so the
    /// type stays `Send + Sync` (the Android shell may call
    /// `observe_network_state` from a different thread than the
    /// caller using the transport).
    network_state: Mutex<NetworkState>,
}

impl TorTransport {
    /// Construct a new `TorTransport` from its config bundle.
    ///
    /// v1 skeleton: no Arti runtime is spun up; the constructor
    /// stores the config + initializes network state to
    /// [`NetworkState::Online`].
    ///
    /// When the Arti integration body lands per D0025 §10 step 4,
    /// this constructor will additionally bootstrap the Arti client
    /// in the background; the synchronous return signals only
    /// "config accepted", not "Tor is ready".
    ///
    /// # Errors
    ///
    /// v1 skeleton: never errors (the only failure modes are config-
    /// validation failures that
    /// [`crate::config::parse_pluggable_transport_config`] surfaces
    /// at parse-time, before this constructor is reached).
    ///
    /// When the body lands: may surface
    /// [`TorTransportError::Network`] if Arti's initial setup
    /// fails (e.g., platform TLS configuration).
    pub fn new(config: TorTransportConfig) -> Result<Self, TorTransportError> {
        Ok(Self {
            pluggable_transports: config.pluggable_transports,
            default_retry_budget: config.default_retry_budget,
            network_state: Mutex::new(NetworkState::Online),
        })
    }

    /// Return the default retry budget.
    #[must_use]
    pub const fn default_retry_budget(&self) -> RetryBudget {
        self.default_retry_budget
    }

    /// Return the currently observed network state.
    ///
    /// # Errors
    ///
    /// Returns [`TorTransportError::Network`] with
    /// `retry_budget_used: 0` if the internal mutex was poisoned by
    /// a panicking thread. Per D0025's posture, mutex poisoning
    /// indicates the handle is unusable + the caller should
    /// reconstruct.
    pub fn current_network_state(&self) -> Result<NetworkState, TorTransportError> {
        self.network_state
            .lock()
            .map(|guard| *guard)
            .map_err(|_| TorTransportError::Network {
                retry_budget_used: 0,
            })
    }

    /// Signal a network-state transition per D0025 §4.
    ///
    /// Idempotent: calling with the current state is a no-op.
    /// Transitions execute on edge changes; v1 skeleton tracks state
    /// only (no behavioral side effects), the implementation cycle
    /// adds the bootstrap-retry-pause + circuit-drop logic per
    /// D0025 §4.1.
    ///
    /// # Errors
    ///
    /// Returns [`TorTransportError::Network`] with
    /// `retry_budget_used: 0` if the internal mutex was poisoned.
    pub fn observe_network_state(&self, new_state: NetworkState) -> Result<(), TorTransportError> {
        let mut guard = self
            .network_state
            .lock()
            .map_err(|_| TorTransportError::Network {
                retry_budget_used: 0,
            })?;
        *guard = new_state;
        // Explicit drop per clippy::significant_drop_in_scrutinee —
        // the MutexGuard's Drop is observable (releases the lock).
        drop(guard);
        Ok(())
    }

    /// Build an outbound stream to `(target_host, target_port)` over
    /// Tor per D0025 §2.1.
    ///
    /// `target_host` is either a hostname (resolved over Tor via
    /// Arti's DNS-over-Tor) or an `.onion` v3 address. The returned
    /// [`TorStream`] is circuit-isolated (Arti's per-stream
    /// isolation default per D0025 §2.3).
    ///
    /// v1 skeleton: returns [`TorTransportError::NetworkUnreached`]
    /// pending the Arti integration body.
    ///
    /// # Errors
    ///
    /// - [`TorTransportError::NetworkUnreached`] (skeleton only;
    ///   replaced by the layered failure modes once the body lands
    ///   — [`TorTransportError::BootstrapFailed`],
    ///   [`TorTransportError::HostResolutionFailed`],
    ///   [`TorTransportError::ConnectionRefused`],
    ///   [`TorTransportError::Network`])
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton; Arti integration body lands per D0025 §10 step 5"
    )]
    pub async fn connect(
        &self,
        _target_host: &str,
        _target_port: u16,
        _retry_budget: RetryBudget,
    ) -> Result<TorStream, TorTransportError> {
        Err(TorTransportError::NetworkUnreached)
    }

    /// Host an onion service per D0025 §7 (v1.5 architectural slot).
    ///
    /// v1 skeleton + v1 implementation cycle: returns
    /// [`TorTransportError::OnionServiceHostingDeferred`]. The
    /// method signature is shipped at v1 so consuming code (a
    /// future `cairn-briar-adapter` or equivalent) can compile
    /// against the same `TorTransport` handle without
    /// restructuring; v1.5 D-doc fills in the body.
    ///
    /// # Errors
    ///
    /// - [`TorTransportError::OnionServiceHostingDeferred`] at v1.
    /// - When v1.5 lands: the layered set per D0025 §7's body
    ///   specification.
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton + v1 implementation cycle; body lands at v1.5 per D0025 §7"
    )]
    pub async fn host_onion_service(
        &self,
        _config: OnionServiceConfig,
    ) -> Result<OnionServiceHandle, TorTransportError> {
        Err(TorTransportError::OnionServiceHostingDeferred)
    }

    /// Shut the transport down cleanly per D0025 §5.2.
    ///
    /// v1 skeleton: no-op (there is no Arti runtime to wind down).
    /// When the body lands, this method drops in-flight circuits,
    /// stops the bootstrap state machine, and releases the
    /// underlying Arti `TorClient`.
    ///
    /// # Errors
    ///
    /// v1 skeleton: never errors. When the body lands: may surface
    /// [`TorTransportError::Network`] if a clean shutdown could not
    /// complete within the retry budget.
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton; body lands with the Arti integration per D0025 §10 step 5"
    )]
    pub async fn shutdown(&self) -> Result<(), TorTransportError> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::parse_pluggable_transport_config;

    fn make_transport_with_pt(count: usize) -> TorTransport {
        let mut toml = String::new();
        for i in 0..count {
            toml.push_str(&format!(
                "[[transport]]\nname = \"obfs4-{i}\"\nbridge_line = \"obfs4 1.2.3.{i}:443 FP cert=c iat-mode=0\"\n\n"
            ));
        }
        let pluggable_transports = parse_pluggable_transport_config(&toml).unwrap();
        let config = TorTransportConfig {
            pluggable_transports,
            default_retry_budget: RetryBudget::default(),
        };
        TorTransport::new(config).unwrap()
    }

    #[test]
    fn transport_construction_succeeds_with_no_pluggable_transports() {
        let config = TorTransportConfig {
            pluggable_transports: PluggableTransportConfig::empty(),
            default_retry_budget: RetryBudget::default(),
        };
        let _transport = TorTransport::new(config).unwrap();
    }

    #[test]
    fn transport_construction_succeeds_with_three_pluggable_transports() {
        let _transport = make_transport_with_pt(3);
    }

    #[test]
    fn transport_exposes_default_retry_budget() {
        let transport = make_transport_with_pt(0);
        let budget = transport.default_retry_budget();
        assert_eq!(budget.max_retries, RetryBudget::default().max_retries);
    }

    #[test]
    fn initial_network_state_is_online() {
        let transport = make_transport_with_pt(0);
        assert_eq!(
            transport.current_network_state().unwrap(),
            NetworkState::Online
        );
    }

    #[test]
    fn observe_network_state_updates_state() {
        let transport = make_transport_with_pt(0);

        transport
            .observe_network_state(NetworkState::Offline)
            .unwrap();
        assert_eq!(
            transport.current_network_state().unwrap(),
            NetworkState::Offline
        );

        transport
            .observe_network_state(NetworkState::Online)
            .unwrap();
        assert_eq!(
            transport.current_network_state().unwrap(),
            NetworkState::Online
        );

        transport
            .observe_network_state(NetworkState::Constrained)
            .unwrap();
        assert_eq!(
            transport.current_network_state().unwrap(),
            NetworkState::Constrained
        );
    }

    #[test]
    fn observe_network_state_is_idempotent() {
        let transport = make_transport_with_pt(0);

        transport
            .observe_network_state(NetworkState::Online)
            .unwrap();
        transport
            .observe_network_state(NetworkState::Online)
            .unwrap();
        assert_eq!(
            transport.current_network_state().unwrap(),
            NetworkState::Online
        );
    }

    #[tokio::test]
    async fn connect_returns_network_unreached_in_skeleton() {
        let transport = make_transport_with_pt(0);
        let result = transport
            .connect("example.org", 443, RetryBudget::default())
            .await;
        assert!(matches!(result, Err(TorTransportError::NetworkUnreached)));
    }

    #[tokio::test]
    async fn connect_returns_network_unreached_even_with_onion_target() {
        let transport = make_transport_with_pt(0);
        let result = transport
            .connect(
                "abcdefghijklmnop1234567890.onion",
                443,
                RetryBudget::default(),
            )
            .await;
        assert!(matches!(result, Err(TorTransportError::NetworkUnreached)));
    }

    #[tokio::test]
    async fn host_onion_service_returns_deferred_in_v1() {
        let transport = make_transport_with_pt(0);
        let result = transport
            .host_onion_service(OnionServiceConfig::default())
            .await;
        assert!(matches!(
            result,
            Err(TorTransportError::OnionServiceHostingDeferred)
        ));
    }

    #[tokio::test]
    async fn shutdown_succeeds_in_skeleton() {
        let transport = make_transport_with_pt(0);
        transport.shutdown().await.unwrap();
    }
}
