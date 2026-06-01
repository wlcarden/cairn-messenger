// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Async `TorTransport` surface per D0025 §1 + §5 (re-anchored under
//! D0020 §2: the Rust-side SOCKS5 + control-port client of the C-Tor
//! `ForegroundService`).
//!
//! ## Implementation status
//!
//! [`TorTransport::connect`] is **implemented**: it opens a real SOCKS5
//! CONNECT tunnel through the C-Tor proxy (hand-rolled client in
//! `crate::socks5`, D0025 §2 / §10), setting the `IsolateSOCKSAuth`
//! username/password = `hex(SHA-256(conversation_id))` per D0020 §2.6 and
//! sending the target as a SOCKS5 domain (resolved over Tor, never
//! locally). The returned [`TorStream`] is `AsyncRead + AsyncWrite` over
//! the tunnel. Only the loopback proxy connect is retried within the
//! budget; SOCKS reply codes map to the typed surface (host-unreachable →
//! [`TorTransportError::HostResolutionFailed`], refused →
//! [`TorTransportError::ConnectionRefused`], other/auth/framing →
//! [`TorTransportError::SocksProtocol`]). Validated by
//! `tests/socks5_connect.rs` against a hermetic mock SOCKS5 server.
//!
//! Also implemented + tested:
//!
//! - [`TorTransport::new`] wiring the bridge manifest, the default retry
//!   budget, and the SOCKS proxy address (default `127.0.0.1:9050`;
//!   overridable via [`TorTransport::with_socks_proxy_addr`]).
//! - [`TorTransport::observe_network_state`] +
//!   [`TorTransport::current_network_state`] state tracking per D0025 §4.
//! - [`TorTransport::shutdown`] (no-op: a [`TorStream`] owns its tunnel,
//!   so there is no transport-held connection to close until the
//!   control-port client lands).
//!
//! Remaining follow-ups (separate from `connect`):
//!
//! - The control-port client (`127.0.0.1:9051`, cookie auth) for
//!   `SIGNAL NEWNYM` on `Offline → Online` (D0025 §4) + bootstrap-status
//!   queries (which would let `connect` surface
//!   [`TorTransportError::BootstrapIncomplete`] precisely rather than as
//!   a generic SOCKS failure).
//! - [`TorTransport::host_onion_service`] (`ADD_ONION`), a v1.5 slot per
//!   D0025 §7 / D0020 §2.8.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

use cairn_sigsum_client::RetryBudget;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::config::BridgeManifest;
use crate::error::TorTransportError;
use crate::socks5::{self, Socks5Error};

/// Default C-Tor SOCKS proxy loopback port per D0020 §2 (`127.0.0.1:9050`).
const DEFAULT_SOCKS_PROXY_PORT: u16 = 9050;

/// Network connectivity state observed by the Android shell and
/// signalled to the transport per D0025 §4.
///
/// `#[non_exhaustive]` per D0018 §4.2. The `Constrained` variant is
/// advisory at v1 (the skeleton + initial body treat it as `Online`);
/// v1.5 enhancements may reduce keepalive frequency under constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkState {
    /// Full network connectivity. Circuits may be built + reused.
    Online,
    /// No network connectivity. In-flight circuits drop; connect
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
    /// Bridge manifest per D0025 §3 / D0020 §2.4. The manifest is
    /// already-verified (signature + witness cosignatures checked
    /// upstream via D0024 + D0023); this crate consumes the parsed
    /// form.
    pub bridge_manifest: BridgeManifest,
    /// Default retry budget for outbound + control-port operations.
    /// Re-uses the D0023 §5.3 type per D0025 §5.1.
    pub default_retry_budget: RetryBudget,
}

/// An open stream over Tor per D0025 §1.1 + §5 — the SOCKS5 tunnel to a
/// target through the C-Tor proxy.
///
/// Implements `AsyncRead + AsyncWrite` by delegating to the underlying
/// SOCKS5-tunneled [`TcpStream`]. No TLS is layered here (D0025 §5.1):
/// SimpleX carries its own E2EE and the SMP server's TLS is SimplOxide's
/// concern. The only constructor is [`TorTransport::connect`]; the
/// private field keeps `TorStream` un-constructable outside the crate.
#[derive(Debug)]
pub struct TorStream {
    inner: TcpStream,
}

impl TorStream {
    /// Wrap an established SOCKS5-tunneled TCP stream. Crate-private; the
    /// only public path is [`TorTransport::connect`].
    pub(crate) const fn new(inner: TcpStream) -> Self {
        Self { inner }
    }
}

impl AsyncRead for TorStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TorStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Handle for a C-Tor-hosted onion service per D0025 §7 / D0020 §2.8
/// (v1.5 architectural slot; `ADD_ONION` via control-port).
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
/// The fields land at v1.5 when the `ADD_ONION` body fills in; for
/// v1, only the type tag is needed so consuming code can compile
/// against the eventual API.
#[derive(Debug, Clone, Default)]
pub struct OnionServiceConfig {
    /// v1: empty; v1.5 fills in with onion-service key material +
    /// virtual-port mappings for the `ADD_ONION` control-port command.
    _v1_5_placeholder: (),
}

/// The async Tor transport handle per D0025 §1 + §5.
///
/// Wraps the bridge manifest, the default retry budget, and the
/// observed network state. The SOCKS5 + control-port connections to
/// the C-Tor `ForegroundService` live behind this handle once the
/// integration body lands; v1 skeleton holds the config + state
/// without live connections.
pub struct TorTransport {
    /// Bridge manifest per D0025 §3 / D0020 §2.4.
    #[allow(
        dead_code,
        reason = "wired in v1 skeleton; populated for the C-Tor control-port bridge launch per D0025 §10"
    )]
    bridge_manifest: BridgeManifest,
    /// Default retry budget per D0025 §5.1 / D0023 §5.3.
    default_retry_budget: RetryBudget,
    /// Loopback address of the C-Tor SOCKS proxy. Defaults to
    /// `127.0.0.1:9050` (D0020 §2); overridable via
    /// [`TorTransport::with_socks_proxy_addr`] (used by tests to point at
    /// a mock SOCKS5 server).
    socks_proxy_addr: SocketAddr,
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
    /// v1 skeleton: no SOCKS5 / control-port connections are opened;
    /// the constructor stores the config + initializes network state
    /// to [`NetworkState::Online`].
    ///
    /// When the body lands per D0025 §10, this constructor will
    /// additionally establish the control-port connection (cookie
    /// auth) to the C-Tor `ForegroundService`; the synchronous return
    /// signals only "config accepted", not "Tor is bootstrapped".
    ///
    /// # Errors
    ///
    /// v1 skeleton: never errors (config-validation failures surface
    /// at [`crate::config::parse_bridge_manifest`] parse-time, before
    /// this constructor is reached).
    ///
    /// When the body lands: may surface
    /// [`TorTransportError::Network`] if the control-port connection
    /// to the C-Tor service cannot be established.
    pub fn new(config: TorTransportConfig) -> Result<Self, TorTransportError> {
        Ok(Self {
            bridge_manifest: config.bridge_manifest,
            default_retry_budget: config.default_retry_budget,
            socks_proxy_addr: SocketAddr::from(([127, 0, 0, 1], DEFAULT_SOCKS_PROXY_PORT)),
            network_state: Mutex::new(NetworkState::Online),
        })
    }

    /// Override the C-Tor SOCKS proxy address.
    ///
    /// Production uses the `127.0.0.1:9050` default per D0020 §2; this
    /// builder lets tests point `connect` at a mock SOCKS5 server. The
    /// control-port address is independent (a v1.5 follow-up).
    #[must_use]
    pub const fn with_socks_proxy_addr(mut self, addr: SocketAddr) -> Self {
        self.socks_proxy_addr = addr;
        self
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
    /// `retry_budget_used: 0` if the internal mutex was poisoned by a
    /// panicking thread. Per D0025's posture, mutex poisoning
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
    /// only (no behavioral side effects). The implementation cycle
    /// adds the `SIGNAL NEWNYM` control-port command + connect-retry-
    /// pause per D0025 §4.1 / D0020 §2.9.
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

    /// Open an outbound SOCKS5 stream to `(target_host, target_port)`
    /// through the C-Tor proxy per D0025 §2.1.
    ///
    /// `conversation_id` is hashed into the SOCKS5 username/password
    /// (`hex(SHA-256(conversation_id))`) with `IsolateSOCKSAuth` per
    /// D0020 §2.6, so different conversations do not share Tor circuits at
    /// the network layer. `target_host` is the SMP queue server's
    /// hostname / `.onion` address — sent as a SOCKS5 domain target so it
    /// resolves THROUGH Tor, never locally.
    ///
    /// Only the loopback connect to the C-Tor proxy is retried within
    /// `retry_budget`; a completed-but-rejected SOCKS handshake is
    /// terminal (retrying would not change the outcome).
    ///
    /// # Errors
    ///
    /// - [`TorTransportError::Network`] — the loopback connect to the
    ///   C-Tor proxy (or a mid-handshake read/write) failed after the
    ///   retry budget; `retry_budget_used` names the retries consumed.
    /// - [`TorTransportError::HostResolutionFailed`] — the target did not
    ///   resolve / route over Tor (SOCKS reply `0x04`), or the host
    ///   exceeds the 255-byte SOCKS domain field.
    /// - [`TorTransportError::ConnectionRefused`] — the target refused the
    ///   connection (SOCKS reply `0x05`).
    /// - [`TorTransportError::SocksProtocol`] — the proxy rejected
    ///   username/password auth, failed RFC 1929 auth, returned another
    ///   CONNECT reply code, or sent malformed framing.
    pub async fn connect(
        &self,
        conversation_id: &[u8],
        target_host: &str,
        target_port: u16,
        retry_budget: RetryBudget,
    ) -> Result<TorStream, TorTransportError> {
        let credential = socks5::isolation_credential(conversation_id);
        let mut delay = retry_budget.initial_delay;
        let mut attempt: u8 = 0;
        loop {
            match socks5::connect_through_proxy(
                self.socks_proxy_addr,
                &credential,
                target_host,
                target_port,
            )
            .await
            {
                Ok(stream) => return Ok(TorStream::new(stream)),
                // Only a loopback transport failure is retryable; a
                // completed SOCKS handshake that rejected the request is
                // terminal.
                Err(Socks5Error::Transport) if attempt < retry_budget.max_retries => {}
                Err(e) => return Err(map_socks5_error(&e, attempt)),
            }
            tokio::time::sleep(delay).await;
            delay = delay.saturating_mul(2).min(retry_budget.max_delay);
            attempt = attempt.saturating_add(1);
        }
    }

    /// Host an onion service per D0025 §7 / D0020 §2.8 (v1.5
    /// architectural slot; `ADD_ONION` via control-port).
    ///
    /// v1 skeleton + v1 implementation cycle: returns
    /// [`TorTransportError::OnionServiceHostingDeferred`]. The method
    /// signature is shipped at v1 so consuming code (a future
    /// `cairn-briar-adapter` or the release-distribution surface) can
    /// compile against the same `TorTransport` handle without
    /// restructuring; v1.5 fills in the body via the control-port
    /// client this crate already owns.
    ///
    /// # Errors
    ///
    /// - [`TorTransportError::OnionServiceHostingDeferred`] at v1.
    /// - When v1.5 lands: the layered set per D0020 §2.8's `ADD_ONION`
    ///   flow.
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton + v1 implementation cycle; body lands at v1.5 per D0025 §7 / D0020 §2.8"
    )]
    pub async fn host_onion_service(
        &self,
        _config: OnionServiceConfig,
    ) -> Result<OnionServiceHandle, TorTransportError> {
        Err(TorTransportError::OnionServiceHostingDeferred)
    }

    /// Shut the transport down cleanly per D0025 §5.2.
    ///
    /// v1 skeleton: no-op (there are no live connections). When the
    /// body lands, this method closes the SOCKS5 streams + the
    /// control-port connection. It does NOT stop the C-Tor
    /// `ForegroundService` — that is the Android shell's job per
    /// D0020 §2.5.
    ///
    /// # Errors
    ///
    /// v1 skeleton: never errors. When the body lands: may surface
    /// [`TorTransportError::Network`] if a clean control-port
    /// teardown could not complete within the retry budget.
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton; body lands with the SOCKS5 + control-port client per D0025 §10"
    )]
    pub async fn shutdown(&self) -> Result<(), TorTransportError> {
        Ok(())
    }
}

/// Map an internal [`Socks5Error`] onto the public typed error surface
/// per D0025 §6. `attempt` is the retry count consumed (only meaningful
/// for the transport-failure case).
const fn map_socks5_error(err: &Socks5Error, attempt: u8) -> TorTransportError {
    match err {
        Socks5Error::Transport => TorTransportError::Network {
            retry_budget_used: attempt,
        },
        // Host-unreachable means the target did not resolve/route over
        // Tor; an over-long host cannot be addressed at all.
        Socks5Error::HostUnreachable | Socks5Error::TargetHostTooLong => {
            TorTransportError::HostResolutionFailed
        }
        Socks5Error::ConnectionRefused => TorTransportError::ConnectionRefused,
        Socks5Error::AuthMethodRejected | Socks5Error::AuthFailed | Socks5Error::Protocol => {
            TorTransportError::SocksProtocol
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::parse_bridge_manifest;

    fn make_transport_with_bridges(count: usize) -> TorTransport {
        let mut toml = String::new();
        for i in 0..count {
            toml.push_str(&format!(
                "[[bridge]]\nname = \"obfs4-{i}\"\nbridge_line = \"obfs4 1.2.3.{i}:443 FP cert=c iat-mode=0\"\n\n"
            ));
        }
        let bridge_manifest = parse_bridge_manifest(&toml).unwrap();
        let config = TorTransportConfig {
            bridge_manifest,
            default_retry_budget: RetryBudget::default(),
        };
        TorTransport::new(config).unwrap()
    }

    #[test]
    fn transport_construction_succeeds_with_no_bridges() {
        let config = TorTransportConfig {
            bridge_manifest: BridgeManifest::empty(),
            default_retry_budget: RetryBudget::default(),
        };
        let _transport = TorTransport::new(config).unwrap();
    }

    #[test]
    fn transport_construction_succeeds_with_three_bridges() {
        let _transport = make_transport_with_bridges(3);
    }

    #[test]
    fn transport_exposes_default_retry_budget() {
        let transport = make_transport_with_bridges(0);
        let budget = transport.default_retry_budget();
        assert_eq!(budget.max_retries, RetryBudget::default().max_retries);
    }

    #[test]
    fn initial_network_state_is_online() {
        let transport = make_transport_with_bridges(0);
        assert_eq!(
            transport.current_network_state().unwrap(),
            NetworkState::Online
        );
    }

    #[test]
    fn observe_network_state_updates_state() {
        let transport = make_transport_with_bridges(0);

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
        let transport = make_transport_with_bridges(0);

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
    async fn connect_to_unreachable_proxy_surfaces_network() {
        // No C-Tor proxy at 127.0.0.1:1; with a zero-retry budget the
        // single loopback connect attempt fails fast →
        // Network{retry_budget_used: 0}. The happy path + SOCKS reply-code
        // mapping are covered in tests/socks5_connect.rs against a mock
        // SOCKS5 server.
        let transport = make_transport_with_bridges(0)
            .with_socks_proxy_addr(SocketAddr::from(([127, 0, 0, 1], 1)));
        let budget = RetryBudget {
            max_retries: 0,
            initial_delay: std::time::Duration::from_millis(1),
            max_delay: std::time::Duration::from_millis(1),
        };
        let result = transport
            .connect(b"conversation-1", "example.org", 443, budget)
            .await;
        assert!(
            matches!(
                result,
                Err(TorTransportError::Network {
                    retry_budget_used: 0
                })
            ),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn host_onion_service_returns_deferred_in_v1() {
        let transport = make_transport_with_bridges(0);
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
        let transport = make_transport_with_bridges(0);
        transport.shutdown().await.unwrap();
    }
}
