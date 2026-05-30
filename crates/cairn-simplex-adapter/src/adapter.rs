// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Async `SimplexAdapter` surface per D0026 §1 + §7 (re-anchored under
//! D0020 §1: the SimplOxide-client-over-CLI-sidecar model).
//!
//! ## The Transport seam (D0020 §1.10)
//!
//! `SimplexAdapter` exposes the four operations the D0020 §1.10
//! `cairn-transport::Transport` trait abstracts:
//!
//! - [`SimplexAdapter::create_invitation`] — create an identifier-less
//!   queue + return an out-of-band invitation.
//! - [`SimplexAdapter::accept_invitation`] — complete the out-of-band
//!   pairing.
//! - [`SimplexAdapter::send`] — send a payload over an established
//!   connection (SimpleX provides the FS + post-compromise security).
//! - [`SimplexAdapter::recv`] — receive the next payload.
//!
//! The `cairn-transport` trait itself lives in a (not-yet-created)
//! shared crate per D0020 §1.10; until it lands, `SimplexAdapter`
//! exposes these as inherent methods with the same shape, and will
//! `impl Transport` for `SimplexAdapter` once the trait crate exists.
//! The four-method shape is the seam that admits the v1.5 Briar
//! adapter without disturbing `cairn-crypto` / `cairn-envelope` /
//! `cairn-trust-graph` / `cairn-recovery`.
//!
//! ## What rides over the seam
//!
//! The `payload` in `send` / `recv` is Cairn's signed + padded
//! message envelope (per [`crate::envelope`] + [`crate::padding`]).
//! SimplOxide owns the SMP wire protocol, the PQ double-ratchet
//! (forward secrecy + post-compromise security), the queue lifecycle,
//! and the invitation flow.
//!
//! ## v1 skeleton status
//!
//! The struct + method signatures are defined per the D0026 §7 API.
//! The network-bound bodies return
//! [`SimplexAdapterError::NetworkUnreached`] pending the SimplOxide-
//! client body landing per D0026 §12 step 5.
//!
//! What IS implemented + tested in the skeleton:
//!
//! - [`SimplexAdapter::new`] constructor wiring the sidecar endpoint +
//!   the `Storage` handle + the default retry budget.
//! - Accessor methods.

use std::sync::Arc;

use cairn_sigsum_client::RetryBudget;
use cairn_storage::Storage;

use crate::error::SimplexAdapterError;

/// Loopback endpoint of the SimpleX Chat CLI sidecar per D0020 §1.1.
///
/// Default `127.0.0.1:5225`. The `ForegroundService` (Android-shell
/// concern per D0020 §1.6) spawns the CLI bound to this port; the
/// adapter is the WebSocket client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarEndpoint {
    /// Loopback host (default `127.0.0.1`).
    pub host: String,
    /// Loopback port (default `5225`).
    pub port: u16,
}

impl Default for SidecarEndpoint {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 5225,
        }
    }
}

/// An out-of-band invitation per the D0020 §1.10 `Transport` seam.
///
/// SimpleX produces an invitation URI when a new identifier-less
/// queue is created; the peer scans/pastes it to pair. The adapter
/// carries it as an opaque string (the URI format is SimpleX's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    /// The SimpleX invitation URI (opaque at the Cairn layer).
    pub uri: String,
}

/// An established connection handle per the D0020 §1.10 seam.
///
/// Opaque identifier the sidecar assigns to a paired connection;
/// Cairn correlates its per-`(sender, recipient)` envelope chains
/// against it but does not interpret its internal structure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub String);

/// Configuration bundle for constructing a [`SimplexAdapter`].
///
/// Builder-pattern is intentional, mirroring D0023's
/// [`cairn_sigsum_client::SigsumClientConfig`].
///
/// Note: this type does NOT derive `Debug` because [`Storage`] does
/// not (it owns a poisoned-mutex-guarded SQLite connection). The
/// fields are operational handles, not secrets.
pub struct SimplexAdapterConfig {
    /// The CLI sidecar loopback endpoint per D0020 §1.1.
    pub sidecar_endpoint: SidecarEndpoint,
    /// Storage handle for Cairn's `MESSAGES` history per D0026 §4.
    /// Shared via `Arc` so the adapter + the Android-shell concurrent
    /// surfaces share the same SQLite connection per D0022's single-
    /// writer discipline.
    pub storage: Arc<Storage>,
    /// Default retry budget per D0026 §7 / D0023 §5.3.
    pub default_retry_budget: RetryBudget,
}

/// Outcome of a successful [`SimplexAdapter::send`] call.
///
/// In the v1 skeleton this type is only constructed by the body that
/// does not yet land; the type exists so the public API is stable
/// from skeleton through implementation.
#[derive(Debug, Clone)]
pub struct MessageSent {
    /// The 32-byte record id under which the sent message was
    /// persisted in [`cairn_storage::categories::MESSAGES`].
    pub record_id: [u8; 32],
    /// The next message number the Cairn envelope chain advanced to.
    pub next_message_number: u64,
}

/// One received message per [`SimplexAdapter::recv`].
///
/// Decoded + verified per D0026 §2.3's signature + AAD discipline.
/// The body returns these once the SimplOxide-client surface lands;
/// the v1 skeleton's `recv` returns `Err(NetworkUnreached)` without
/// constructing this type.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// Sender's operational identity per D0026 §2.1 key 2.
    pub sender_operational_pubkey: [u8; 32],
    /// Application-level payload per D0026 §2.1 key 6 (padding
    /// stripped on receive).
    pub payload: Vec<u8>,
    /// Receive-side wall-clock timestamp.
    pub received_at_unix: u64,
}

/// The async Cairn SimpleX adapter per D0026 §7.
///
/// A WebSocket client of the SimpleX Chat CLI sidecar + an envelope-
/// construction/parse layer. It is NOT a protocol implementation —
/// SimplOxide / the CLI sidecar own the SMP wire + the PQ ratchet per
/// D0026 §1.3. The adapter's security-critical surface is exactly:
/// constructing + signing the Cairn envelope, padding it, verifying
/// inbound envelopes, and the typed error surface.
pub struct SimplexAdapter {
    /// The CLI sidecar loopback endpoint per D0020 §1.1.
    #[allow(
        dead_code,
        reason = "wired in v1 skeleton; populated for the SimplOxide WebSocket client per D0026 §12 step 5"
    )]
    sidecar_endpoint: SidecarEndpoint,
    /// Storage handle for Cairn's `MESSAGES` history.
    #[allow(
        dead_code,
        reason = "wired in v1 skeleton; populated for message-history persistence"
    )]
    storage: Arc<Storage>,
    /// Default retry budget per D0026 §7.
    default_retry_budget: RetryBudget,
}

impl SimplexAdapter {
    /// Construct a new `SimplexAdapter` from its config bundle.
    ///
    /// v1 skeleton: no WebSocket connection is opened; the constructor
    /// stores the config + handles for use when the body lands.
    ///
    /// # Errors
    ///
    /// v1 skeleton: never errors. When the body lands: may surface
    /// [`SimplexAdapterError::SidecarUnavailable`] if the initial
    /// WebSocket handshake to the CLI sidecar fails.
    pub fn new(config: SimplexAdapterConfig) -> Result<Self, SimplexAdapterError> {
        Ok(Self {
            sidecar_endpoint: config.sidecar_endpoint,
            storage: config.storage,
            default_retry_budget: config.default_retry_budget,
        })
    }

    /// Return the default retry budget.
    #[must_use]
    pub const fn default_retry_budget(&self) -> RetryBudget {
        self.default_retry_budget
    }

    /// Return the configured sidecar endpoint.
    #[must_use]
    pub const fn sidecar_endpoint(&self) -> &SidecarEndpoint {
        &self.sidecar_endpoint
    }

    /// Create a new identifier-less queue + return an out-of-band
    /// invitation per the D0020 §1.10 `Transport` seam.
    ///
    /// v1 skeleton: returns [`SimplexAdapterError::NetworkUnreached`].
    ///
    /// # Errors
    ///
    /// - [`SimplexAdapterError::NetworkUnreached`] (skeleton only;
    ///   replaced by the sidecar-layer failure modes once the body
    ///   lands).
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton; SimplOxide body lands per D0026 §12 step 5"
    )]
    pub async fn create_invitation(
        &self,
        _retry_budget: RetryBudget,
    ) -> Result<Invitation, SimplexAdapterError> {
        Err(SimplexAdapterError::NetworkUnreached)
    }

    /// Accept a peer's invitation + complete the out-of-band pairing
    /// per the D0020 §1.10 seam.
    ///
    /// v1 skeleton: returns [`SimplexAdapterError::NetworkUnreached`].
    ///
    /// # Errors
    ///
    /// - [`SimplexAdapterError::NetworkUnreached`] (skeleton only).
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton; SimplOxide body lands per D0026 §12 step 5"
    )]
    pub async fn accept_invitation(
        &self,
        _invitation: Invitation,
        _retry_budget: RetryBudget,
    ) -> Result<ConnectionId, SimplexAdapterError> {
        Err(SimplexAdapterError::NetworkUnreached)
    }

    /// Send a payload over an established connection per the D0020
    /// §1.10 seam.
    ///
    /// The `payload` the caller passes is wrapped in a signed + padded
    /// Cairn envelope (per [`crate::envelope`] + [`crate::padding`])
    /// before being handed to SimplOxide's send. SimplOxide applies
    /// the PQ double-ratchet + the SMP wire.
    ///
    /// v1 skeleton: returns [`SimplexAdapterError::NetworkUnreached`].
    ///
    /// # Errors
    ///
    /// - [`SimplexAdapterError::NetworkUnreached`] (skeleton only;
    ///   replaced by the layered failure modes once the body lands).
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton; SimplOxide body lands per D0026 §12 step 5"
    )]
    pub async fn send(
        &self,
        _conn: &ConnectionId,
        _recipient_operational_pubkey: &[u8; 32],
        _payload: &[u8],
        _retry_budget: RetryBudget,
    ) -> Result<MessageSent, SimplexAdapterError> {
        Err(SimplexAdapterError::NetworkUnreached)
    }

    /// Receive the next payload on an established connection per the
    /// D0020 §1.10 seam. Each received Cairn envelope is verified
    /// (signature + AAD + chain) before the payload is returned.
    ///
    /// v1 skeleton: returns [`SimplexAdapterError::NetworkUnreached`].
    ///
    /// # Errors
    ///
    /// - [`SimplexAdapterError::NetworkUnreached`] (skeleton only).
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton; SimplOxide body lands per D0026 §12 step 5"
    )]
    pub async fn recv(
        &self,
        _conn: &ConnectionId,
        _retry_budget: RetryBudget,
    ) -> Result<ReceivedMessage, SimplexAdapterError> {
        Err(SimplexAdapterError::NetworkUnreached)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use cairn_storage::key_provider::testing::InMemoryKeyProvider;
    use zeroize::Zeroizing;

    fn make_storage() -> Arc<Storage> {
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"test passphrase".to_vec());
        Arc::new(Storage::open_in_memory(&provider, &passphrase).unwrap())
    }

    fn make_adapter() -> SimplexAdapter {
        let config = SimplexAdapterConfig {
            sidecar_endpoint: SidecarEndpoint::default(),
            storage: make_storage(),
            default_retry_budget: RetryBudget::default(),
        };
        SimplexAdapter::new(config).unwrap()
    }

    #[test]
    fn default_sidecar_endpoint_is_loopback_5225() {
        let ep = SidecarEndpoint::default();
        assert_eq!(ep.host, "127.0.0.1");
        assert_eq!(ep.port, 5225);
    }

    #[test]
    fn adapter_construction_succeeds() {
        let _adapter = make_adapter();
    }

    #[test]
    fn adapter_exposes_sidecar_endpoint() {
        let adapter = make_adapter();
        assert_eq!(adapter.sidecar_endpoint().port, 5225);
    }

    #[test]
    fn adapter_exposes_default_retry_budget() {
        let adapter = make_adapter();
        assert_eq!(
            adapter.default_retry_budget().max_retries,
            RetryBudget::default().max_retries
        );
    }

    #[tokio::test]
    async fn create_invitation_returns_network_unreached_in_skeleton() {
        let adapter = make_adapter();
        let result = adapter.create_invitation(RetryBudget::default()).await;
        assert!(matches!(result, Err(SimplexAdapterError::NetworkUnreached)));
    }

    #[tokio::test]
    async fn accept_invitation_returns_network_unreached_in_skeleton() {
        let adapter = make_adapter();
        let inv = Invitation {
            uri: "simplex://invitation/placeholder".to_string(),
        };
        let result = adapter.accept_invitation(inv, RetryBudget::default()).await;
        assert!(matches!(result, Err(SimplexAdapterError::NetworkUnreached)));
    }

    #[tokio::test]
    async fn send_returns_network_unreached_in_skeleton() {
        let adapter = make_adapter();
        let conn = ConnectionId("conn-1".to_string());
        let recipient = [0xCC; 32];
        let result = adapter
            .send(&conn, &recipient, b"hello", RetryBudget::default())
            .await;
        assert!(matches!(result, Err(SimplexAdapterError::NetworkUnreached)));
    }

    #[tokio::test]
    async fn recv_returns_network_unreached_in_skeleton() {
        let adapter = make_adapter();
        let conn = ConnectionId("conn-1".to_string());
        let result = adapter.recv(&conn, RetryBudget::default()).await;
        assert!(matches!(result, Err(SimplexAdapterError::NetworkUnreached)));
    }
}
