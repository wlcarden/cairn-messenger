// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Async `SimplexClient` surface per D0026 §7.
//!
//! ## v1 skeleton status
//!
//! The struct + method signatures are defined per the D0026 §7 API.
//! The network-bound bodies ([`SimplexClient::send_message`],
//! [`SimplexClient::poll_inbox`], [`SimplexClient::rotate_queue`])
//! return [`SimplexAdapterError::NetworkUnreached`] pending the SMP
//! wire-protocol body landing per D0026 §12 step 6.
//!
//! What IS implemented + tested in the skeleton:
//!
//! - [`SimplexClient::new`] constructor wiring the server config +
//!   the composed `cairn_tor_transport::TorTransport` reference +
//!   the default retry budget.
//! - Server-config accessor methods + retry-budget accessor.
//!
//! When the network bodies land, [`SimplexClient::send_message`]:
//!
//! 1. Selects the SMP queue for the recipient (per-conversation
//!    queue state).
//! 2. Loads the [`crate::ratchet::RatchetState`] from
//!    [`cairn_storage::categories::RATCHET_STATE`].
//! 3. Builds the [`crate::envelope::MessageEnvelope`] with the
//!    next-message size-bin padded payload.
//! 4. Signs the envelope under the device key with AAD =
//!    [`crate::envelope::DOMAIN_TAG`] per D0006 §8.
//! 5. Advances the ratchet's sending chain.
//! 6. Sends the wire ciphertext over the SMP queue via Tor.
//! 7. Persists the updated ratchet state + the sent message in
//!    [`cairn_storage::categories::MESSAGES`].

use std::sync::Arc;

use cairn_sigsum_client::RetryBudget;
use cairn_storage::Storage;
use cairn_tor_transport::TorTransport;

use crate::error::SimplexAdapterError;

/// One SimpleX server entry per D0026 §6.1.
///
/// `server_address` is either a hostname or an `.onion` v3 address;
/// `server_pubkey` pins the server's identity so a network attacker
/// cannot substitute a different SMP relay.
#[derive(Debug, Clone)]
pub struct SimplexServer {
    /// `.onion` v3 address or hostname.
    pub server_address: String,
    /// 32-byte pinned server identity pubkey.
    pub server_pubkey: [u8; 32],
}

/// The configured SimpleX server set per D0026 §6.
///
/// Parsed from a release-bundled `simplex_servers.toml` (same
/// posture as the witness pool per D0023 §3.3 + the pluggable
/// transports list per D0025 §3). The Android-shell UI MAY accept
/// user-pasted server entries that override the bundled defaults
/// at runtime; v1 ships the bundled list only.
#[derive(Debug, Clone)]
pub struct SimplexServerConfig {
    /// Configured server entries in selection order.
    pub servers: Vec<SimplexServer>,
}

/// Configuration bundle for constructing a [`SimplexClient`].
///
/// Builder-pattern is intentional, mirroring D0023's
/// [`cairn_sigsum_client::SigsumClientConfig`] +
/// D0025's [`cairn_tor_transport::TorTransportConfig`].
pub struct SimplexClientConfig {
    /// Server selection per D0026 §6.
    pub servers: SimplexServerConfig,
    /// Composed Tor transport handle per D0026 §8. Shared via `Arc`
    /// so multiple `SimplexClient` instances may share the same
    /// underlying Arti runtime when the body lands.
    pub tor_transport: Arc<TorTransport>,
    /// Storage handle for `RATCHET_STATE` + `MESSAGES` categories
    /// per D0026 §3.2. Shared via `Arc` so the SimplexClient + the
    /// Android-shell concurrent surfaces share the same underlying
    /// SQLite connection per D0022's single-writer discipline.
    pub storage: Arc<Storage>,
    /// Default retry budget per D0026 §7.1 / D0023 §5.3.
    pub default_retry_budget: RetryBudget,
}

/// Outcome of a successful [`SimplexClient::send_message`] call.
///
/// In the v1 skeleton this type is only constructed by the body
/// that does not yet land; the type exists so the public API is
/// stable from skeleton through implementation.
#[derive(Debug, Clone)]
pub struct MessageSent {
    /// The 32-byte record id under which the sent message was
    /// persisted in [`cairn_storage::categories::MESSAGES`].
    pub record_id: [u8; 32],
    /// The next-message number the local ratchet advanced to.
    pub next_message_number: u64,
}

/// One received message per [`SimplexClient::poll_inbox`].
///
/// Decoded + verified per D0026 §2.3's signature + AAD discipline.
/// The body returns these once the wire-protocol surface lands;
/// the v1 skeleton's `poll_inbox` returns `Err(NetworkUnreached)`
/// without constructing this type.
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
/// Wraps the configured server set + the composed `TorTransport` +
/// the `Storage` handle + the default retry budget. Each async
/// method routes through the retry logic per D0026 §7.1.
pub struct SimplexClient {
    /// Server selection per D0026 §6.
    #[allow(
        dead_code,
        reason = "wired in v1 skeleton; populated for the SMP body per D0026 §12 step 6"
    )]
    servers: SimplexServerConfig,
    /// Composed Tor transport per D0026 §8.
    #[allow(dead_code, reason = "wired in v1 skeleton; populated for the SMP body")]
    tor_transport: Arc<TorTransport>,
    /// Storage handle for `RATCHET_STATE` + `MESSAGES`.
    #[allow(
        dead_code,
        reason = "wired in v1 skeleton; populated for ratchet + message persistence"
    )]
    storage: Arc<Storage>,
    /// Default retry budget per D0026 §7.1.
    default_retry_budget: RetryBudget,
}

impl SimplexClient {
    /// Construct a new `SimplexClient` from its config bundle.
    ///
    /// v1 skeleton: no SMP connections are opened; the constructor
    /// stores the config + composed handles for use when the body
    /// lands.
    ///
    /// # Errors
    ///
    /// v1 skeleton: never errors. When the body lands: may surface
    /// [`SimplexAdapterError::TransportError`] if initial Tor
    /// bootstrap fails.
    pub fn new(config: SimplexClientConfig) -> Result<Self, SimplexAdapterError> {
        Ok(Self {
            servers: config.servers,
            tor_transport: config.tor_transport,
            storage: config.storage,
            default_retry_budget: config.default_retry_budget,
        })
    }

    /// Return the default retry budget.
    #[must_use]
    pub const fn default_retry_budget(&self) -> RetryBudget {
        self.default_retry_budget
    }

    /// Return the configured server set.
    #[must_use]
    pub const fn servers(&self) -> &SimplexServerConfig {
        &self.servers
    }

    /// Send a message to `recipient` per D0026 §7.
    ///
    /// v1 skeleton: returns [`SimplexAdapterError::NetworkUnreached`]
    /// pending the SMP wire-protocol body.
    ///
    /// # Errors
    ///
    /// - [`SimplexAdapterError::NetworkUnreached`] (skeleton only;
    ///   replaced by the layered failure modes once the body lands).
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton; SMP body lands per D0026 §12 step 6"
    )]
    pub async fn send_message(
        &self,
        _recipient_operational_pubkey: &[u8; 32],
        _payload: &[u8],
        _retry_budget: RetryBudget,
    ) -> Result<MessageSent, SimplexAdapterError> {
        Err(SimplexAdapterError::NetworkUnreached)
    }

    /// Poll the local inbox for new messages per D0026 §7.
    ///
    /// v1 skeleton: returns [`SimplexAdapterError::NetworkUnreached`].
    ///
    /// # Errors
    ///
    /// - [`SimplexAdapterError::NetworkUnreached`] (skeleton only).
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton; SMP body lands per D0026 §12 step 6"
    )]
    pub async fn poll_inbox(
        &self,
        _retry_budget: RetryBudget,
    ) -> Result<Vec<ReceivedMessage>, SimplexAdapterError> {
        Err(SimplexAdapterError::NetworkUnreached)
    }

    /// Rotate the SMP queue for the named peer per D0026 §7.
    ///
    /// Per D0026 §7.2, this method is NOT cancel-safe — queue
    /// rotation is a multi-step state transition that cannot be
    /// safely cancelled mid-way.
    ///
    /// v1 skeleton: returns [`SimplexAdapterError::NetworkUnreached`].
    ///
    /// # Errors
    ///
    /// - [`SimplexAdapterError::NetworkUnreached`] (skeleton only).
    #[allow(
        clippy::unused_async,
        reason = "v1 skeleton; SMP body lands per D0026 §12 step 6"
    )]
    pub async fn rotate_queue(
        &self,
        _peer_operational_pubkey: &[u8; 32],
        _retry_budget: RetryBudget,
    ) -> Result<(), SimplexAdapterError> {
        Err(SimplexAdapterError::NetworkUnreached)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use cairn_storage::key_provider::testing::InMemoryKeyProvider;
    use cairn_tor_transport::{PluggableTransportConfig, TorTransportConfig};
    use zeroize::Zeroizing;

    fn make_storage() -> Arc<Storage> {
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"test passphrase".to_vec());
        Arc::new(Storage::open_in_memory(&provider, &passphrase).unwrap())
    }

    fn make_tor_transport() -> Arc<TorTransport> {
        let config = TorTransportConfig {
            pluggable_transports: PluggableTransportConfig::empty(),
            default_retry_budget: RetryBudget::default(),
        };
        Arc::new(TorTransport::new(config).unwrap())
    }

    fn make_servers() -> SimplexServerConfig {
        SimplexServerConfig {
            servers: vec![
                SimplexServer {
                    server_address: "smp-1.example.org".to_string(),
                    server_pubkey: [0xAA; 32],
                },
                SimplexServer {
                    server_address: "smp-2.example.org".to_string(),
                    server_pubkey: [0xBB; 32],
                },
            ],
        }
    }

    fn make_client() -> SimplexClient {
        let config = SimplexClientConfig {
            servers: make_servers(),
            tor_transport: make_tor_transport(),
            storage: make_storage(),
            default_retry_budget: RetryBudget::default(),
        };
        SimplexClient::new(config).unwrap()
    }

    #[test]
    fn client_construction_succeeds() {
        let _client = make_client();
    }

    #[test]
    fn client_exposes_server_set() {
        let client = make_client();
        assert_eq!(client.servers().servers.len(), 2);
        assert_eq!(
            client.servers().servers[0].server_address,
            "smp-1.example.org"
        );
    }

    #[test]
    fn client_exposes_default_retry_budget() {
        let client = make_client();
        assert_eq!(
            client.default_retry_budget().max_retries,
            RetryBudget::default().max_retries
        );
    }

    #[tokio::test]
    async fn send_message_returns_network_unreached_in_skeleton() {
        let client = make_client();
        let recipient = [0xCC; 32];
        let result = client
            .send_message(&recipient, b"hello", RetryBudget::default())
            .await;
        assert!(matches!(result, Err(SimplexAdapterError::NetworkUnreached)));
    }

    #[tokio::test]
    async fn poll_inbox_returns_network_unreached_in_skeleton() {
        let client = make_client();
        let result = client.poll_inbox(RetryBudget::default()).await;
        assert!(matches!(result, Err(SimplexAdapterError::NetworkUnreached)));
    }

    #[tokio::test]
    async fn rotate_queue_returns_network_unreached_in_skeleton() {
        let client = make_client();
        let peer = [0xDD; 32];
        let result = client.rotate_queue(&peer, RetryBudget::default()).await;
        assert!(matches!(result, Err(SimplexAdapterError::NetworkUnreached)));
    }
}
