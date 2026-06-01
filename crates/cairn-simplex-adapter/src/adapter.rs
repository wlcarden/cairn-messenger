// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Async `SimplexAdapter` surface per D0026 §1 + §7 (re-anchored under
//! D0020 §1: the SimplOxide-client-over-CLI-sidecar model).
//!
//! ## The transport seam (D0020 §1.10 / D0026 §1.2)
//!
//! `SimplexAdapter<T>` is generic over a [`crate::sidecar::SidecarTransport`]
//! — the raw byte transport below Cairn's envelope. This inverts the
//! dependency: the adapter's security-critical envelope flow (build →
//! sign → pad on send; verify → bind → chain-check → unpad on recv) is
//! implemented ONCE, generically, and is fully testable over an in-memory
//! `MockSidecarTransport` — without the SimpleX Chat CLI
//! sidecar (D0026 §1.2). Production uses
//! `SimplexAdapter<`[`crate::sidecar::SimploxideTransport`]`>`; that
//! concrete transport's WebSocket body is deferred pending the
//! `simploxide-client` crate (D0026 §12), but every layer Cairn owns is
//! live below.
//!
//! ## What rides over the seam
//!
//! The `payload` in `send` / `recv` is the application message body. The
//! adapter wraps it in a signed + padded Cairn envelope (per
//! [`crate::envelope`] + [`crate::padding`]) before handing the bytes to
//! the transport; SimplOxide owns the SMP wire, the PQ double-ratchet, the
//! queue lifecycle, and the invitation flow. Per-`(sender, recipient)`
//! chain integrity rides on the envelope `prior_envelope_hash` (D0026
//! §2.1 key 5); the transport-assigned message number keys the `MESSAGES`
//! history record.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, SigningKey, VerifyingKey};
use cairn_sigsum_client::RetryBudget;
use cairn_storage::{Storage, categories};

use crate::envelope::{
    ENVELOPE_SCHEMA_VERSION, MessageEnvelope, next_prior_envelope_hash, verify_envelope,
};
use crate::error::SimplexAdapterError;
use crate::padding::{generate_padding, padding_bytes_required};
use crate::sidecar::SidecarTransport;
use crate::storage::message_record_id_for;

/// Loopback endpoint of the SimpleX Chat CLI sidecar per D0020 §1.1.
///
/// Default `127.0.0.1:5225`. Consumed by
/// [`crate::sidecar::SimploxideTransport`]; the `ForegroundService`
/// (Android-shell concern per D0020 §1.6) spawns the CLI bound to this
/// port.
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

/// An out-of-band invitation per the D0020 §1.10 seam. SimpleX produces an
/// invitation URI when a new identifier-less queue is created; the peer
/// scans/pastes it to pair. Opaque at the Cairn layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    /// The SimpleX invitation URI (opaque at the Cairn layer).
    pub uri: String,
}

/// An established connection handle per the D0020 §1.10 seam — the opaque
/// identifier the sidecar assigns to a paired connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub String);

/// The local operational identity the adapter sends + signs as.
///
/// Per D0006's delegation model the envelope is SIGNED by the device key
/// but is FROM the operational identity, so both are held: the device key
/// produces the `COSE_Sign1` signature; `operational_pubkey` populates the
/// envelope's sender field (key 2) + the message-history record-id.
///
/// No `Debug` impl — it holds a secret signing key.
pub struct LocalIdentity {
    /// Device Ed25519 signing key (signs the envelope per D0006 §9).
    pub device_signing_key: SigningKey,
    /// This identity's operational-identity public key (D0026 §2.1 key 2).
    pub operational_pubkey: [u8; PUBLIC_KEY_LEN],
}

/// Configuration bundle for constructing a [`SimplexAdapter`].
///
/// No `Debug` impl: [`Storage`] does not derive `Debug` (it owns a
/// poisoned-mutex-guarded SQLite connection) and [`LocalIdentity`] holds a
/// secret key.
pub struct SimplexAdapterConfig {
    /// The local sending identity per D0006 §9.
    pub identity: LocalIdentity,
    /// Storage handle for Cairn's `MESSAGES` history per D0026 §4, shared
    /// via `Arc` per D0022's single-writer discipline.
    pub storage: Arc<Storage>,
    /// Default retry budget per D0026 §7 / D0023 §5.3.
    pub default_retry_budget: RetryBudget,
}

/// Outcome of a successful [`SimplexAdapter::send`].
#[derive(Debug, Clone)]
pub struct MessageSent {
    /// The 32-byte record id under which the sent envelope was persisted
    /// in [`cairn_storage::categories::MESSAGES`].
    pub record_id: [u8; 32],
    /// The next message number the chain advanced to.
    pub next_message_number: u64,
}

/// One received + verified message per [`SimplexAdapter::recv`].
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    /// Sender's operational identity per D0026 §2.1 key 2.
    pub sender_operational_pubkey: [u8; PUBLIC_KEY_LEN],
    /// Application-level payload (padding stripped on receive).
    pub payload: Vec<u8>,
    /// Receive-side wall-clock timestamp.
    pub received_at_unix: u64,
}

/// Per-`(sender, recipient)` envelope-chain cursor.
///
/// In-memory for this implementation cycle: the chain state lives for the
/// adapter's lifetime. Cross-restart persistence (rehydrating the cursor
/// from the `MESSAGES` history on startup) is a documented follow-up.
struct ChainState {
    /// `prior_envelope_hash` the NEXT envelope must commit to (empty until
    /// the first message has flowed).
    prior_hash: Vec<u8>,
    /// Last in-order message number seen on this chain (for the
    /// [`SimplexAdapterError::EnvelopeChainGap`] diagnostic).
    last_message_number: u64,
}

/// The async Cairn SimpleX adapter per D0026 §7.
///
/// Generic over the [`SidecarTransport`] seam; constructs + signs + pads
/// Cairn envelopes on send and verifies + chain-checks + unpads them on
/// recv. NOT a protocol implementation — SimplOxide / the CLI sidecar own
/// the SMP wire + the PQ ratchet (D0026 §1.3).
pub struct SimplexAdapter<T: SidecarTransport> {
    transport: T,
    storage: Arc<Storage>,
    default_retry_budget: RetryBudget,
    identity: LocalIdentity,
    /// Send chain keyed by recipient operational pubkey.
    send_chains: Mutex<HashMap<[u8; PUBLIC_KEY_LEN], ChainState>>,
    /// Recv chain keyed by sender operational pubkey.
    recv_chains: Mutex<HashMap<[u8; PUBLIC_KEY_LEN], ChainState>>,
}

impl<T: SidecarTransport> SimplexAdapter<T> {
    /// Construct an adapter over a concrete [`SidecarTransport`].
    ///
    /// # Errors
    ///
    /// Never errors today (config is moved in); the `Result` is retained
    /// for a future transport that validates at construction time.
    pub fn new(transport: T, config: SimplexAdapterConfig) -> Result<Self, SimplexAdapterError> {
        Ok(Self {
            transport,
            storage: config.storage,
            default_retry_budget: config.default_retry_budget,
            identity: config.identity,
            send_chains: Mutex::new(HashMap::new()),
            recv_chains: Mutex::new(HashMap::new()),
        })
    }

    /// Return the default retry budget.
    #[must_use]
    pub const fn default_retry_budget(&self) -> RetryBudget {
        self.default_retry_budget
    }

    /// Create a new identifier-less queue + return an out-of-band
    /// invitation (delegates to the transport).
    ///
    /// # Errors
    ///
    /// Whatever the transport surfaces (e.g.
    /// [`SimplexAdapterError::SidecarUnavailable`] /
    /// [`SimplexAdapterError::NetworkUnreached`] for the deferred
    /// SimplOxide transport).
    pub async fn create_invitation(&self) -> Result<Invitation, SimplexAdapterError> {
        self.transport.create_invitation().await
    }

    /// Accept a peer's invitation + complete out-of-band pairing
    /// (delegates to the transport).
    ///
    /// # Errors
    ///
    /// Whatever the transport surfaces.
    pub async fn accept_invitation(
        &self,
        invitation: Invitation,
    ) -> Result<ConnectionId, SimplexAdapterError> {
        self.transport.accept_invitation(invitation).await
    }

    /// Send `payload` to `recipient_operational_pubkey` over `conn`.
    ///
    /// Builds + signs + pads a Cairn envelope (chained to this pair's
    /// prior envelope), hands the bytes to the transport, persists the
    /// envelope to `MESSAGES`, and advances the send chain.
    ///
    /// # Errors
    ///
    /// - [`SimplexAdapterError::PaddingMalformed`] — padding generation
    ///   failed.
    /// - [`SimplexAdapterError::EnvelopeSignatureVerifyFailed`] /
    ///   [`SimplexAdapterError::EnvelopeDecodeFailed`] — envelope
    ///   sign/encode failure (unreachable for valid keys).
    /// - the transport's error on `send`.
    /// - [`SimplexAdapterError::Storage`] — persisting the sent envelope
    ///   failed, or the send-chain mutex was poisoned.
    pub async fn send(
        &self,
        conn: &ConnectionId,
        recipient_operational_pubkey: &[u8; PUBLIC_KEY_LEN],
        payload: &[u8],
    ) -> Result<MessageSent, SimplexAdapterError> {
        let prior_hash = self.send_chain_prior_hash(recipient_operational_pubkey)?;

        let padding_len = padding_bytes_required(payload.len());
        let padding =
            generate_padding(padding_len).map_err(|_| SimplexAdapterError::PaddingMalformed)?;
        let envelope = MessageEnvelope {
            version: ENVELOPE_SCHEMA_VERSION,
            sender_operational_pubkey: self.identity.operational_pubkey,
            recipient_operational_pubkey: *recipient_operational_pubkey,
            timestamp: now_unix(),
            prior_envelope_hash: prior_hash,
            payload: payload.to_vec(),
            padding,
        };
        let cose = envelope.sign(&self.identity.device_signing_key)?;

        let message_number = self.transport.send(conn, &cose).await?;

        let record_id = message_record_id_for(
            &self.identity.operational_pubkey,
            recipient_operational_pubkey,
            message_number,
        );
        self.storage.put(categories::MESSAGES, &record_id, &cose)?;

        let next_hash = next_prior_envelope_hash(&cose)?;
        advance_chain(
            &self.send_chains,
            *recipient_operational_pubkey,
            next_hash,
            message_number,
        )?;

        Ok(MessageSent {
            record_id,
            next_message_number: message_number.saturating_add(1),
        })
    }

    /// Receive + verify the next message on `conn` from
    /// `expected_sender_operational_pubkey`, whose envelope is signed by
    /// `sender_device_pubkey`.
    ///
    /// Verifies the `COSE_Sign1` signature + AAD domain tag, binds the
    /// envelope's sender to the expected operational identity, checks the
    /// `prior_envelope_hash` against this pair's recv chain, strips
    /// padding, persists, and advances the recv chain.
    ///
    /// # Errors
    ///
    /// - the transport's error on `recv`.
    /// - [`SimplexAdapterError::EnvelopeSignatureVerifyFailed`] — bad
    ///   signature/AAD, or the envelope's sender is not the expected
    ///   operational identity.
    /// - [`SimplexAdapterError::EnvelopeChainGap`] — the
    ///   `prior_envelope_hash` did not link to the last observed envelope.
    /// - [`SimplexAdapterError::Storage`] — persisting failed, or a chain
    ///   mutex was poisoned.
    pub async fn recv(
        &self,
        conn: &ConnectionId,
        expected_sender_operational_pubkey: &[u8; PUBLIC_KEY_LEN],
        sender_device_pubkey: &VerifyingKey,
    ) -> Result<ReceivedMessage, SimplexAdapterError> {
        let (message_number, cose) = self.transport.recv(conn).await?;

        let envelope = verify_envelope(&cose, sender_device_pubkey)?;
        // Bind the verified envelope to the expected peer: a validly-signed
        // envelope from a DIFFERENT operational identity must not be
        // accepted on this connection.
        if &envelope.sender_operational_pubkey != expected_sender_operational_pubkey {
            return Err(SimplexAdapterError::EnvelopeSignatureVerifyFailed);
        }

        let (expected_prior, last_number) =
            self.recv_chain_expectation(expected_sender_operational_pubkey)?;
        if envelope.prior_envelope_hash != expected_prior {
            return Err(SimplexAdapterError::EnvelopeChainGap {
                last_observed_message_number: last_number,
                observed_message_number: message_number,
            });
        }

        // Padding is a separate envelope field (D0026 §2.1 key 7); the
        // payload field is already clean.
        let payload = envelope.payload.clone();

        let record_id = message_record_id_for(
            expected_sender_operational_pubkey,
            &self.identity.operational_pubkey,
            message_number,
        );
        self.storage.put(categories::MESSAGES, &record_id, &cose)?;

        let next_hash = next_prior_envelope_hash(&cose)?;
        advance_chain(
            &self.recv_chains,
            *expected_sender_operational_pubkey,
            next_hash,
            message_number,
        )?;

        Ok(ReceivedMessage {
            sender_operational_pubkey: envelope.sender_operational_pubkey,
            payload,
            received_at_unix: now_unix(),
        })
    }

    /// The `prior_envelope_hash` for the next send to `recipient` (empty
    /// for the first message).
    fn send_chain_prior_hash(
        &self,
        recipient: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<Vec<u8>, SimplexAdapterError> {
        let guard = self
            .send_chains
            .lock()
            .map_err(|_| poisoned_chain_error())?;
        let prior = guard
            .get(recipient)
            .map_or_else(Vec::new, |c| c.prior_hash.clone());
        drop(guard);
        Ok(prior)
    }

    /// The expected `(prior_envelope_hash, last_message_number)` for the
    /// next recv from `sender`.
    fn recv_chain_expectation(
        &self,
        sender: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(Vec<u8>, u64), SimplexAdapterError> {
        let guard = self
            .recv_chains
            .lock()
            .map_err(|_| poisoned_chain_error())?;
        let expectation = guard.get(sender).map_or_else(
            || (Vec::new(), 0),
            |c| (c.prior_hash.clone(), c.last_message_number),
        );
        drop(guard);
        Ok(expectation)
    }
}

/// Record the new chain cursor after a successful send/recv.
fn advance_chain(
    chains: &Mutex<HashMap<[u8; PUBLIC_KEY_LEN], ChainState>>,
    peer: [u8; PUBLIC_KEY_LEN],
    next_hash: [u8; 32],
    message_number: u64,
) -> Result<(), SimplexAdapterError> {
    let mut guard = chains.lock().map_err(|_| poisoned_chain_error())?;
    guard.insert(
        peer,
        ChainState {
            prior_hash: next_hash.to_vec(),
            last_message_number: message_number,
        },
    );
    drop(guard);
    Ok(())
}

/// A poisoned chain mutex means a prior panic left the handle unusable.
const fn poisoned_chain_error() -> SimplexAdapterError {
    SimplexAdapterError::Network {
        retry_budget_used: 0,
    }
}

/// Wall-clock Unix seconds (saturating to 0 before the epoch).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::similar_names
)]
mod tests {
    use super::*;
    use crate::sidecar::MockSidecarTransport;
    use cairn_storage::key_provider::testing::InMemoryKeyProvider;
    use rand_core::OsRng;
    use zeroize::Zeroizing;

    fn make_storage() -> Arc<Storage> {
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"test passphrase".to_vec());
        Arc::new(Storage::open_in_memory(&provider, &passphrase).unwrap())
    }

    /// A party: its device verifying key + operational pubkey (kept for the
    /// peer's recv params) + an adapter over a (shared) mock transport.
    struct Party {
        device_vk: VerifyingKey,
        operational_pubkey: [u8; PUBLIC_KEY_LEN],
        adapter: SimplexAdapter<MockSidecarTransport>,
    }

    fn make_party_from_seed(seed: [u8; 32], transport: MockSidecarTransport) -> Party {
        let device_sk = SigningKey::from_seed(&Zeroizing::new(seed));
        let device_vk = device_sk.verifying_key();
        let mut op_seed = seed;
        op_seed[0] ^= 0xFF; // distinct from the device key
        let operational_pubkey = SigningKey::from_seed(&Zeroizing::new(op_seed))
            .verifying_key()
            .to_bytes();
        let config = SimplexAdapterConfig {
            identity: LocalIdentity {
                device_signing_key: device_sk,
                operational_pubkey,
            },
            storage: make_storage(),
            default_retry_budget: RetryBudget::default(),
        };
        Party {
            device_vk,
            operational_pubkey,
            adapter: SimplexAdapter::new(transport, config).unwrap(),
        }
    }

    fn make_party(transport: MockSidecarTransport) -> Party {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        make_party_from_seed(seed, transport)
    }

    #[tokio::test]
    async fn message_round_trips_with_signature_and_payload() {
        let wire = MockSidecarTransport::new();
        let alice = make_party(wire.clone());
        let bob = make_party(wire.clone());
        let conn = ConnectionId("conn-1".to_string());

        let sent = alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"hello bob")
            .await
            .unwrap();
        assert_eq!(sent.next_message_number, 1);

        let received = bob
            .adapter
            .recv(&conn, &alice.operational_pubkey, &alice.device_vk)
            .await
            .unwrap();
        assert_eq!(received.payload, b"hello bob");
        assert_eq!(received.sender_operational_pubkey, alice.operational_pubkey);
    }

    #[tokio::test]
    async fn chain_links_across_two_messages() {
        let wire = MockSidecarTransport::new();
        let alice = make_party(wire.clone());
        let bob = make_party(wire.clone());
        let conn = ConnectionId("conn-1".to_string());

        alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"first")
            .await
            .unwrap();
        alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"second")
            .await
            .unwrap();

        // Both verify + chain-link in order (msg 2's prior_envelope_hash ==
        // hash of msg 1).
        let m1 = bob
            .adapter
            .recv(&conn, &alice.operational_pubkey, &alice.device_vk)
            .await
            .unwrap();
        assert_eq!(m1.payload, b"first");
        let m2 = bob
            .adapter
            .recv(&conn, &alice.operational_pubkey, &alice.device_vk)
            .await
            .unwrap();
        assert_eq!(m2.payload, b"second");
    }

    #[tokio::test]
    async fn recv_with_wrong_device_key_fails_verification() {
        let wire = MockSidecarTransport::new();
        let alice = make_party(wire.clone());
        let bob = make_party(wire.clone());
        let imposter_vk = SigningKey::generate(&mut OsRng).verifying_key();
        let conn = ConnectionId("conn-1".to_string());

        alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"hi")
            .await
            .unwrap();
        let err = bob
            .adapter
            .recv(&conn, &alice.operational_pubkey, &imposter_vk)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SimplexAdapterError::EnvelopeSignatureVerifyFailed),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn recv_binds_envelope_to_expected_sender() {
        // A validly-signed envelope whose sender operational pubkey is not
        // the expected peer must be rejected.
        let wire = MockSidecarTransport::new();
        let alice = make_party(wire.clone());
        let bob = make_party(wire.clone());
        let conn = ConnectionId("conn-1".to_string());

        alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"hi")
            .await
            .unwrap();
        let wrong_sender = [0x77u8; PUBLIC_KEY_LEN];
        let err = bob
            .adapter
            .recv(&conn, &wrong_sender, &alice.device_vk)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SimplexAdapterError::EnvelopeSignatureVerifyFailed),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn out_of_chain_envelope_surfaces_chain_gap() {
        // Bob receives alice's msg 1 (advancing his recv chain), then a
        // SECOND alice adapter (same identity via the same seed, but a
        // fresh send chain) sends a message whose prior_envelope_hash is
        // empty — which no longer links to bob's expected prior.
        let wire = MockSidecarTransport::new();
        let seed = [0x42u8; 32];
        let alice1 = make_party_from_seed(seed, wire.clone());
        let alice2 = make_party_from_seed(seed, wire.clone());
        let bob = make_party(wire.clone());
        let conn = ConnectionId("conn-1".to_string());

        alice1
            .adapter
            .send(&conn, &bob.operational_pubkey, b"first")
            .await
            .unwrap();
        bob.adapter
            .recv(&conn, &alice1.operational_pubkey, &alice1.device_vk)
            .await
            .unwrap();

        alice2
            .adapter
            .send(&conn, &bob.operational_pubkey, b"orphan")
            .await
            .unwrap();
        let err = bob
            .adapter
            .recv(&conn, &alice1.operational_pubkey, &alice1.device_vk)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SimplexAdapterError::EnvelopeChainGap { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn deferred_simploxide_transport_is_network_unreached() {
        use crate::sidecar::SimploxideTransport;
        let transport = SimploxideTransport::new(SidecarEndpoint::default());
        let config = SimplexAdapterConfig {
            identity: LocalIdentity {
                device_signing_key: SigningKey::generate(&mut OsRng),
                operational_pubkey: [0u8; PUBLIC_KEY_LEN],
            },
            storage: make_storage(),
            default_retry_budget: RetryBudget::default(),
        };
        let adapter = SimplexAdapter::new(transport, config).unwrap();
        let result = adapter.create_invitation().await;
        assert!(matches!(result, Err(SimplexAdapterError::NetworkUnreached)));
    }

    #[test]
    fn default_sidecar_endpoint_is_loopback_5225() {
        let ep = SidecarEndpoint::default();
        assert_eq!(ep.host, "127.0.0.1");
        assert_eq!(ep.port, 5225);
    }
}
