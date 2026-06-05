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
//! sidecar (D0026 §1.2). Production uses `SimplexAdapter` over the ws-core
//! [`crate::sidecar::SimploxideTransport`], whose loopback-WebSocket body is
//! live-validated against a real simplex-chat daemon (D0026 §12); every layer
//! Cairn owns is live below it.
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

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, VerifyingKey};
use cairn_sigsum_client::RetryBudget;
use cairn_storage::{Storage, StorageError, categories};

use crate::envelope::{
    ENVELOPE_SCHEMA_VERSION, EnvelopeSigner, MessageEnvelope, decode_envelope_unverified,
    next_prior_envelope_hash, verify_envelope, verify_envelope_learning_sender,
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
/// but is FROM the operational identity, so both are held: the
/// [`EnvelopeSigner`] produces the `COSE_Sign1` device signature;
/// `operational_pubkey` populates the envelope's sender field (key 2) +
/// the message-history record-id.
///
/// `device_signer` is an [`EnvelopeSigner`] rather than a concrete
/// `SigningKey` so the device signature can be produced EITHER in-process
/// (a software key, for the `cairn-cli` demo + tests) OR in hardware (an
/// Android StrongBox bridge via `cairn-uniffi` per D0020 §3.4) — the latter
/// is what lets the FFI messaging handle exist without a software key ever
/// crossing the boundary (D0026 §2.3 / D0027 §2.4).
///
/// No `Debug` impl — the signer may hold a secret key.
pub struct LocalIdentity {
    /// Device-key envelope signer (software key OR hardware bridge), per
    /// D0006 §9 / D0026 §2.3.
    pub device_signer: Arc<dyn EnvelopeSigner>,
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
    /// Application-level payload (padding stripped on receive). Empty for a
    /// read-receipt envelope (D0032), where [`Self::read_up_to`] is `Some`.
    pub payload: Vec<u8>,
    /// Receive-side wall-clock timestamp.
    pub received_at_unix: u64,
    /// `Some(n)` if this is a read receipt (D0032): the sender has read this
    /// side's messages up to number `n`. `None` for a normal content message.
    /// The caller marks its outgoing messages ≤ `n` as read.
    pub read_up_to: Option<u64>,
    /// `Some(bytes)` if this is a provenance vouch (D0036): the canonical-CBOR
    /// `{op_chain, token}` the sender shared. The caller verifies + ingests it
    /// (the `me <- sender` envelope already authenticated the sender). `None`
    /// for content + read-receipt messages.
    pub vouch: Option<Vec<u8>>,
}

/// One persisted message in a conversation's history per
/// [`SimplexAdapter::load_message_history`] (D0026 §3.2).
#[derive(Debug, Clone)]
pub struct HistoryMessage {
    /// `true` if this side SENT it (an outgoing `me -> peer` record); `false`
    /// for an incoming `peer -> me` record.
    pub mine: bool,
    /// Application-level payload (envelope key 6; padding is a separate field).
    pub payload: Vec<u8>,
    /// Envelope construction Unix-seconds timestamp (key 4).
    pub timestamp_unix: u64,
    /// This message's position on its directed chain (D0026 §3.2). For a
    /// `mine` (outgoing) message it is the send-chain number the peer's
    /// `read_up_to` is compared against to mark it read (D0032).
    pub message_number: u64,
}

/// A conversation's persisted history plus the peer's read high-water
/// (D0032), returned by [`SimplexAdapter::load_message_history`].
#[derive(Debug, Clone)]
pub struct ConversationHistory {
    /// Content messages both directions, chronological (read receipts skipped).
    pub messages: Vec<HistoryMessage>,
    /// The highest outgoing message number the peer has acknowledged reading
    /// (the max `read_up_to` across the peer's read receipts to this side), or
    /// `None` if the peer has sent no read receipt. Lets a re-opened
    /// conversation reconstruct which sent messages show "read".
    pub peer_read_up_to: Option<u64>,
}

/// Per-`(sender, recipient)` envelope-chain cursor.
///
/// The in-memory cache of a per-`(sender, recipient)` chain cursor.
///
/// The cache is rebuilt lazily on the first chain access after a restart
/// by [`rehydrate_chain`] (which walks the `MESSAGES` history), so the
/// `prior_envelope_hash` chain survives process restarts (D0026 §3.2).
/// `Default` is the genesis cursor (empty `prior_hash`, next message 0).
#[derive(Default)]
struct ChainState {
    /// `prior_envelope_hash` the NEXT envelope must commit to (empty until
    /// the first message has flowed).
    prior_hash: Vec<u8>,
    /// The per-`(sender, recipient)` number the NEXT message on this chain
    /// takes — **Cairn's chain position**, NOT a transport-assigned id
    /// (D0026 §3.2 revision note (c): SimpleX's chat-item id is
    /// global-monotonic + sparse-per-pair, which would break the
    /// contiguous-walk rehydration). `0` at genesis; [`advance_chain`] sets
    /// it to `used_number + 1` after each message.
    next_message_number: u64,
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

    /// Await an inbound connection becoming established after this side
    /// created + shared an invitation (the peer accepted it), returning the
    /// established connection id (delegates to the transport).
    ///
    /// The inviter-side counterpart to [`Self::accept_invitation`]'s
    /// establishment wait (D0026 §12): the usable connection id is the
    /// established contact, learned only once the peer connects.
    ///
    /// # Errors
    ///
    /// Whatever the transport surfaces.
    pub async fn await_connection(&self) -> Result<ConnectionId, SimplexAdapterError> {
        self.transport.await_connection().await
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
        self.send_envelope_inner(conn, recipient_operational_pubkey, payload, None, None)
            .await
    }

    /// Send a **provenance vouch** to `recipient` (D0036): share a verified
    /// contact's `Attest` op chain + capability token so the recipient can
    /// verify + store the foreign attestation and surface its provenance.
    ///
    /// `vouch_bytes` is the canonical-CBOR `{op_chain, token}` structure (built
    /// by the caller). The vouch is an **empty-payload** Cairn envelope carrying
    /// envelope key 9 — a normal signed + chained envelope on the
    /// `me -> recipient` direction, so it inherits device-signature
    /// authentication + chain integrity (D0036 §2, §3).
    ///
    /// # Errors
    ///
    /// As [`Self::send`] (transport, sign, storage, or a poisoned chain mutex).
    pub async fn send_vouch(
        &self,
        conn: &ConnectionId,
        recipient_operational_pubkey: &[u8; PUBLIC_KEY_LEN],
        vouch_bytes: &[u8],
    ) -> Result<(), SimplexAdapterError> {
        self.send_envelope_inner(
            conn,
            recipient_operational_pubkey,
            &[],
            None,
            Some(vouch_bytes.to_vec()),
        )
        .await?;
        Ok(())
    }

    /// Send a **read receipt** to `recipient` acknowledging every message this
    /// side has received from them (D0032).
    ///
    /// The high-water `read_up_to` is derived from this side's recv-chain
    /// position for `recipient` (the highest message number received from
    /// them), so no caller bookkeeping is needed. The receipt is an
    /// **empty-payload** Cairn envelope carrying envelope key 8 — a normal
    /// signed + chained envelope on the `me -> recipient` direction. A no-op
    /// (returns `Ok` without sending) if nothing has been received from
    /// `recipient` yet (nothing to acknowledge).
    ///
    /// Policy note: WHETHER to call this is the caller's (off by default,
    /// D0032 §4); the adapter only provides the mechanism.
    ///
    /// # Errors
    ///
    /// As [`Self::send`] (transport, sign, storage, or a poisoned chain mutex).
    pub async fn send_read_receipt(
        &self,
        conn: &ConnectionId,
        recipient_operational_pubkey: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(), SimplexAdapterError> {
        // The recv-chain `next_message_number` for `recipient` is the count of
        // envelopes received from them; the highest received number is one less.
        let (_prior, next_recv) = self.recv_chain_state(recipient_operational_pubkey)?;
        let Some(read_up_to) = next_recv.checked_sub(1) else {
            return Ok(()); // nothing received from this peer → nothing to ack
        };
        self.send_envelope_inner(
            conn,
            recipient_operational_pubkey,
            &[],
            Some(read_up_to),
            None,
        )
        .await?;
        Ok(())
    }

    /// Shared send tail for [`Self::send`] (content, `read_up_to = None`) and
    /// [`Self::send_read_receipt`] (empty payload, `read_up_to = Some`): build →
    /// sign → transport → persist → advance the `me -> recipient` send chain.
    async fn send_envelope_inner(
        &self,
        conn: &ConnectionId,
        recipient_operational_pubkey: &[u8; PUBLIC_KEY_LEN],
        payload: &[u8],
        read_up_to: Option<u64>,
        vouch: Option<Vec<u8>>,
    ) -> Result<MessageSent, SimplexAdapterError> {
        let (prior_hash, message_number) = self.send_chain_state(recipient_operational_pubkey)?;

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
            read_up_to,
            vouch,
        };
        let cose = envelope.sign_with(self.identity.device_signer.as_ref())?;

        // The seam carries no message number (D0026 §3.2 (c)); the number is
        // Cairn's chain position, assigned above + advanced below.
        self.transport.send(conn, &cose).await?;

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
        let cose = self.transport.recv(conn).await?;

        let envelope = verify_envelope(&cose, sender_device_pubkey)?;
        // Bind the verified envelope to the expected peer: a validly-signed
        // envelope from a DIFFERENT operational identity must not be
        // accepted on this connection.
        if &envelope.sender_operational_pubkey != expected_sender_operational_pubkey {
            return Err(SimplexAdapterError::EnvelopeSignatureVerifyFailed);
        }

        self.finish_recv(expected_sender_operational_pubkey, &envelope, &cose)
    }

    /// Receive + verify the next message on `conn` **without a pre-known
    /// sender**, learning the sender's operational identity from the envelope
    /// itself (TOFU on first contact, D0026 §12).
    ///
    /// The pairing-handshake counterpart to [`Self::recv`]: after sharing a
    /// one-time invitation, the inviter cannot know the acceptor's key until
    /// the first envelope arrives. This verifies the `COSE_Sign1` against the
    /// key embedded in the envelope (the 1:1-demo operational==device key,
    /// D0028 — see [`verify_envelope_learning_sender`] for the security posture
    /// and the op≠device safety argument), then **re-anchors** the recv chain
    /// to this envelope keyed on the **learned** sender.
    ///
    /// ## Re-anchor, not chain-check (D0031 re-pair fix)
    ///
    /// Unlike steady-state [`Self::recv`], this does NOT enforce the
    /// `prior_envelope_hash` link. The first envelope of a (re-)pairing has no
    /// prior to link against: on a fresh pairing the receiver's recv chain is
    /// genesis (nothing to compare), and on a **re-pair after a one-sided
    /// delete** (D0031) one side reset its chain while the other did not — so
    /// the handshake envelope legitimately carries a `prior_envelope_hash` that
    /// does not match the receiver's (stale or genesis) cursor. This path
    /// anchors the recv chain to whatever this envelope is; steady-state
    /// [`Self::recv`] keeps the strict chain-gap check, so the D0026 §2.3
    /// stolen-key-detection property is preserved for the ONGOING conversation
    /// (a forger cannot trigger a mid-stream re-anchor — re-anchoring only
    /// happens on an explicit pairing handshake, after which manual key
    /// verification, D0006 §70, is the human check). The persist position is
    /// the receiver's current recv-chain number, so the non-deleting side
    /// APPENDS to its retained history (never overwrites).
    ///
    /// # Errors
    ///
    /// - the transport's error on `recv`.
    /// - [`SimplexAdapterError::EnvelopeSignatureVerifyFailed`] — bad
    ///   signature/AAD, or (always) an op≠device envelope.
    /// - [`SimplexAdapterError::Storage`] — persisting failed, or a chain
    ///   mutex was poisoned.
    pub async fn recv_learning_sender(
        &self,
        conn: &ConnectionId,
    ) -> Result<ReceivedMessage, SimplexAdapterError> {
        let cose = self.transport.recv(conn).await?;
        let envelope = verify_envelope_learning_sender(&cose)?;
        let learned_sender = envelope.sender_operational_pubkey;
        self.finish_recv_reanchor(&learned_sender, &envelope, &cose)
    }

    /// Steady-state recv tail (D0026 §3.2): enforce the `prior_envelope_hash`
    /// link against `sender`'s recv chain (the §2.3 gap/substitution detector),
    /// then persist + advance. The strict path used by [`Self::recv`].
    ///
    /// # Errors
    ///
    /// [`SimplexAdapterError::EnvelopeChainGap`] if the envelope's
    /// `prior_envelope_hash` does not link to the last observed envelope;
    /// otherwise as [`Self::persist_and_advance_recv`].
    fn finish_recv(
        &self,
        sender: &[u8; PUBLIC_KEY_LEN],
        envelope: &MessageEnvelope,
        cose: &[u8],
    ) -> Result<ReceivedMessage, SimplexAdapterError> {
        // The message number is Cairn's recv-chain position (D0026 §3.2 (c)),
        // not transport-supplied.
        let (expected_prior, message_number) = self.recv_chain_state(sender)?;
        if envelope.prior_envelope_hash != expected_prior {
            return Err(SimplexAdapterError::EnvelopeChainGap {
                last_observed_message_number: message_number.saturating_sub(1),
                observed_message_number: message_number,
            });
        }
        self.persist_and_advance_recv(sender, envelope, cose, message_number)
    }

    /// Pairing-handshake recv tail (D0031): persist + advance WITHOUT the
    /// `prior_envelope_hash` link check — re-anchoring the recv chain to this
    /// envelope. Used ONLY by [`Self::recv_learning_sender`] (the first
    /// envelope of a (re-)pairing); see that method's "Re-anchor" note for why
    /// this does not weaken the steady-state §2.3 property.
    fn finish_recv_reanchor(
        &self,
        sender: &[u8; PUBLIC_KEY_LEN],
        envelope: &MessageEnvelope,
        cose: &[u8],
    ) -> Result<ReceivedMessage, SimplexAdapterError> {
        // Anchor at the receiver's CURRENT recv position (genesis for the side
        // that purged, or its retained high-water for the side that did not) so
        // the non-deleting side appends to its history rather than overwriting.
        let (_expected_prior, message_number) = self.recv_chain_state(sender)?;
        self.persist_and_advance_recv(sender, envelope, cose, message_number)
    }

    /// Shared recv tail: strip padding (key 7), persist the verified envelope
    /// under the `(sender, me, message_number)` record id, and advance the recv
    /// chain to this envelope's `next_prior_envelope_hash`. The envelope is
    /// already verified; the chain decision (strict vs. re-anchor) was made by
    /// the caller.
    fn persist_and_advance_recv(
        &self,
        sender: &[u8; PUBLIC_KEY_LEN],
        envelope: &MessageEnvelope,
        cose: &[u8],
        message_number: u64,
    ) -> Result<ReceivedMessage, SimplexAdapterError> {
        // Padding is a separate envelope field (D0026 §2.1 key 7); the
        // payload field is already clean.
        let payload = envelope.payload.clone();

        let record_id =
            message_record_id_for(sender, &self.identity.operational_pubkey, message_number);
        self.storage.put(categories::MESSAGES, &record_id, cose)?;

        let next_hash = next_prior_envelope_hash(cose)?;
        advance_chain(&self.recv_chains, *sender, next_hash, message_number)?;

        Ok(ReceivedMessage {
            sender_operational_pubkey: *sender,
            payload,
            received_at_unix: now_unix(),
            // A read receipt (D0032) carries key 8 + an empty payload; the caller
            // routes a `Some` to read-status handling, not to the message list.
            read_up_to: envelope.read_up_to,
            // A vouch (D0036) carries key 9 + an empty payload; the caller routes
            // a `Some` to verify+ingest, not to the message list.
            vouch: envelope.vouch.clone(),
        })
    }

    /// Load the persisted conversation history with `peer` — both directions,
    /// chronologically ordered by envelope timestamp (D0026 §3.2). Reads the
    /// `MESSAGES` store this adapter already persists on every `send`/`recv`;
    /// records were verified when they flowed, so they are decoded WITHOUT
    /// re-verifying (the history view holds no device key). 0-length hello
    /// markers (the one-link-pairing key exchange, D0026 §12) are skipped.
    ///
    /// `O(N)` in the pair's message count (a contiguous `0..` walk per
    /// direction), called once when a conversation is opened.
    ///
    /// # Errors
    ///
    /// [`SimplexAdapterError::Storage`] on a read failure;
    /// [`SimplexAdapterError::EnvelopeDecodeFailed`] if a stored record does
    /// not parse.
    pub fn load_message_history(
        &self,
        peer_operational_pubkey: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<ConversationHistory, SimplexAdapterError> {
        let me = &self.identity.operational_pubkey;
        let mut out: Vec<HistoryMessage> = Vec::new();
        // Incoming (peer -> me): the peer's content messages AND the peer's read
        // receipts to me — the latter carry the `read_up_to` high-water of MY
        // messages the peer has read (D0032), so that direction yields
        // `peer_read_up_to`.
        let peer_read_up_to =
            self.collect_direction(peer_operational_pubkey, me, false, &mut out)?;
        // Outgoing (me -> peer): my content messages. My own read receipts'
        // `read_up_to` here ack the PEER's messages — irrelevant to read-status
        // of my sent messages — so this direction's high-water is ignored.
        self.collect_direction(me, peer_operational_pubkey, true, &mut out)?;
        // Chronological across both directions; stable so same-second ties keep
        // their per-direction insertion order.
        out.sort_by_key(|m| m.timestamp_unix);
        Ok(ConversationHistory {
            messages: out,
            peer_read_up_to,
        })
    }

    /// Purge ALL local trace of the conversation with `peer` — the deeper
    /// delete-purge invoked when the user deletes a contact (D0031).
    ///
    /// Deletes BOTH directed `MESSAGES` chains (outgoing `me -> peer` AND
    /// incoming `peer -> me`), drops this pair's in-memory send + recv chain
    /// cursors (so a future re-pair with the same operational identity restarts
    /// at the genesis chain rather than expecting the purged history's last
    /// cursor), then tears down the SimpleX-side connection/queue over `conn`.
    ///
    /// **Ordering is the privacy contract.** The `MESSAGES` purge is the
    /// irreversible deletion of locally-decryptable plaintext history the user
    /// asked for, so it happens FIRST + is authoritative. The connection
    /// teardown is attempted AFTER; a transport failure there is surfaced but
    /// does NOT undo the history purge — it leaves a lingering SMP queue (a
    /// retriable resource leak, the pre-D0031 status quo for the queue), never
    /// readable history.
    ///
    /// # Errors
    ///
    /// - [`SimplexAdapterError::Storage`] if a `MESSAGES` delete or a chain-cache
    ///   lock fails (the purge aborts before the teardown).
    /// - the transport's error from [`SidecarTransport::delete_connection`] (the
    ///   history is already purged; only the queue teardown failed).
    pub async fn purge_conversation(
        &self,
        conn: &ConnectionId,
        peer_operational_pubkey: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(), SimplexAdapterError> {
        let me = &self.identity.operational_pubkey;
        // Both directed chains: incoming (peer -> me) + outgoing (me -> peer).
        self.purge_direction(peer_operational_pubkey, me)?;
        self.purge_direction(me, peer_operational_pubkey)?;
        // Drop the cached cursors so a re-pair restarts at the genesis chain.
        self.forget_chain_state(peer_operational_pubkey)?;
        // Best-effort SimpleX-side teardown (SMP queue + conversation).
        self.transport.delete_connection(conn).await
    }

    /// Walk the contiguous `0..` `MESSAGES` records for one directed
    /// `(sender, recipient)` pair, decoding each into [`HistoryMessage`]s
    /// appended to `out` (stamped with their chain `message_number`). Stops at
    /// the first missing message number. Returns the **max `read_up_to`** seen
    /// on this direction (D0032) — used by [`Self::load_message_history`] for
    /// the peer's read high-water on the incoming direction.
    fn collect_direction(
        &self,
        sender: &[u8; PUBLIC_KEY_LEN],
        recipient: &[u8; PUBLIC_KEY_LEN],
        mine: bool,
        out: &mut Vec<HistoryMessage>,
    ) -> Result<Option<u64>, SimplexAdapterError> {
        let mut message_number = 0u64;
        let mut max_read_up_to: Option<u64> = None;
        loop {
            let record_id = message_record_id_for(sender, recipient, message_number);
            match self.storage.get(categories::MESSAGES, &record_id) {
                Ok(cose) => {
                    let envelope = decode_envelope_unverified(&cose)?;
                    if let Some(r) = envelope.read_up_to {
                        max_read_up_to = Some(max_read_up_to.map_or(r, |m| m.max(r)));
                    }
                    // Skip empty-payload envelopes — the 0-length pairing hello
                    // (D0026 §12) AND read receipts (D0032) — they are markers,
                    // not user-visible messages.
                    if !envelope.payload.is_empty() {
                        out.push(HistoryMessage {
                            mine,
                            payload: envelope.payload,
                            timestamp_unix: envelope.timestamp,
                            message_number,
                        });
                    }
                    message_number = message_number.saturating_add(1);
                }
                Err(StorageError::RecordNotFound { .. }) => break,
                Err(e) => return Err(SimplexAdapterError::from(e)),
            }
        }
        Ok(max_read_up_to)
    }

    /// Delete the contiguous `0..` `MESSAGES` records for one directed
    /// `(sender, recipient)` pair — the purge-walk analog of
    /// [`Self::collect_direction`] (D0031). Stops at the first message number
    /// with no stored record: messages are persisted strictly in order (send
    /// numbers are contiguous; the recv chain-gap check rejects out-of-order
    /// delivery), so the contiguous `0..` prefix IS the whole chain, and
    /// [`Storage::delete`] returning `false` (no such row) marks its end.
    fn purge_direction(
        &self,
        sender: &[u8; PUBLIC_KEY_LEN],
        recipient: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(), SimplexAdapterError> {
        let mut message_number = 0u64;
        loop {
            let record_id = message_record_id_for(sender, recipient, message_number);
            match self.storage.delete(categories::MESSAGES, &record_id) {
                Ok(true) => message_number = message_number.saturating_add(1),
                Ok(false) => break,
                Err(e) => return Err(SimplexAdapterError::from(e)),
            }
        }
        Ok(())
    }

    /// The `(prior_envelope_hash, next_message_number)` for the next send to
    /// `recipient` — `(empty, 0)` at genesis.
    fn send_chain_state(
        &self,
        recipient: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(Vec<u8>, u64), SimplexAdapterError> {
        // Fast path: the cursor is already cached in memory. The guard is
        // scoped to this block so it drops before the rehydrate path.
        let cached = {
            let guard = self
                .send_chains
                .lock()
                .map_err(|_| poisoned_chain_error())?;
            guard
                .get(recipient)
                .map(|state| (state.prior_hash.clone(), state.next_message_number))
        };
        if let Some(state) = cached {
            return Ok(state);
        }
        // Miss (first access, e.g. after a restart): rebuild from the
        // MESSAGES history so the chain continues across restarts. The
        // send chain's records are keyed (me → recipient).
        let rehydrated =
            rehydrate_chain(&self.storage, &self.identity.operational_pubkey, recipient)?;
        let mut guard = self
            .send_chains
            .lock()
            .map_err(|_| poisoned_chain_error())?;
        let state = guard
            .entry(*recipient)
            .or_insert_with(|| rehydrated.unwrap_or_default());
        let result = (state.prior_hash.clone(), state.next_message_number);
        drop(guard);
        Ok(result)
    }

    /// The expected `(prior_envelope_hash, next_message_number)` for the next
    /// recv from `sender` — `(empty, 0)` at genesis.
    fn recv_chain_state(
        &self,
        sender: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(Vec<u8>, u64), SimplexAdapterError> {
        // Fast path scoped so the guard drops before the rehydrate path.
        let cached = {
            let guard = self
                .recv_chains
                .lock()
                .map_err(|_| poisoned_chain_error())?;
            guard
                .get(sender)
                .map(|state| (state.prior_hash.clone(), state.next_message_number))
        };
        if let Some(expectation) = cached {
            return Ok(expectation);
        }
        // Miss: rebuild from MESSAGES. The recv chain's records are keyed
        // (sender → me).
        let rehydrated = rehydrate_chain(&self.storage, sender, &self.identity.operational_pubkey)?;
        let mut guard = self
            .recv_chains
            .lock()
            .map_err(|_| poisoned_chain_error())?;
        let expectation = {
            let state = guard
                .entry(*sender)
                .or_insert_with(|| rehydrated.unwrap_or_default());
            (state.prior_hash.clone(), state.next_message_number)
        };
        drop(guard);
        Ok(expectation)
    }

    /// Drop the cached send + recv chain cursors for `peer` (D0031) so a
    /// subsequent re-pair with the same operational identity restarts at the
    /// genesis chain (empty `prior_hash`, message 0). Without this the stale
    /// cursors would still expect the purged history's last
    /// `prior_envelope_hash`, raising an [`SimplexAdapterError::EnvelopeChainGap`]
    /// on the first recv after a re-pair (or chaining a new send onto a
    /// no-longer-persisted prior).
    fn forget_chain_state(&self, peer: &[u8; PUBLIC_KEY_LEN]) -> Result<(), SimplexAdapterError> {
        self.send_chains
            .lock()
            .map_err(|_| poisoned_chain_error())?
            .remove(peer);
        self.recv_chains
            .lock()
            .map_err(|_| poisoned_chain_error())?
            .remove(peer);
        Ok(())
    }
}

/// Record the new chain cursor after a successful send/recv.
fn advance_chain(
    chains: &Mutex<HashMap<[u8; PUBLIC_KEY_LEN], ChainState>>,
    peer: [u8; PUBLIC_KEY_LEN],
    next_hash: [u8; 32],
    used_number: u64,
) -> Result<(), SimplexAdapterError> {
    let mut guard = chains.lock().map_err(|_| poisoned_chain_error())?;
    guard.insert(
        peer,
        ChainState {
            prior_hash: next_hash.to_vec(),
            next_message_number: used_number.saturating_add(1),
        },
    );
    drop(guard);
    Ok(())
}

/// Rebuild a chain cursor for the `(sender, recipient)` pair from the
/// persisted `MESSAGES` history (D0026 §3.2 / §4) — the lazy cross-restart
/// rehydration of [`SimplexAdapter`]'s in-memory cursor.
///
/// Walks message numbers from 0 until the first gap. Messages are stored
/// strictly in order (the recv chain-gap check rejects out-of-order
/// delivery, and send numbers are the transport's contiguous per-pair
/// counter), so the contiguous prefix IS the full chain; the cursor is
/// derived from the last envelope's [`next_prior_envelope_hash`]. Returns
/// `None` if the pair has no stored history (a genesis chain).
///
/// `O(N)` in the pair's message count, run once per pair on the first
/// chain access after a restart. (A per-pair cursor record would make it
/// `O(1)` at the cost of a write per message — a follow-up if message
/// volume warrants it.)
fn rehydrate_chain(
    storage: &Storage,
    sender_operational_pubkey: &[u8; PUBLIC_KEY_LEN],
    recipient_operational_pubkey: &[u8; PUBLIC_KEY_LEN],
) -> Result<Option<ChainState>, SimplexAdapterError> {
    let mut message_number = 0u64;
    let mut last: Option<(Vec<u8>, u64)> = None;
    loop {
        let record_id = message_record_id_for(
            sender_operational_pubkey,
            recipient_operational_pubkey,
            message_number,
        );
        match storage.get(categories::MESSAGES, &record_id) {
            Ok(cose) => {
                last = Some((cose.to_vec(), message_number));
                message_number = message_number.saturating_add(1);
            }
            Err(StorageError::RecordNotFound { .. }) => break,
            Err(e) => return Err(SimplexAdapterError::from(e)),
        }
    }
    match last {
        Some((cose, number)) => Ok(Some(ChainState {
            prior_hash: next_prior_envelope_hash(&cose)?.to_vec(),
            // After the contiguous `0..=number` prefix, the next chain
            // position is `number + 1`.
            next_message_number: number.saturating_add(1),
        })),
        None => Ok(None),
    }
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
    use cairn_crypto::ed25519::SigningKey;
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
                device_signer: Arc::new(device_sk),
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

    /// A 1:1-identity party (operational pubkey == device signing key, the
    /// D0028 demo model). This is the only model `recv_learning_sender` /
    /// `verify_envelope_learning_sender` can verify, because the embedded
    /// operational key doubles as the COSE verification key.
    fn make_party_1to1(seed: [u8; 32], transport: MockSidecarTransport) -> Party {
        let device_sk = SigningKey::from_seed(&Zeroizing::new(seed));
        let device_vk = device_sk.verifying_key();
        let config = SimplexAdapterConfig {
            identity: LocalIdentity {
                device_signer: Arc::new(device_sk),
                operational_pubkey: device_vk.to_bytes(),
            },
            storage: make_storage(),
            default_retry_budget: RetryBudget::default(),
        };
        Party {
            device_vk,
            operational_pubkey: device_vk.to_bytes(),
            adapter: SimplexAdapter::new(transport, config).unwrap(),
        }
    }

    /// The `(device_vk, operational_pubkey)` a fixed `seed` derives (the
    /// same derivation `make_party_from_seed` uses).
    fn identity_for_seed(seed: [u8; 32]) -> (VerifyingKey, [u8; PUBLIC_KEY_LEN]) {
        let device_vk = SigningKey::from_seed(&Zeroizing::new(seed)).verifying_key();
        let mut op_seed = seed;
        op_seed[0] ^= 0xFF;
        let operational_pubkey = SigningKey::from_seed(&Zeroizing::new(op_seed))
            .verifying_key()
            .to_bytes();
        (device_vk, operational_pubkey)
    }

    /// Build an adapter with a FIXED `seed` identity over a SHARED
    /// `storage` — used to simulate a process restart (same identity +
    /// same persistent MESSAGES, fresh in-memory chains).
    fn make_adapter_with_storage(
        seed: [u8; 32],
        transport: MockSidecarTransport,
        storage: Arc<Storage>,
    ) -> SimplexAdapter<MockSidecarTransport> {
        let device_signing_key = SigningKey::from_seed(&Zeroizing::new(seed));
        let (_, operational_pubkey) = identity_for_seed(seed);
        let config = SimplexAdapterConfig {
            identity: LocalIdentity {
                device_signer: Arc::new(device_signing_key),
                operational_pubkey,
            },
            storage,
            default_retry_budget: RetryBudget::default(),
        };
        SimplexAdapter::new(transport, config).unwrap()
    }

    #[tokio::test]
    async fn send_chain_rehydrates_from_messages_after_restart() {
        // Alice sends msg-1, then "restarts" (a fresh adapter with the
        // SAME identity + SAME storage but empty in-memory chains) and
        // sends msg-2. Bob receives both in order: msg-2 verifies only if
        // its prior_envelope_hash links to msg-1 — i.e. the restarted
        // adapter rebuilt the send-chain cursor from the MESSAGES history
        // rather than starting a fresh genesis chain (which would make
        // Bob's recv of msg-2 raise EnvelopeChainGap).
        let wire = MockSidecarTransport::new();
        let storage = make_storage();
        let conn = ConnectionId("conn-restart".to_string());

        let alice_seed = [7u8; 32];
        let (alice_vk, alice_op) = identity_for_seed(alice_seed);
        let bob = make_party(wire.clone());

        let alice1 = make_adapter_with_storage(alice_seed, wire.clone(), storage.clone());
        alice1
            .send(&conn, &bob.operational_pubkey, b"msg-1")
            .await
            .unwrap();
        drop(alice1); // simulate process exit: in-memory chains gone.

        let alice2 = make_adapter_with_storage(alice_seed, wire.clone(), storage.clone());
        alice2
            .send(&conn, &bob.operational_pubkey, b"msg-2")
            .await
            .unwrap();

        let r1 = bob.adapter.recv(&conn, &alice_op, &alice_vk).await.unwrap();
        assert_eq!(r1.payload, b"msg-1");
        let r2 = bob.adapter.recv(&conn, &alice_op, &alice_vk).await.unwrap();
        assert_eq!(r2.payload, b"msg-2");
    }

    #[tokio::test]
    async fn recv_chain_rehydrates_from_messages_after_restart() {
        // Symmetric to the send case: Bob receives msg-1, "restarts", then
        // receives msg-2. The restarted recv chain must expect msg-2's
        // prior_envelope_hash (linking to msg-1) — rebuilt from the
        // MESSAGES history — or it would raise EnvelopeChainGap.
        let wire = MockSidecarTransport::new();
        let bob_storage = make_storage();
        let conn = ConnectionId("conn-restart-recv".to_string());

        let alice = make_party(wire.clone());
        let bob_seed = [9u8; 32];
        let (_bob_vk, bob_op) = identity_for_seed(bob_seed);

        alice.adapter.send(&conn, &bob_op, b"msg-1").await.unwrap();
        alice.adapter.send(&conn, &bob_op, b"msg-2").await.unwrap();

        let bob1 = make_adapter_with_storage(bob_seed, wire.clone(), bob_storage.clone());
        let r1 = bob1
            .recv(&conn, &alice.operational_pubkey, &alice.device_vk)
            .await
            .unwrap();
        assert_eq!(r1.payload, b"msg-1");
        drop(bob1); // restart: recv-chain cursor lost from memory.

        let bob2 = make_adapter_with_storage(bob_seed, wire.clone(), bob_storage.clone());
        let r2 = bob2
            .recv(&conn, &alice.operational_pubkey, &alice.device_vk)
            .await
            .unwrap();
        assert_eq!(r2.payload, b"msg-2");
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
    async fn recv_learning_sender_learns_sender_on_first_contact() {
        // TOFU (D0026 §12): bob receives WITHOUT pre-knowing alice's key,
        // learning it from the envelope. Requires the 1:1 identity model
        // (op == device) so the embedded operational key verifies the COSE.
        let wire = MockSidecarTransport::new();
        let alice = make_party_1to1([7u8; 32], wire.clone());
        let bob = make_party_1to1([9u8; 32], wire.clone());
        let conn = ConnectionId("conn-1".to_string());

        alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"hello bob")
            .await
            .unwrap();

        let received = bob.adapter.recv_learning_sender(&conn).await.unwrap();
        assert_eq!(received.payload, b"hello bob");
        assert_eq!(received.sender_operational_pubkey, alice.operational_pubkey);
    }

    #[tokio::test]
    async fn recv_learning_sender_rejects_op_ne_device_envelope() {
        // Safety-by-construction: under op≠device the envelope is signed by the
        // device key but carries the (different) operational key, so verifying
        // the signature against the embedded operational key FAILS — no sender
        // is wrongly learned. `make_party` is deliberately op≠device.
        let wire = MockSidecarTransport::new();
        let alice = make_party(wire.clone());
        let bob = make_party(wire.clone());
        let conn = ConnectionId("conn-1".to_string());

        alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"hi")
            .await
            .unwrap();
        let err = bob.adapter.recv_learning_sender(&conn).await.unwrap_err();
        assert!(
            matches!(err, SimplexAdapterError::EnvelopeSignatureVerifyFailed),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn load_message_history_returns_both_directions() {
        let wire = MockSidecarTransport::new();
        let alice = make_party_1to1([1u8; 32], wire.clone());
        let bob = make_party_1to1([2u8; 32], wire.clone());
        let conn = ConnectionId("c".to_string());

        // alice -> bob, then bob -> alice (each side persists its own view).
        alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"a1")
            .await
            .unwrap();
        bob.adapter.recv_learning_sender(&conn).await.unwrap();
        bob.adapter
            .send(&conn, &alice.operational_pubkey, b"b1")
            .await
            .unwrap();
        alice
            .adapter
            .recv(&conn, &bob.operational_pubkey, &bob.device_vk)
            .await
            .unwrap();

        // From alice's store: her outgoing "a1" (mine) + her incoming "b1".
        let hist = alice
            .adapter
            .load_message_history(&bob.operational_pubkey)
            .unwrap();
        assert_eq!(hist.messages.len(), 2);
        assert!(hist.messages.iter().any(|m| m.mine && m.payload == b"a1"));
        assert!(hist.messages.iter().any(|m| !m.mine && m.payload == b"b1"));
        // No read receipts flowed, so no peer read high-water.
        assert_eq!(hist.peer_read_up_to, None);
    }

    #[tokio::test]
    async fn load_message_history_skips_zero_length_hello() {
        let wire = MockSidecarTransport::new();
        let alice = make_party_1to1([3u8; 32], wire.clone());
        let bob = make_party_1to1([4u8; 32], wire.clone());
        let conn = ConnectionId("c".to_string());
        // The 0-length pairing hello (D0026 §12), then a real message.
        alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"")
            .await
            .unwrap();
        alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"real")
            .await
            .unwrap();
        let hist = alice
            .adapter
            .load_message_history(&bob.operational_pubkey)
            .unwrap();
        assert_eq!(hist.messages.len(), 1);
        assert_eq!(hist.messages[0].payload, b"real");
    }

    #[tokio::test]
    async fn purge_conversation_deletes_both_directions_and_tears_down() {
        // The deeper delete-purge (D0031): purging alice's conversation with bob
        // wipes BOTH directed MESSAGES chains from alice's store AND tears down
        // the SimpleX-side connection — while bob's own store is untouched (the
        // purge is local to the deleting party).
        let wire = MockSidecarTransport::new();
        let alice = make_party_1to1([5u8; 32], wire.clone());
        let bob = make_party_1to1([6u8; 32], wire.clone());
        let conn = ConnectionId("c".to_string());

        // A two-way exchange, so alice's store holds an outgoing AND an incoming.
        alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"a1")
            .await
            .unwrap();
        bob.adapter.recv_learning_sender(&conn).await.unwrap();
        bob.adapter
            .send(&conn, &alice.operational_pubkey, b"b1")
            .await
            .unwrap();
        alice
            .adapter
            .recv(&conn, &bob.operational_pubkey, &bob.device_vk)
            .await
            .unwrap();
        assert_eq!(
            alice
                .adapter
                .load_message_history(&bob.operational_pubkey)
                .unwrap()
                .messages
                .len(),
            2,
            "precondition: alice sees both directions"
        );

        alice
            .adapter
            .purge_conversation(&conn, &bob.operational_pubkey)
            .await
            .unwrap();

        assert!(
            alice
                .adapter
                .load_message_history(&bob.operational_pubkey)
                .unwrap()
                .messages
                .is_empty(),
            "alice's history with bob must be gone after the purge"
        );
        // The SimpleX-side teardown reached the transport (best-effort half).
        assert_eq!(wire.deleted_connections(), vec![conn.clone()]);
        // Bob's store is untouched — the purge only wipes the deleting side.
        assert_eq!(
            bob.adapter
                .load_message_history(&alice.operational_pubkey)
                .unwrap()
                .messages
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn purge_conversation_resets_send_chain_to_genesis() {
        // After a purge, the in-memory chain cursor is dropped AND no MESSAGES
        // remain to rehydrate from, so a fresh send to the same peer restarts at
        // the genesis chain (message number 0) — what a clean re-pair needs.
        let wire = MockSidecarTransport::new();
        let alice = make_party_1to1([7u8; 32], wire.clone());
        let bob = make_party_1to1([8u8; 32], wire.clone());
        let conn = ConnectionId("c".to_string());

        alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"m0")
            .await
            .unwrap();
        let before = alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"m1")
            .await
            .unwrap();
        assert_eq!(before.next_message_number, 2, "chain advanced to 2");

        alice
            .adapter
            .purge_conversation(&conn, &bob.operational_pubkey)
            .await
            .unwrap();

        let after = alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"again")
            .await
            .unwrap();
        assert_eq!(
            after.next_message_number, 1,
            "after purge the send chain restarts at message 0 (genesis)"
        );
    }

    #[tokio::test]
    async fn repair_after_one_sided_delete_round_trips_both_directions() {
        // The D0031 re-pair desync: A deletes B (purge → A's chains reset to
        // genesis), B keeps its advanced chains. On re-pair the handshake
        // envelopes carry priors that don't link to the other side's cursor —
        // but the pairing path (`recv_learning_sender`) re-anchors, so BOTH
        // directions flow again. Each side's FIRST recv of a (re-)pairing goes
        // through `recv_learning_sender` (the inviter to learn; the acceptor to
        // re-anchor); steady-state `recv` stays strict (proven separately by
        // `out_of_chain_envelope_surfaces_chain_gap`).
        let wire = MockSidecarTransport::new();
        let alice = make_party_1to1([20u8; 32], wire.clone());
        let bob = make_party_1to1([21u8; 32], wire.clone());
        let conn1 = ConnectionId("pair-1".to_string());

        // --- Original pairing: advance BOTH chains a few steps. ---
        // B (acceptor) sends the hello; A (inviter) learns + anchors.
        bob.adapter
            .send(&conn1, &alice.operational_pubkey, b"")
            .await
            .unwrap();
        let learned = alice.adapter.recv_learning_sender(&conn1).await.unwrap();
        assert_eq!(learned.sender_operational_pubkey, bob.operational_pubkey);
        // A → B content; B's first recv (acceptor) re-anchors on it.
        alice
            .adapter
            .send(&conn1, &bob.operational_pubkey, b"a-hi")
            .await
            .unwrap();
        let b0 = bob.adapter.recv_learning_sender(&conn1).await.unwrap();
        assert_eq!(b0.payload, b"a-hi");
        // Steady both ways → advance the chains further.
        bob.adapter
            .send(&conn1, &alice.operational_pubkey, b"b-yo")
            .await
            .unwrap();
        alice
            .adapter
            .recv(&conn1, &bob.operational_pubkey, &bob.device_vk)
            .await
            .unwrap();
        alice
            .adapter
            .send(&conn1, &bob.operational_pubkey, b"a-2")
            .await
            .unwrap();
        bob.adapter
            .recv(&conn1, &alice.operational_pubkey, &alice.device_vk)
            .await
            .unwrap();

        // --- A deletes B (one-sided): purge resets A's chains + history;
        //     B keeps everything (its chains stay advanced via rehydration). ---
        alice
            .adapter
            .purge_conversation(&conn1, &bob.operational_pubkey)
            .await
            .unwrap();

        // --- RE-PAIR on a fresh connection. A = inviter (genesis), B = acceptor
        //     (still advanced). ---
        let conn2 = ConnectionId("pair-2".to_string());
        // B's hello chains from B's STALE (advanced) send cursor → non-empty prior.
        bob.adapter
            .send(&conn2, &alice.operational_pubkey, b"")
            .await
            .unwrap();
        // Direction 1 (the reported bug): BEFORE the fix this raised
        // EnvelopeChainGap (A's genesis recv ≠ B's stale prior). The re-anchor
        // accepts it.
        let relearned = alice.adapter.recv_learning_sender(&conn2).await.unwrap();
        assert_eq!(
            relearned.sender_operational_pubkey, bob.operational_pubkey,
            "A re-learns B on re-pair (no chain gap)"
        );

        // Direction 2 (the symmetric residual): A sends genesis content
        // (purged). B's first recv of the re-pair re-anchors (acceptor learning
        // path) — accepts despite B's stale recv chain. BEFORE the fix B's
        // steady recv raised EnvelopeChainGap here → A→B silently dropped.
        alice
            .adapter
            .send(&conn2, &bob.operational_pubkey, b"again-1")
            .await
            .unwrap();
        let b_re = bob.adapter.recv_learning_sender(&conn2).await.unwrap();
        assert_eq!(b_re.payload, b"again-1", "A→B flows after re-anchor");

        // --- Steady-state both ways now LINK strictly (the re-anchor set both
        //     sides' cursors); no further re-anchor needed. ---
        alice
            .adapter
            .send(&conn2, &bob.operational_pubkey, b"again-2")
            .await
            .unwrap();
        let b_s = bob
            .adapter
            .recv(&conn2, &alice.operational_pubkey, &alice.device_vk)
            .await
            .unwrap();
        assert_eq!(b_s.payload, b"again-2", "A→B steady links after re-pair");
        bob.adapter
            .send(&conn2, &alice.operational_pubkey, b"b-reply")
            .await
            .unwrap();
        let a_s = alice
            .adapter
            .recv(&conn2, &bob.operational_pubkey, &bob.device_vk)
            .await
            .unwrap();
        assert_eq!(a_s.payload, b"b-reply", "B→A steady links after re-pair");
    }

    #[tokio::test]
    async fn send_read_receipt_round_trips_read_up_to() {
        // bob sends two messages to alice; alice acks → bob receives an
        // empty-payload envelope carrying read_up_to = the high-water (1, the
        // last received number), proving the D0032 read-receipt mechanism.
        let wire = MockSidecarTransport::new();
        let alice = make_party_1to1([10u8; 32], wire.clone());
        let bob = make_party_1to1([11u8; 32], wire.clone());
        let conn = ConnectionId("c".to_string());

        bob.adapter
            .send(&conn, &alice.operational_pubkey, b"m0")
            .await
            .unwrap();
        bob.adapter
            .send(&conn, &alice.operational_pubkey, b"m1")
            .await
            .unwrap();
        alice
            .adapter
            .recv(&conn, &bob.operational_pubkey, &bob.device_vk)
            .await
            .unwrap();
        alice
            .adapter
            .recv(&conn, &bob.operational_pubkey, &bob.device_vk)
            .await
            .unwrap();

        alice
            .adapter
            .send_read_receipt(&conn, &bob.operational_pubkey)
            .await
            .unwrap();

        let receipt = bob
            .adapter
            .recv(&conn, &alice.operational_pubkey, &alice.device_vk)
            .await
            .unwrap();
        assert_eq!(receipt.read_up_to, Some(1), "acks up to the last received");
        assert!(receipt.payload.is_empty(), "a receipt carries no content");
    }

    #[tokio::test]
    async fn send_read_receipt_is_noop_when_nothing_received() {
        // With nothing received from bob, alice's ack is a no-op — no envelope
        // is enqueued, so bob's recv finds nothing.
        let wire = MockSidecarTransport::new();
        let alice = make_party_1to1([12u8; 32], wire.clone());
        let bob = make_party_1to1([13u8; 32], wire.clone());
        let conn = ConnectionId("c".to_string());

        alice
            .adapter
            .send_read_receipt(&conn, &bob.operational_pubkey)
            .await
            .unwrap();
        let got = bob
            .adapter
            .recv(&conn, &alice.operational_pubkey, &alice.device_vk)
            .await;
        assert!(got.is_err(), "no receipt is sent when nothing was received");
    }

    #[tokio::test]
    async fn load_message_history_reconstructs_peer_read_up_to() {
        // alice sends two; bob reads + acks; alice receives the ack. alice's
        // history then shows her two sent messages AND peer_read_up_to = 1 (so a
        // re-opened conversation can mark sent ≤ 1 as read) — and the receipt is
        // NOT surfaced as a message.
        let wire = MockSidecarTransport::new();
        let alice = make_party_1to1([14u8; 32], wire.clone());
        let bob = make_party_1to1([15u8; 32], wire.clone());
        let conn = ConnectionId("c".to_string());

        alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"a0")
            .await
            .unwrap();
        alice
            .adapter
            .send(&conn, &bob.operational_pubkey, b"a1")
            .await
            .unwrap();
        bob.adapter
            .recv(&conn, &alice.operational_pubkey, &alice.device_vk)
            .await
            .unwrap();
        bob.adapter
            .recv(&conn, &alice.operational_pubkey, &alice.device_vk)
            .await
            .unwrap();
        bob.adapter
            .send_read_receipt(&conn, &alice.operational_pubkey)
            .await
            .unwrap();
        alice
            .adapter
            .recv(&conn, &bob.operational_pubkey, &bob.device_vk)
            .await
            .unwrap();

        let hist = alice
            .adapter
            .load_message_history(&bob.operational_pubkey)
            .unwrap();
        assert_eq!(hist.messages.len(), 2, "the receipt is not a message");
        assert!(hist.messages.iter().all(|m| m.mine));
        assert_eq!(
            hist.peer_read_up_to,
            Some(1),
            "the peer's read high-water is reconstructed from its receipt"
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
    async fn simploxide_transport_unreachable_sidecar_is_sidecar_unavailable() {
        // With no SimpleX Chat CLI listening, the lazy ws-core dial fails and
        // the transport surfaces SidecarUnavailable (not a panic, not the old
        // NetworkUnreached stub). Port 1 is deterministically closed, so this
        // stays hermetic (localhost refusal, no external network). Live
        // two-party behavior is the integration-tests gate (D0026 §12).
        use crate::sidecar::SimploxideTransport;
        let transport = SimploxideTransport::new(SidecarEndpoint {
            host: "127.0.0.1".to_string(),
            port: 1,
        });
        let config = SimplexAdapterConfig {
            identity: LocalIdentity {
                device_signer: Arc::new(SigningKey::generate(&mut OsRng)),
                operational_pubkey: [0u8; PUBLIC_KEY_LEN],
            },
            storage: make_storage(),
            default_retry_budget: RetryBudget::default(),
        };
        let adapter = SimplexAdapter::new(transport, config).unwrap();
        let result = adapter.create_invitation().await;
        assert!(
            matches!(result, Err(SimplexAdapterError::SidecarUnavailable)),
            "got {result:?}"
        );
    }

    #[test]
    fn default_sidecar_endpoint_is_loopback_5225() {
        let ep = SidecarEndpoint::default();
        assert_eq!(ep.host, "127.0.0.1");
        assert_eq!(ep.port, 5225);
    }
}
