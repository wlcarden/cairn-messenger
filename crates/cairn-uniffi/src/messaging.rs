// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Messaging export surface (D0027 §2 — the `messaging` module).
//!
//! [`SimplexAdapterHandle`] over `cairn_simplex_adapter::SimplexAdapter`
//! — the last per-domain async Object. `create_invitation` /
//! `accept_invitation` / `send` / `recv` export as Kotlin `suspend fun`s
//! (`#[uniffi::export(async_runtime = "tokio")]` per D0027 §5).
//!
//! ## Hardware-signed envelopes (the security boundary)
//!
//! Each message envelope's `COSE_Sign1` is signed by the DEVICE key,
//! which lives in StrongBox (D0020 §3.4 / D0006 §9). So the handle does
//! NOT hold a software signing key — it takes the
//! [`crate::hardware::HardwareKeySigner`] callback, bridged into
//! `cairn_simplex_adapter::EnvelopeSigner` by `FfiEnvelopeSigner`. The
//! adapter builds the COSE `Sig_structure` Rust-side, the key signs it in
//! hardware, and only the 64-byte signature crosses back (D0026 §2.3 /
//! D0018 §2.2). This is what lets the handle be CONSTRUCTED at all: the
//! adapter's `LocalIdentity` takes an `Arc<dyn EnvelopeSigner>`, never a
//! `SigningKey` (which is `NeverExport` and cannot cross the boundary).
//! This is the third instance of the hardware-callback-signing pattern,
//! after the identity op-key and transparency's `TreeLeafSigner`.
//!
//! ## Shared storage
//!
//! The handle shares the [`crate::storage::StorageHandle`]'s
//! `Arc<Storage>` (via the crate-internal `storage_arc` accessor) so the
//! Cairn message history (the `MESSAGES` category, D0026 §4) lives in the
//! same unlocked store as the rest of the app — no second connection.
//!
//! ## Transport (per-target; live two-party gated on the daemon)
//!
//! The concrete transport is selected by target (the `MessagingTransport`
//! alias, D0026 §12), but the handle's async surface is identical across both:
//! - **Android:** `FfiSidecarTransport` — the in-process JNI `libsimplex`
//!   (there is no Android CLI binary). Brought up from `config.db_path` +
//!   `config.files_dir`. Its `simploxide-ffi-core` dep is target-gated, so the
//!   desktop/CI host never builds it; on-device link + run is the APK cycle.
//! - **Desktop / dev / CI:** `SimploxideTransport` — a real
//!   `simploxide-ws-core` WebSocket client of the SimpleX Chat CLI sidecar
//!   (`config.host` + `config.port`).
//!
//! The ws-core transport lazily dials `ws://host:port`, issues simplex-chat
//! commands, and drains events. With no sidecar listening, `create_invitation` /
//! `accept_invitation` / `send` / `recv` surface
//! [`CairnFfiError::SidecarFailure`] (the facade mapping of the transport's
//! `SidecarUnavailable`). The handle's construction + the full envelope
//! build → sign → pad → persist → chain-advance path are real + exercised: a
//! `send` invokes the StrongBox-signing callback (and persists the envelope)
//! BEFORE it reaches the transport's network hop. Live two-party messaging
//! is validated under the adapter's `integration-tests` feature against a
//! running SimpleX Chat CLI (D0026 §12), not in unit tests.

use std::sync::Arc;

use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, SIGNATURE_LEN, VerifyingKey};
use cairn_simplex_adapter::{
    ConnectionId, ConversationHistory, EnvelopeSigner, HistoryMessage, Invitation, LocalIdentity,
    RetryBudget, SimplexAdapter, SimplexAdapterConfig, SimplexAdapterError,
};
// The concrete transport is selected per target (D0026 §12): the ws-core
// CLI-sidecar client for desktop/dev/CI, the in-process JNI `libsimplex`
// transport on Android (whose `simploxide-ffi-core` dep is target-gated, so
// the desktop/CI host never builds it).
#[cfg(target_os = "android")]
use cairn_simplex_adapter::FfiSidecarTransport;
#[cfg(not(target_os = "android"))]
use cairn_simplex_adapter::{SidecarEndpoint, SimploxideTransport};
#[cfg(target_os = "android")]
use std::path::PathBuf;
// Two-party loopback selftest deps (D0026 §12) — Android only, like the
// in-process FFI transport they drive.
#[cfg(target_os = "android")]
use cairn_crypto::ed25519::SigningKey;
#[cfg(target_os = "android")]
use cairn_storage::{Storage, key_provider::testing::InMemoryKeyProvider};
#[cfg(target_os = "android")]
use zeroize::Zeroizing;

use crate::error::CairnFfiError;
use crate::hardware::HardwareKeySigner;
use crate::storage::StorageHandle;

// The messaging `SidecarTransport` selected for this build target (D0026 §12):
// the Android in-process FFI transport on-device, the ws-core CLI-sidecar
// transport everywhere else. `SimplexAdapterHandle`'s export surface is
// identical across both — only the bring-up (in-process `init` vs a WebSocket
// dial) differs.
#[cfg(target_os = "android")]
type MessagingTransport = FfiSidecarTransport;
#[cfg(not(target_os = "android"))]
type MessagingTransport = SimploxideTransport;

/// Transport + retry configuration for the messaging handle (D0027 §2.2).
///
/// All public values; becomes a `uniffi::Record`. The struct carries the
/// inputs for BOTH transports (D0026 §12); each build
/// target reads only its relevant subset and ignores the rest (only one
/// transport is compiled per target):
/// - **Desktop / dev / CI (ws-core):** `host` + `port` address the SimpleX
///   Chat CLI sidecar (loopback default `127.0.0.1:5225`, D0020 §1.1); the
///   external CLI owns its own DB + file staging, so `db_path` / `files_dir`
///   are ignored.
/// - **Android (in-process FFI):** `db_path` + `files_dir` are app-private
///   paths for the in-process `libsimplex` chat DB + `CryptoFile`/XFTP staging
///   (there is no CLI process, so `host` / `port` are ignored).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct SidecarEndpointConfig {
    /// ws-core (desktop) transport: loopback host of the CLI sidecar
    /// (default `127.0.0.1`). Ignored by the Android in-process transport.
    pub host: String,
    /// ws-core (desktop) transport: loopback port (default `5225`).
    /// Ignored by the Android in-process transport.
    pub port: u16,
    /// Android (in-process FFI) transport: app-private DB-path PREFIX for the
    /// in-process `libsimplex` chat DB (D0026 §12). Ignored by the ws-core
    /// transport (the external CLI owns its DB).
    pub db_path: String,
    /// Android (in-process FFI) transport: directory for `CryptoFile`/XFTP
    /// payload staging (D0026 §2.4). Ignored by the ws-core transport (which
    /// stages under the OS temp dir).
    pub files_dir: String,
    /// Optional SOCKS5 proxy `<ip>:<port>` for Tor routing (D0020 §2.2).
    /// **Android (in-process FFI):** issued as a `/network socks=` command at
    /// bring-up so outbound SMP/XFTP traffic (incl. the `.onion` relays) routes
    /// over Tor; `None` = direct connections. **Desktop / CI (ws-core):**
    /// ignored — the external CLI owns its own network config.
    pub socks_proxy: Option<String>,
    /// Optional SQLCipher passphrase for the at-rest chat DB (D0006 §3.5 / D0022 §2.2).
    /// **Android (in-process FFI):** `Some` opens the in-process `libsimplex`
    /// chat DB with `DbOpts::encrypted` (AES-encrypted SMP-agent/chat databases
    /// on disk); `None` opens it unencrypted. Supplied by the storage layer (a
    /// demo passphrase now; the Argon2id storage KEK in v1). **Desktop / CI
    /// (ws-core):** ignored — the external CLI owns its own DB. A DB first
    /// created unencrypted cannot later be opened encrypted (fresh installs
    /// only).
    pub db_key: Option<String>,
    /// Maximum send/recv retry attempts (backoff uses the D0023 §5.3
    /// defaults).
    pub max_retries: u8,
}

/// Bridges a [`HardwareKeySigner`] callback into the
/// `cairn_simplex_adapter::EnvelopeSigner` the adapter's send path
/// consumes. The device key signs the envelope COSE `Sig_structure` in
/// StrongBox; only the signature bytes cross (D0026 §2.3).
struct FfiEnvelopeSigner {
    signer: Box<dyn HardwareKeySigner>,
    key_alias: String,
}

impl EnvelopeSigner for FfiEnvelopeSigner {
    fn sign_envelope(
        &self,
        signing_input: &[u8],
    ) -> Result<[u8; SIGNATURE_LEN], SimplexAdapterError> {
        let signature = self
            .signer
            .sign(self.key_alias.clone(), signing_input.to_vec())
            .map_err(|_| SimplexAdapterError::EnvelopeSignatureVerifyFailed)?;
        signature
            .as_slice()
            .try_into()
            .map_err(|_| SimplexAdapterError::EnvelopeSignatureVerifyFailed)
    }
}

/// Outcome of a successful [`SimplexAdapterHandle::send`] (D0027 §2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct MessageSentRecord {
    /// The 32-byte `MESSAGES` record id the sent envelope was persisted
    /// under (D0026 §4).
    pub record_id: Vec<u8>,
    /// The next per-`(sender, recipient)` message number the chain
    /// advanced to.
    pub next_message_number: u64,
}

/// A received + verified message (D0027 §2.2). All fields public: the
/// sender's operational pubkey, the application payload (padding
/// stripped), and the receive-side wall-clock timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct ReceivedMessageRecord {
    /// Sender's operational-identity pubkey (32 bytes; D0026 §2.1 key 2).
    pub sender_operational_pubkey: Vec<u8>,
    /// Application-level payload (padding stripped on receive). Empty for a
    /// read receipt (D0032), where `read_up_to` is `Some`.
    pub payload: Vec<u8>,
    /// Receive-side Unix-seconds timestamp.
    pub received_at_unix: u64,
    /// `Some(n)` if this is a read receipt (D0032): the sender has read this
    /// side's messages up to number `n`. The caller marks its outgoing messages
    /// ≤ `n` as read (and must NOT treat it as a content message). `None` for a
    /// normal message.
    pub read_up_to: Option<u64>,
    /// `Some(bytes)` if this is a provenance vouch (D0036): the `{op_chain,
    /// token}` blob the sender shared. The caller routes it to
    /// `TrustGraphHandle::ingest_vouch` (the sender is already authenticated by
    /// the envelope signature), NOT to the message list. `None` otherwise.
    pub vouch: Option<Vec<u8>>,
    /// `Some(bytes)` if this is an introduction control message (D0037): the
    /// canonical-CBOR introduction blob the sender sent. The caller routes it to
    /// `decode_introduction` + the dual-consent flow (the sender is already
    /// authenticated by the envelope signature), NOT to the message list. `None`
    /// otherwise.
    pub introduction: Option<Vec<u8>>,
    /// `Some(bytes)` if this is a recovery share (D0038 §7): one recovery card a
    /// contact entrusted to this side to HOLD, or RETURNed during recovery. The
    /// caller stores it (hold) or feeds it into the recovery reconstruct flow
    /// (return), NOT the message list. `None` otherwise.
    pub recovery_share: Option<Vec<u8>>,
    /// `Some(bytes)` if this is a recovery request (D0038 §7): a contact is asking
    /// this side to return the recovery share it holds for them. The caller
    /// surfaces a manual-approval prompt (Stage 2). `None` otherwise.
    pub recovery_request: Option<Vec<u8>>,
    /// `Some(bytes)` if this is a recovery re-split control message (D0040 §5 /
    /// 3c): `[kind(1)][resplit_id(16)]` (PREPARE / ACK / COMMIT / DISCARD). A
    /// PREPARE arrives alongside `recovery_share` (the new card in key 11); the
    /// caller routes a `Some` to the two-phase re-split orchestration (store
    /// pending / ACK / promote-on-COMMIT / discard-on-DISCARD), NOT the message
    /// list. `None` otherwise.
    pub recovery_control: Option<Vec<u8>>,
}

/// One persisted message in a conversation's history (D0026 §3.2).
///
/// For the contact-list / conversation-resume UI. `mine` distinguishes the
/// sent vs received direction; the payload is decoded (already verified when
/// it flowed) and the timestamp is the envelope's construction time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct HistoryMessageRecord {
    /// `true` if this side SENT the message (outgoing); `false` if received.
    pub mine: bool,
    /// Application-level payload (padding stripped).
    pub payload: Vec<u8>,
    /// Envelope construction Unix-seconds timestamp.
    pub timestamp_unix: u64,
    /// This message's position on its directed chain (D0026 §3.2). For a `mine`
    /// (outgoing) message it is compared against the peer's read high-water to
    /// mark it read (D0032).
    pub message_number: u64,
}

/// A conversation's history plus the peer's read high-water (D0032), the
/// result of [`SimplexAdapterHandle::load_message_history`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct ConversationHistoryRecord {
    /// Content messages both directions, chronological (read receipts skipped).
    pub messages: Vec<HistoryMessageRecord>,
    /// The highest outgoing message number the peer has acknowledged reading,
    /// or `None`. Lets a re-opened conversation reconstruct which sent messages
    /// show "read" (D0032) — applied only when the local read-receipts setting
    /// is on (the reciprocal display half is a Kotlin policy).
    pub peer_read_up_to: Option<u64>,
}

/// An opaque async handle to the Cairn SimpleX messaging adapter (D0027 §2.2).
///
/// Built over the per-target `MessagingTransport` (D0026 §12): the in-process
/// FFI transport on Android, the ws-core CLI-sidecar transport elsewhere. The
/// async export surface is identical across both.
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Object))]
pub struct SimplexAdapterHandle {
    adapter: SimplexAdapter<MessagingTransport>,
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
impl SimplexAdapterHandle {
    /// Construct the messaging handle over `storage`'s shared store, with
    /// device-key envelope signing mediated by the StrongBox `signer`
    /// callback (the key never crosses; D0026 §2.3).
    ///
    /// `device_key_alias` names the StrongBox device key; `operational_pubkey`
    /// is this identity's 32-byte operational-identity public key (the
    /// envelope sender field + the message-history record-id, D0026 §2.1
    /// key 2).
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `operational_pubkey` is not
    ///   exactly [`PUBLIC_KEY_LEN`] (32) bytes.
    /// - The facade mapping of any `SimplexAdapterError` from adapter
    ///   construction.
    #[cfg_attr(feature = "uniffi-bindings", uniffi::constructor)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI constructors take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub fn new(
        storage: Arc<StorageHandle>,
        signer: Box<dyn HardwareKeySigner>,
        device_key_alias: String,
        operational_pubkey: Vec<u8>,
        config: SidecarEndpointConfig,
    ) -> Result<Arc<Self>, CairnFfiError> {
        // Install the logcat backend for the `log` facade so the adapter's SMP
        // command/event flow surfaces on-device under the `CairnRust` tag
        // (D0026 §12 two-party observability). Idempotent; android-only.
        #[cfg(target_os = "android")]
        crate::android_log::init();

        let operational_pubkey: [u8; PUBLIC_KEY_LEN] = operational_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CairnFfiError::MalformedData)?;
        let device_signer: Arc<dyn EnvelopeSigner> = Arc::new(FfiEnvelopeSigner {
            signer,
            key_alias: device_key_alias,
        });
        let adapter_config = SimplexAdapterConfig {
            identity: LocalIdentity {
                device_signer,
                operational_pubkey,
            },
            storage: storage.storage_arc(),
            default_retry_budget: RetryBudget {
                max_retries: config.max_retries,
                ..RetryBudget::default()
            },
        };
        // Per-target transport (D0026 §12): in-process `libsimplex` on
        // Android (app-private DB + staging dir), the ws-core CLI-sidecar
        // client elsewhere (loopback host:port).
        #[cfg(not(target_os = "android"))]
        let transport = SimploxideTransport::new(SidecarEndpoint {
            host: config.host,
            port: config.port,
        });
        #[cfg(target_os = "android")]
        let transport = FfiSidecarTransport::with_options(
            PathBuf::from(config.db_path),
            PathBuf::from(config.files_dir),
            config.socks_proxy,
            config.db_key,
        );
        let adapter =
            SimplexAdapter::new(transport, adapter_config).map_err(CairnFfiError::from)?;
        Ok(Arc::new(Self { adapter }))
    }
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export(async_runtime = "tokio"))]
impl SimplexAdapterHandle {
    /// Create a new identifier-less queue + return its out-of-band
    /// invitation URI (delegates to the transport).
    ///
    /// # Errors
    ///
    /// The facade mapping of the transport error —
    /// [`CairnFfiError::SidecarFailure`] when the sidecar is unreachable.
    pub async fn create_invitation(&self) -> Result<String, CairnFfiError> {
        let invitation = self
            .adapter
            .create_invitation()
            .await
            .map_err(CairnFfiError::from)?;
        Ok(invitation.uri)
    }

    /// Accept a peer's invitation URI + complete out-of-band pairing,
    /// returning the connection id.
    ///
    /// # Errors
    ///
    /// The facade mapping of the transport error.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub async fn accept_invitation(&self, invitation_uri: String) -> Result<String, CairnFfiError> {
        let connection = self
            .adapter
            .accept_invitation(Invitation {
                uri: invitation_uri,
            })
            .await
            .map_err(CairnFfiError::from)?;
        Ok(connection.0)
    }

    /// Await an inbound connection becoming established after this side
    /// created + shared an invitation (the peer accepted it), returning the
    /// connection id. The inviter-side counterpart to `accept_invitation`'s
    /// establishment wait (D0026 §12).
    ///
    /// # Errors
    ///
    /// The facade mapping of the transport error
    /// ([`CairnFfiError::SidecarFailure`] when the sidecar is unreachable).
    pub async fn await_connection(&self) -> Result<String, CairnFfiError> {
        let connection = self
            .adapter
            .await_connection()
            .await
            .map_err(CairnFfiError::from)?;
        Ok(connection.0)
    }

    /// Build → sign (in StrongBox) → pad → persist a Cairn envelope to
    /// `recipient_operational_pubkey` over `connection_id`, then hand it
    /// to the transport. Returns the persisted record id + the advanced
    /// message number.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `recipient_operational_pubkey`
    ///   is not 32 bytes.
    /// - The facade mapping of any `SimplexAdapterError`:
    ///   [`CairnFfiError::SidecarFailure`] when the sidecar is unreachable,
    ///   [`CairnFfiError::EnvelopeVerifyFailed`] on a signer failure, or
    ///   [`CairnFfiError::StorageFailure`] on a persist failure.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub async fn send(
        &self,
        connection_id: String,
        recipient_operational_pubkey: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<MessageSentRecord, CairnFfiError> {
        let recipient: [u8; PUBLIC_KEY_LEN] = recipient_operational_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CairnFfiError::MalformedData)?;
        let sent = self
            .adapter
            .send(&ConnectionId(connection_id), &recipient, &payload)
            .await
            .map_err(CairnFfiError::from)?;
        Ok(MessageSentRecord {
            record_id: sent.record_id.to_vec(),
            next_message_number: sent.next_message_number,
        })
    }

    /// Receive + verify the next message on `connection_id` from
    /// `expected_sender_operational_pubkey`, whose envelope is signed by
    /// `sender_device_pubkey`. Returns the verified message (padding
    /// stripped).
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if either pubkey is not 32 bytes
    ///   / not a valid Ed25519 key.
    /// - The facade mapping of any `SimplexAdapterError`:
    ///   [`CairnFfiError::SidecarFailure`] when the sidecar is unreachable,
    ///   [`CairnFfiError::EnvelopeVerifyFailed`] on a bad signature or
    ///   sender binding, or [`CairnFfiError::EnvelopeChainGap`] on a gap.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub async fn recv(
        &self,
        connection_id: String,
        expected_sender_operational_pubkey: Vec<u8>,
        sender_device_pubkey: Vec<u8>,
    ) -> Result<ReceivedMessageRecord, CairnFfiError> {
        let sender: [u8; PUBLIC_KEY_LEN] = expected_sender_operational_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CairnFfiError::MalformedData)?;
        let device_pubkey_bytes: [u8; PUBLIC_KEY_LEN] = sender_device_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CairnFfiError::MalformedData)?;
        let sender_device_vk = VerifyingKey::from_bytes(&device_pubkey_bytes)
            .map_err(|_| CairnFfiError::MalformedData)?;
        let received = self
            .adapter
            .recv(&ConnectionId(connection_id), &sender, &sender_device_vk)
            .await
            .map_err(CairnFfiError::from)?;
        Ok(ReceivedMessageRecord {
            sender_operational_pubkey: received.sender_operational_pubkey.to_vec(),
            payload: received.payload,
            received_at_unix: received.received_at_unix,
            read_up_to: received.read_up_to,
            vouch: received.vouch,
            introduction: received.introduction,
            recovery_share: received.recovery_share,
            recovery_request: received.recovery_request,
            recovery_control: received.recovery_control,
        })
    }

    /// Receive + verify the next message on `connection_id` **without a
    /// pre-known sender**, learning the sender's operational pubkey from the
    /// envelope (TOFU on first contact, D0026 §12). The inviter-side bootstrap:
    /// after sharing a one-time invitation, the inviter cannot know the
    /// acceptor's key until the first envelope arrives. Returns the verified
    /// message (padding stripped) with the **learned** sender pubkey.
    ///
    /// Assumes the v1 1:1 identity model (operational pubkey == device signing
    /// key); an op≠device envelope verifies to a different key and is rejected
    /// (see `cairn_simplex_adapter::verify_envelope_learning_sender`). The
    /// binding of the learned key to a real-world identity is the D0006 trust
    /// graph (a v1.x layer).
    ///
    /// # Errors
    ///
    /// The facade mapping of any `SimplexAdapterError`:
    /// [`CairnFfiError::SidecarFailure`] when the sidecar is unreachable,
    /// [`CairnFfiError::EnvelopeVerifyFailed`] on a bad signature / op≠device
    /// envelope, or [`CairnFfiError::EnvelopeChainGap`] on a gap.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub async fn recv_learning_sender(
        &self,
        connection_id: String,
    ) -> Result<ReceivedMessageRecord, CairnFfiError> {
        let received = self
            .adapter
            .recv_learning_sender(&ConnectionId(connection_id))
            .await
            .map_err(CairnFfiError::from)?;
        Ok(ReceivedMessageRecord {
            sender_operational_pubkey: received.sender_operational_pubkey.to_vec(),
            payload: received.payload,
            received_at_unix: received.received_at_unix,
            read_up_to: received.read_up_to,
            vouch: received.vouch,
            introduction: received.introduction,
            recovery_share: received.recovery_share,
            recovery_request: received.recovery_request,
            recovery_control: received.recovery_control,
        })
    }

    /// Load the persisted conversation history with `peer_operational_pubkey`
    /// (both directions, chronological) for the contact-list / conversation
    /// resume UI (D0026 §3.2). Reads the local `MESSAGES` store — records were
    /// verified when they flowed, so they are decoded without re-verifying.
    /// Synchronous (a local storage read, no network).
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `peer_operational_pubkey` is not
    ///   32 bytes.
    /// - The facade mapping of any `SimplexAdapterError`
    ///   ([`CairnFfiError::StorageFailure`] on a read failure).
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub fn load_message_history(
        &self,
        peer_operational_pubkey: Vec<u8>,
    ) -> Result<ConversationHistoryRecord, CairnFfiError> {
        let peer: [u8; PUBLIC_KEY_LEN] = peer_operational_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CairnFfiError::MalformedData)?;
        let ConversationHistory {
            messages,
            peer_read_up_to,
        } = self
            .adapter
            .load_message_history(&peer)
            .map_err(CairnFfiError::from)?;
        Ok(ConversationHistoryRecord {
            messages: messages
                .into_iter()
                .map(|m: HistoryMessage| HistoryMessageRecord {
                    mine: m.mine,
                    payload: m.payload,
                    timestamp_unix: m.timestamp_unix,
                    message_number: m.message_number,
                })
                .collect(),
            peer_read_up_to,
        })
    }

    /// Purge ALL local trace of the conversation with `peer_operational_pubkey`
    /// — the deeper delete-purge run when the user deletes a contact (D0031).
    /// Deletes both directed `MESSAGES` chains + resets this pair's chain
    /// cursors, then tears down the SimpleX-side connection/queue over
    /// `connection_id`. The local history purge is authoritative + happens
    /// FIRST; the connection teardown is best-effort — a transport failure
    /// leaves a lingering SMP queue but never un-deletes the already-purged
    /// history.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `peer_operational_pubkey` is not 32
    ///   bytes.
    /// - The facade mapping of any `SimplexAdapterError`:
    ///   [`CairnFfiError::StorageFailure`] if the `MESSAGES` purge failed (before
    ///   any teardown), or [`CairnFfiError::SidecarFailure`] if the connection
    ///   teardown failed (the local history is already purged in that case).
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub async fn purge_conversation(
        &self,
        connection_id: String,
        peer_operational_pubkey: Vec<u8>,
    ) -> Result<(), CairnFfiError> {
        let peer: [u8; PUBLIC_KEY_LEN] = peer_operational_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CairnFfiError::MalformedData)?;
        self.adapter
            .purge_conversation(&ConnectionId(connection_id), &peer)
            .await
            .map_err(CairnFfiError::from)?;
        Ok(())
    }

    /// Send a **read receipt** to `recipient_operational_pubkey` over
    /// `connection_id`, acknowledging every message received from them (D0032).
    /// A no-op if nothing has been received from that peer yet.
    ///
    /// WHETHER to call this is the caller's policy (read receipts are off by
    /// default, D0032 §4) — the handle only provides the mechanism.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `recipient_operational_pubkey` is
    ///   not 32 bytes.
    /// - The facade mapping of any `SimplexAdapterError`
    ///   ([`CairnFfiError::SidecarFailure`] when the sidecar is unreachable,
    ///   [`CairnFfiError::StorageFailure`] on a persist failure).
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub async fn send_read_receipt(
        &self,
        connection_id: String,
        recipient_operational_pubkey: Vec<u8>,
    ) -> Result<(), CairnFfiError> {
        let recipient: [u8; PUBLIC_KEY_LEN] = recipient_operational_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CairnFfiError::MalformedData)?;
        self.adapter
            .send_read_receipt(&ConnectionId(connection_id), &recipient)
            .await
            .map_err(CairnFfiError::from)?;
        Ok(())
    }

    /// Send a **provenance vouch** to `recipient_operational_pubkey` over
    /// `connection_id` (D0036 §2): `vouch_bytes` is the `{op_chain, token}` blob
    /// from `TrustGraphHandle::build_vouch`. An empty-payload, signed + chained
    /// envelope carrying envelope key 9 — the recipient verifies + ingests it
    /// (the envelope signature already authenticates this sender).
    ///
    /// WHETHER to vouch is the caller's deliberate, opt-in act (D0036 §1) — the
    /// handle only provides the mechanism.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `recipient_operational_pubkey` is
    ///   not 32 bytes.
    /// - The facade mapping of any `SimplexAdapterError`
    ///   ([`CairnFfiError::SidecarFailure`] when the sidecar is unreachable,
    ///   [`CairnFfiError::StorageFailure`] on a persist failure).
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub async fn send_vouch(
        &self,
        connection_id: String,
        recipient_operational_pubkey: Vec<u8>,
        vouch_bytes: Vec<u8>,
    ) -> Result<(), CairnFfiError> {
        let recipient: [u8; PUBLIC_KEY_LEN] = recipient_operational_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CairnFfiError::MalformedData)?;
        self.adapter
            .send_vouch(&ConnectionId(connection_id), &recipient, &vouch_bytes)
            .await
            .map_err(CairnFfiError::from)?;
        Ok(())
    }

    /// Send an **introduction control message** to `recipient_operational_pubkey`
    /// over `connection_id` (D0037 §5): `introduction_bytes` is the canonical-CBOR
    /// blob from `encode_introduction_message` (carrying one of the three
    /// dual-consent handshake messages). An empty-payload, signed + chained
    /// envelope carrying envelope key 10 — the recipient decodes + routes it to
    /// the consent flow (the envelope signature already authenticates this
    /// sender).
    ///
    /// WHICH message + WHETHER to send it is the shell's consent-gated
    /// orchestration (D0037 §3) — the handle only provides the mechanism.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `recipient_operational_pubkey` is
    ///   not 32 bytes.
    /// - The facade mapping of any `SimplexAdapterError`
    ///   ([`CairnFfiError::SidecarFailure`] when the sidecar is unreachable,
    ///   [`CairnFfiError::StorageFailure`] on a persist failure).
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub async fn send_introduction(
        &self,
        connection_id: String,
        recipient_operational_pubkey: Vec<u8>,
        introduction_bytes: Vec<u8>,
    ) -> Result<(), CairnFfiError> {
        let recipient: [u8; PUBLIC_KEY_LEN] = recipient_operational_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CairnFfiError::MalformedData)?;
        self.adapter
            .send_introduction(
                &ConnectionId(connection_id),
                &recipient,
                &introduction_bytes,
            )
            .await
            .map_err(CairnFfiError::from)?;
        Ok(())
    }

    /// Send a **recovery share** to `recipient_operational_pubkey` over
    /// `connection_id` (D0038 §7): entrust one recovery card (`card_bytes`, from
    /// the recovery codec) to a recovery peer to HOLD, or RETURN a held card to a
    /// recovering owner. An empty-payload, signed + chained envelope carrying
    /// envelope key 11 — the recipient stores it (hold) or feeds it into the
    /// recovery reconstruct flow (return).
    ///
    /// A single share is transportable-by-design (below the reconstruction
    /// threshold); the master seed never crosses. WHETHER + to WHOM to send is the
    /// shell's choice — the handle only provides the mechanism.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `recipient_operational_pubkey` is
    ///   not 32 bytes.
    /// - The facade mapping of any `SimplexAdapterError`
    ///   ([`CairnFfiError::SidecarFailure`] when the sidecar is unreachable,
    ///   [`CairnFfiError::StorageFailure`] on a persist failure).
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub async fn send_recovery_share(
        &self,
        connection_id: String,
        recipient_operational_pubkey: Vec<u8>,
        card_bytes: Vec<u8>,
    ) -> Result<(), CairnFfiError> {
        let recipient: [u8; PUBLIC_KEY_LEN] = recipient_operational_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CairnFfiError::MalformedData)?;
        self.adapter
            .send_recovery_share(&ConnectionId(connection_id), &recipient, &card_bytes)
            .await
            .map_err(CairnFfiError::from)?;
        Ok(())
    }

    /// Send a **recovery request** to `recipient_operational_pubkey` over
    /// `connection_id` (D0038 §7): ask a recovery peer to return the share it
    /// holds for this side. `request_bytes` is empty in Stage 2 (release is gated
    /// by the peer's manual approval, not a payload). An empty-payload, signed +
    /// chained envelope carrying envelope key 12.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `recipient_operational_pubkey` is
    ///   not 32 bytes.
    /// - The facade mapping of any `SimplexAdapterError`
    ///   ([`CairnFfiError::SidecarFailure`] when the sidecar is unreachable,
    ///   [`CairnFfiError::StorageFailure`] on a persist failure).
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub async fn send_recovery_request(
        &self,
        connection_id: String,
        recipient_operational_pubkey: Vec<u8>,
        request_bytes: Vec<u8>,
    ) -> Result<(), CairnFfiError> {
        let recipient: [u8; PUBLIC_KEY_LEN] = recipient_operational_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CairnFfiError::MalformedData)?;
        self.adapter
            .send_recovery_request(&ConnectionId(connection_id), &recipient, &request_bytes)
            .await
            .map_err(CairnFfiError::from)?;
        Ok(())
    }

    /// Send a **recovery re-split control** message to
    /// `recipient_operational_pubkey` over `connection_id` (D0040 §5 / 3c): one
    /// step of the two-phase atomic re-split. `control_bytes` is
    /// `[kind(1)][resplit_id(16)]` (PREPARE / ACK / COMMIT / DISCARD, envelope
    /// key 13). For a PREPARE, `new_card_bytes` carries the peer's NEW recovery
    /// card (rides alongside in envelope key 11) so the peer can stage it pending;
    /// for ACK / COMMIT / DISCARD pass `None`. An empty-payload, signed + chained
    /// envelope.
    ///
    /// The orchestration (which step to send, to whom, in what order) is the
    /// shell's; the handle only provides the mechanism. The master seed never
    /// crosses here — only the peer's single new share does (a PREPARE), exactly
    /// as for a Stage-2 recovery share.
    ///
    /// # Errors
    ///
    /// - [`CairnFfiError::MalformedData`] if `recipient_operational_pubkey` is
    ///   not 32 bytes.
    /// - The facade mapping of any `SimplexAdapterError`
    ///   ([`CairnFfiError::SidecarFailure`] when the sidecar is unreachable,
    ///   [`CairnFfiError::StorageFailure`] on a persist failure).
    #[allow(
        clippy::needless_pass_by_value,
        reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
    )]
    pub async fn send_recovery_control(
        &self,
        connection_id: String,
        recipient_operational_pubkey: Vec<u8>,
        control_bytes: Vec<u8>,
        new_card_bytes: Option<Vec<u8>>,
    ) -> Result<(), CairnFfiError> {
        let recipient: [u8; PUBLIC_KEY_LEN] = recipient_operational_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| CairnFfiError::MalformedData)?;
        self.adapter
            .send_recovery_control(
                &ConnectionId(connection_id),
                &recipient,
                &control_bytes,
                new_card_bytes.as_deref(),
            )
            .await
            .map_err(CairnFfiError::from)?;
        Ok(())
    }
}

/// On-device FFI self-test (D0026 §12) — boot the in-process `libsimplex`
/// transport + create an invitation.
///
/// Proves the GHC runtime initialises + responds **on the device** (the
/// on-device equivalent of the host runtime proof). Returns the invitation URI
/// on success.
///
/// `db_path` is an app-private path prefix for the in-process chat DB;
/// `files_dir` a directory for `CryptoFile` staging (both created if absent).
/// `socks_proxy` (`<ip>:<port>`, optional) routes the daemon's outbound
/// traffic through a Tor SOCKS proxy via a `/network socks=` command issued
/// before `/_connect` (D0020 §2.2); `None` attempts a direct connection —
/// which fails reaching the SMP relay's `.onion` (the pre-Tor baseline this
/// diagnostic first surfaced). This is a diagnostic hook, NOT the messaging
/// surface — that is [`SimplexAdapterHandle`]. The export is present on all
/// targets (so the host-generated Kotlin bindings include it), but only does
/// real work on Android, where `MessagingTransport` is the in-process FFI
/// transport.
///
/// # Errors
///
/// - [`CairnFfiError::SidecarFailure`] if `libsimplex` cannot init / respond
///   (or, on non-Android targets, because the in-process FFI transport is
///   Android-only — desktop/CI uses the ws-core [`SimplexAdapterHandle`]).
#[cfg_attr(feature = "uniffi-bindings", uniffi::export(async_runtime = "tokio"))]
#[allow(
    clippy::needless_pass_by_value,
    reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
)]
#[allow(
    clippy::unused_async,
    reason = "async is required by the Android branch's .await + the UniFFI async-export contract; the non-Android body has no await"
)]
pub async fn messaging_ffi_selftest(
    db_path: String,
    files_dir: String,
    socks_proxy: Option<String>,
) -> Result<String, CairnFfiError> {
    #[cfg(target_os = "android")]
    {
        // Call `simploxide-ffi-core` init DIRECTLY (not via the transport's
        // opaque error map) so the on-device diagnostic surfaces the real
        // `InitError`, and use `/user` (LOCAL — no network) to isolate "does
        // the GHC runtime init + respond" from SMP-relay reachability. Always
        // returns Ok(<diagnostic>) so the result reaches the device log.
        use simploxide_ffi_core::{DbOpts, DefaultUser, init};
        if let Some(parent) = std::path::Path::new(&db_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::create_dir_all(&files_dir);
        let (client, _events) =
            match init(DefaultUser::regular("cairn"), DbOpts::unencrypted(&db_path)).await {
                Err(e) => return Ok(format!("init ERR: {e:?}")),
                Ok(c) => c,
            };
        // init + /user prove the GHC runtime runs (LOCAL, no network).
        if let Err(e) = client.send("/user".to_string()).await {
            return Ok(format!("init OK; /user ERR: {e:?}"));
        }
        // Route outbound SMP/XFTP through the C-Tor SOCKS proxy (D0020 §2.2)
        // BEFORE /_connect, when configured. Setting it only configures the
        // client; a proxy-down condition surfaces at /_connect, not here.
        if let Some(addr) = socks_proxy.as_deref() {
            if let Err(e) = client.send(format!("/network socks={addr}")).await {
                return Ok(format!("init+/user OK; /network socks ERR: {e:?}"));
            }
        }
        let route = socks_proxy
            .as_deref()
            .map_or_else(|| "direct".to_string(), |a| format!("socks={a}"));
        // /_connect adds the SMP-relay network round-trip (a real invitation
        // link) — over Tor when `route` is a socks proxy, else direct.
        match client.send("/_connect 1".to_string()).await {
            Err(e) => Ok(format!("init+/user OK ({route}); /_connect ERR: {e:?}")),
            Ok(inv) => Ok(format!(
                "init+/user OK ({route}); /_connect -> {}",
                inv.chars().take(220).collect::<String>()
            )),
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        // The in-process FFI transport is Android-only; desktop/CI uses the
        // ws-core SimplexAdapterHandle. Keep the export present on all targets
        // so the host-generated bindings include it; no-op here.
        let _ = (db_path, files_dir, socks_proxy);
        Err(CairnFfiError::SidecarFailure)
    }
}

/// On-device TWO-PARTY loopback selftest (D0026 §12): two in-process
/// `libsimplex` instances messaging each other in ONE process.
///
/// Boots TWO in-process `libsimplex` messaging instances + two SOFTWARE
/// Ed25519 identities in THIS one process, connects them through a public SMP
/// relay over Tor, then sends a message EACH WAY and verifies the received
/// plaintext + signature.
///
/// This proves the full Cairn envelope round-trip (sign → XFTP `CryptoFile`
/// send → recv → `COSE_Sign1` verify → sender-binding) end-to-end on-device
/// using only ONE network path — both peers ride the same phone's bundled Tor,
/// so the result is independent of any second device's connectivity (the
/// motivation: validate the software-signer round-trip without depending on a
/// flaky second-device network, D0026 §12).
///
/// Returns a human-readable result (`ROUND-TRIP OK …`); any failure is returned
/// as `Ok("… FAILED: …")` so the diagnostic always reaches the device log
/// (mirroring [`messaging_ffi_selftest`]). `db_path_*` / `files_dir_*` are
/// distinct app-private path prefixes for the two instances' chat DBs +
/// `CryptoFile`/XFTP staging; `socks_proxy` (`<ip>:<port>`) routes both through
/// the bundled Tor.
///
/// # Errors
///
/// [`CairnFfiError::SidecarFailure`] only on the non-Android stub (the
/// in-process FFI transport is Android-only).
#[cfg_attr(feature = "uniffi-bindings", uniffi::export(async_runtime = "tokio"))]
#[allow(
    clippy::needless_pass_by_value,
    reason = "UniFFI exports take owned arguments by value; the FFI layer owns the lowered buffers"
)]
#[allow(
    clippy::unused_async,
    reason = "async is required by the Android branch's .await + the UniFFI async-export contract; the non-Android body has no await"
)]
pub async fn messaging_ffi_two_party_selftest(
    db_path_a: String,
    files_dir_a: String,
    db_path_b: String,
    files_dir_b: String,
    socks_proxy: Option<String>,
) -> Result<String, CairnFfiError> {
    #[cfg(target_os = "android")]
    {
        match two_party_roundtrip(
            &db_path_a,
            &files_dir_a,
            &db_path_b,
            &files_dir_b,
            socks_proxy,
        )
        .await
        {
            Ok(s) => Ok(s),
            Err(e) => Ok(format!("two-party selftest FAILED: {e:?}")),
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (db_path_a, files_dir_a, db_path_b, files_dir_b, socks_proxy);
        Err(CairnFfiError::SidecarFailure)
    }
}

/// Build a messaging adapter over a fresh in-memory store + a software Ed25519
/// identity (device == operational, the 1:1 demo), wired to the in-process FFI
/// transport at `db_path` / `files_dir` through `socks_proxy`.
#[cfg(target_os = "android")]
fn two_party_build_adapter(
    seed: [u8; 32],
    db_path: &str,
    files_dir: &str,
    socks_proxy: Option<String>,
) -> Result<SimplexAdapter<FfiSidecarTransport>, SimplexAdapterError> {
    let provider = InMemoryKeyProvider::new();
    let passphrase = Zeroizing::new(b"cairn-selftest".to_vec());
    let storage = Arc::new(Storage::open_in_memory(&provider, &passphrase)?);

    let device_sk = SigningKey::from_seed(&Zeroizing::new(seed));
    let operational_pubkey = device_sk.verifying_key().to_bytes();
    let device_signer: Arc<dyn EnvelopeSigner> = Arc::new(device_sk);
    let config = SimplexAdapterConfig {
        identity: LocalIdentity {
            device_signer,
            operational_pubkey,
        },
        storage,
        default_retry_budget: RetryBudget::default(),
    };

    if let Some(parent) = std::path::Path::new(db_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::create_dir_all(files_dir);
    // Fresh chat DB per run: remove any prior selftest's libsimplex DB so the
    // agent does not resubscribe to stale connections — those surface as
    // `chatErrors` and can stall an otherwise-clean connect (D0026 §12).
    for suffix in ["_agent.db", "_chat.db", "_agent.db-wal", "_chat.db-wal"] {
        let _ = std::fs::remove_file(format!("{db_path}{suffix}"));
    }
    // Exercise the at-rest-encrypted bring-up (D0006 §3.5 / D0022 §2.2) the production path
    // uses: the loop above deletes the prior run's DB files, so this prefix is
    // fresh and safe to open with `DbOpts::encrypted` (a DB first created
    // unencrypted could not later be opened encrypted).
    let transport = FfiSidecarTransport::with_options(
        PathBuf::from(db_path),
        PathBuf::from(files_dir),
        socks_proxy,
        Some("cairn-selftest-dbkey".to_owned()),
    );
    SimplexAdapter::new(transport, config)
}

/// The (device verifying key, operational pubkey) a `seed` derives. For the
/// demo the device key IS the operational key, so the peer's recv params are
/// both this one key.
#[cfg(target_os = "android")]
fn two_party_identity(seed: [u8; 32]) -> (VerifyingKey, [u8; PUBLIC_KEY_LEN]) {
    let vk = SigningKey::from_seed(&Zeroizing::new(seed)).verifying_key();
    (vk, vk.to_bytes())
}

/// Drive the full two-party round-trip: A invites, B accepts over Tor, then a
/// message each way with the software signer — verifying the received text.
///
/// The connect is sequential (B accepts, then A's `await_connection` drains its
/// already-buffered `contactConnected`): each instance's libsimplex agent
/// processes the handshake on its own background worker, so A need not be
/// actively awaiting while B connects.
#[cfg(target_os = "android")]
async fn two_party_roundtrip(
    db_path_a: &str,
    files_dir_a: &str,
    db_path_b: &str,
    files_dir_b: &str,
    socks_proxy: Option<String>,
) -> Result<String, SimplexAdapterError> {
    let seed_a = [0x11_u8; 32];
    let seed_b = [0x22_u8; 32];
    let (vk_a, op_a) = two_party_identity(seed_a);
    let (vk_b, op_b) = two_party_identity(seed_b);

    let adapter_a = two_party_build_adapter(seed_a, db_path_a, files_dir_a, socks_proxy.clone())?;
    let adapter_b = two_party_build_adapter(seed_b, db_path_b, files_dir_b, socks_proxy)?;

    let invitation = adapter_a.create_invitation().await?;
    let conn_b = adapter_b.accept_invitation(invitation).await?;
    let conn_a = adapter_a.await_connection().await?;

    let msg_ab: &[u8] = b"ping from A over Tor";
    let msg_ba: &[u8] = b"pong from B over Tor";
    adapter_a.send(&conn_a, &op_b, msg_ab).await?;
    let got_b = adapter_b.recv(&conn_b, &op_a, &vk_a).await?;
    adapter_b.send(&conn_b, &op_a, msg_ba).await?;
    let got_a = adapter_a.recv(&conn_a, &op_b, &vk_b).await?;

    let ab_ok = got_b.payload.as_slice() == msg_ab;
    let ba_ok = got_a.payload.as_slice() == msg_ba;
    Ok(format!(
        "ROUND-TRIP {} | B<-A '{}' ({}) | A<-B '{}' ({})",
        if ab_ok && ba_ok { "OK" } else { "MISMATCH" },
        String::from_utf8_lossy(&got_b.payload),
        if ab_ok { "match" } else { "MISMATCH" },
        String::from_utf8_lossy(&got_a.payload),
        if ba_ok { "match" } else { "MISMATCH" },
    ))
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::hardware::{AttestationCertificate, HardwarePublicKey, KeyGenSpec};

    /// A mock `HardwareKeySigner` that counts sign invocations + returns a
    /// fixed 64-byte signature. The count lets a test assert the
    /// StrongBox-signing path actually runs during `send` (before the
    /// transport's network hop).
    struct CountingSigner {
        calls: Arc<AtomicUsize>,
    }
    impl HardwareKeySigner for CountingSigner {
        fn sign(&self, _key_alias: String, _payload: Vec<u8>) -> Result<Vec<u8>, CairnFfiError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![0x42u8; SIGNATURE_LEN])
        }
        fn generate_key(
            &self,
            _key_alias: String,
            _spec: KeyGenSpec,
        ) -> Result<HardwarePublicKey, CairnFfiError> {
            Ok(HardwarePublicKey { encoded: vec![] })
        }
        fn attestation_chain(
            &self,
            _key_alias: String,
        ) -> Result<Vec<AttestationCertificate>, CairnFfiError> {
            Ok(vec![])
        }
    }

    /// A shared in-memory `Storage` for the async tests (mirrors
    /// transparency's direct-construction pattern, avoiding the
    /// Argon2-heavy `StorageHandle::open`).
    fn test_storage() -> Arc<cairn_storage::Storage> {
        use cairn_storage::key_provider::testing::InMemoryKeyProvider;
        use zeroize::Zeroizing;
        let provider = InMemoryKeyProvider::new();
        let passphrase = Zeroizing::new(b"test-passphrase".to_vec());
        Arc::new(cairn_storage::Storage::open_in_memory(&provider, &passphrase).unwrap())
    }

    /// Build a handle directly (bypassing the `StorageHandle` constructor)
    /// over the `SimploxideTransport` stub, returning the handle + the
    /// signer's invocation counter.
    fn test_handle() -> (SimplexAdapterHandle, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let device_signer: Arc<dyn EnvelopeSigner> = Arc::new(FfiEnvelopeSigner {
            signer: Box::new(CountingSigner {
                calls: Arc::clone(&calls),
            }),
            key_alias: "device-key".to_string(),
        });
        let config = SimplexAdapterConfig {
            identity: LocalIdentity {
                device_signer,
                operational_pubkey: [0x11u8; PUBLIC_KEY_LEN],
            },
            storage: test_storage(),
            default_retry_budget: RetryBudget::default(),
        };
        // A deterministically-closed port (1): the lazy ws-core dial refuses
        // fast, so the transport surfaces SidecarFailure — hermetic, no live
        // sidecar. (Live two-party behavior is the integration-tests gate,
        // D0026 §12.)
        let transport = SimploxideTransport::new(SidecarEndpoint {
            host: "127.0.0.1".to_string(),
            port: 1,
        });
        let adapter = SimplexAdapter::new(transport, config).unwrap();
        (SimplexAdapterHandle { adapter }, calls)
    }

    #[test]
    fn ffi_envelope_signer_bridges_callback() {
        let calls = Arc::new(AtomicUsize::new(0));
        let bridge = FfiEnvelopeSigner {
            signer: Box::new(CountingSigner {
                calls: Arc::clone(&calls),
            }),
            key_alias: "device-key".to_string(),
        };
        // The bridge returns the callback's 64-byte signature.
        assert_eq!(
            bridge.sign_envelope(b"signing-input").unwrap(),
            [0x42u8; SIGNATURE_LEN]
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ffi_envelope_signer_rejects_wrong_length_signature() {
        // A mock returning a non-64-byte signature must surface as a sign
        // failure, never a truncated/oversized signature.
        struct ShortSigner;
        impl HardwareKeySigner for ShortSigner {
            fn sign(&self, _a: String, _p: Vec<u8>) -> Result<Vec<u8>, CairnFfiError> {
                Ok(vec![0u8; 32]) // wrong length
            }
            fn generate_key(
                &self,
                _a: String,
                _s: KeyGenSpec,
            ) -> Result<HardwarePublicKey, CairnFfiError> {
                Ok(HardwarePublicKey { encoded: vec![] })
            }
            fn attestation_chain(
                &self,
                _a: String,
            ) -> Result<Vec<AttestationCertificate>, CairnFfiError> {
                Ok(vec![])
            }
        }
        let bridge = FfiEnvelopeSigner {
            signer: Box::new(ShortSigner),
            key_alias: "device-key".to_string(),
        };
        assert!(matches!(
            bridge.sign_envelope(b"input"),
            Err(SimplexAdapterError::EnvelopeSignatureVerifyFailed)
        ));
    }

    #[tokio::test]
    async fn create_invitation_unreachable_sidecar_is_sidecar_failure() {
        // Exercises the async export bridge (tokio runtime + await + error
        // mapping) end-to-end; with no sidecar listening, the ws-core dial
        // refuses and the facade surfaces SidecarFailure, not a panic.
        let (handle, _calls) = test_handle();
        assert!(matches!(
            handle.create_invitation().await,
            Err(CairnFfiError::SidecarFailure)
        ));
    }

    #[tokio::test]
    async fn send_signs_in_hardware_then_reports_sidecar_failure() {
        // The whole point of the unblocked handle: a send CONSTRUCTS the
        // envelope and signs it via the StrongBox callback BEFORE the
        // transport's network hop. So the signer is invoked exactly once,
        // and the call then surfaces SidecarFailure over the unreachable
        // sidecar. This proves the hardware-signing path is wired through the
        // FFI; live two-party network is the integration-tests gate (§12).
        let (handle, calls) = test_handle();
        let recipient = vec![0x22u8; PUBLIC_KEY_LEN];
        let result = handle
            .send("conn-1".to_string(), recipient, b"hello".to_vec())
            .await;
        assert!(
            matches!(result, Err(CairnFfiError::SidecarFailure)),
            "send over an unreachable sidecar must surface SidecarFailure"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the StrongBox-signing callback must run before the transport hop"
        );
    }

    #[tokio::test]
    async fn send_rejects_wrong_length_recipient_pubkey() {
        let (handle, _calls) = test_handle();
        let result = handle
            .send("conn-1".to_string(), vec![0u8; 31], b"hi".to_vec())
            .await;
        assert!(matches!(result, Err(CairnFfiError::MalformedData)));
    }
}
