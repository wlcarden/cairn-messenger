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
//! ## Transport (ws-core; live, two-party gated on the CLI sidecar)
//!
//! The concrete `SimploxideTransport` is a real `simploxide-ws-core`
//! WebSocket client of the SimpleX Chat CLI sidecar (D0026 §1.3 / §12): it
//! lazily dials `ws://host:port`, issues simplex-chat commands, and drains
//! events. With no sidecar listening, `create_invitation` /
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
    ConnectionId, EnvelopeSigner, Invitation, LocalIdentity, RetryBudget, SidecarEndpoint,
    SimplexAdapter, SimplexAdapterConfig, SimplexAdapterError, SimploxideTransport,
};

use crate::error::CairnFfiError;
use crate::hardware::HardwareKeySigner;
use crate::storage::StorageHandle;

/// Endpoint + retry configuration for the SimpleX Chat CLI sidecar
/// (D0027 §2.2). All public values; the loopback defaults are
/// `127.0.0.1:5225` per D0020 §1.1. Becomes a `uniffi::Record`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Record))]
pub struct SidecarEndpointConfig {
    /// Loopback host of the CLI sidecar (default `127.0.0.1`).
    pub host: String,
    /// Loopback port (default `5225`).
    pub port: u16,
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
    /// Application-level payload (padding stripped on receive).
    pub payload: Vec<u8>,
    /// Receive-side Unix-seconds timestamp.
    pub received_at_unix: u64,
}

/// An opaque async handle to the Cairn SimpleX messaging adapter
/// (D0027 §2.2), over the ws-core `SimploxideTransport` (D0026 §1.3 / §12).
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Object))]
pub struct SimplexAdapterHandle {
    adapter: SimplexAdapter<SimploxideTransport>,
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
        let transport = SimploxideTransport::new(SidecarEndpoint {
            host: config.host,
            port: config.port,
        });
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
        })
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
