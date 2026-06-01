// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! The internal sidecar-transport seam (D0020 §1.10 / D0026 §1.2).
//!
//! [`SidecarTransport`] abstracts the raw byte transport BELOW Cairn's
//! message envelope: invitation pairing + opaque-byte `send`/`recv` over an
//! established connection. Inverting the dependency this way lets
//! [`crate::adapter::SimplexAdapter`] implement its security-critical
//! envelope flow (build → sign → pad / verify → unpad → chain) generically
//! over the seam, testable with an in-memory mock and with the real
//! ws-core-backed transport injected in production.
//!
//! ## Concrete transport: `simploxide-ws-core` (D0026 §1.3 / §12)
//!
//! [`SimploxideTransport`] is a client of the SimpleX Chat CLI sidecar over
//! a loopback WebSocket, built on the LOW-LEVEL `simploxide-ws-core` (a raw
//! command/event WS client) rather than the high-level `simploxide-client`
//! Bot SDK — see the workspace-pin rationale + the D0026 §12 probe matrix
//! (ws-core compiles on the pinned rust 1.85; the Bot SDK does not, and its
//! websocket-only build is upstream-broken). `connect("ws://host:port")`
//! yields a `RawClient` (command RPC) + an `EventQueue` (incoming events);
//! Cairn owns the simplex-chat command/JSON layer in the crate-internal
//! `protocol` module.
//!
//! **Verification boundary (honest):** the ws-core connection + command-RPC
//! + event-drain + error-mapping machinery below is hermetically tested
//! against a localhost mock WS server (the `mock_ws` tests). The simplex-chat
//! command strings + response/event parsing are reference-derived (the
//! crate-internal `protocol` module); their wire fidelity against a live
//! simplex-chat daemon — especially the `CryptoFile`/XFTP file lifecycle — is
//! ONLY under the `integration-tests` feature (D0026 §12), NOT here.
//!
//! ## Message numbers (D0026 §3.2 + revision note (c))
//!
//! Per the corrected D0026 design the per-`(sender, recipient)` message
//! number is **Cairn's chain position** (derived by the adapter from the
//! `MESSAGES` history), NOT a transport-assigned value: SimpleX's chat-item
//! id is local-DB-global-monotonic + sparse-per-pair, which would break the
//! contiguous-walk `rehydrate_chain`. The seam therefore carries NO number —
//! `send` returns `()` and `recv` returns the raw bytes; the adapter owns
//! the numbering. (The earlier `send -> u64` / `recv -> (u64, bytes)` seam
//! was vestigial; dropped here per the revision-note (c) implementation
//! step.)

use std::future::Future;

use crate::adapter::{ConnectionId, Invitation};
use crate::error::SimplexAdapterError;

#[cfg(test)]
use std::collections::{HashMap, VecDeque};
#[cfg(test)]
use std::sync::{Arc, Mutex};

/// The raw byte transport below the Cairn envelope (D0020 §1.10).
///
/// Implementations own the SMP wire, the PQ double-ratchet, the queue
/// lifecycle, and the out-of-band invitation flow (D0026 §1.3); Cairn rides
/// its signed + padded envelope over the opaque `send`/`recv`.
///
/// Methods return `impl Future + Send` (RPITIT) rather than `async fn`, and
/// the supertrait `Sync` bound makes `&SimplexAdapter<T>` `Send`, so the
/// generic [`crate::adapter::SimplexAdapter`]'s public async surface is
/// `Send` (spawnable on a multi-threaded executor).
pub trait SidecarTransport: Sync {
    /// Create an identifier-less queue + return its out-of-band invitation.
    fn create_invitation(
        &self,
    ) -> impl Future<Output = Result<Invitation, SimplexAdapterError>> + Send;

    /// Complete out-of-band pairing for a peer's invitation.
    fn accept_invitation(
        &self,
        invitation: Invitation,
    ) -> impl Future<Output = Result<ConnectionId, SimplexAdapterError>> + Send;

    /// Send `raw` envelope bytes over `conn`.
    ///
    /// Per D0026 §3.2 (revision note (c)) the message number is Cairn's
    /// chain position, owned by the adapter — the seam carries no number.
    fn send(
        &self,
        conn: &ConnectionId,
        raw: &[u8],
    ) -> impl Future<Output = Result<(), SimplexAdapterError>> + Send;

    /// Receive the next raw envelope bytes on `conn` (blocking until one
    /// arrives, for a network transport).
    fn recv(
        &self,
        conn: &ConnectionId,
    ) -> impl Future<Output = Result<Vec<u8>, SimplexAdapterError>> + Send;
}

// ===================================================================
// SimplOxide (ws-core)-backed transport — the production transport
// ===================================================================

mod simploxide {
    use std::path::PathBuf;

    use simploxide_ws_core::{EventQueue, RawClient, connect};
    use tokio::sync::{Mutex as AsyncMutex, OnceCell};

    use super::SidecarTransport;
    use crate::adapter::{ConnectionId, Invitation, SidecarEndpoint};
    use crate::error::SimplexAdapterError;
    use crate::protocol::{self, Resp};

    /// An established ws-core connection to the sidecar daemon: the command
    /// RPC client, the (exclusively-locked) incoming-event queue, and the
    /// active `userId` the `/_connect` / `/_send` commands require.
    struct Conn {
        client: RawClient,
        events: AsyncMutex<EventQueue>,
        user_id: i64,
    }

    /// The production [`SidecarTransport`] — a `simploxide-ws-core` WebSocket
    /// client of the SimpleX Chat CLI sidecar (D0026 §1.3).
    ///
    /// The WebSocket is dialed **lazily** on first use (the constructor is
    /// synchronous because `cairn-uniffi`'s `uniffi::constructor` is), so a
    /// connection failure surfaces on the first `create_invitation` / `send`
    /// / `recv`, not at construction. All `ConnectionId`s multiplex over the
    /// one daemon connection.
    pub struct SimploxideTransport {
        endpoint: SidecarEndpoint,
        /// Directory the daemon shares for `CryptoFile`/XFTP staging: Cairn
        /// writes outgoing envelope bytes here for the daemon's upload, and
        /// reads completed downloads the daemon writes here (D0026 §2.4).
        files_dir: PathBuf,
        conn: OnceCell<Conn>,
    }

    impl SimploxideTransport {
        /// Construct the (lazily-dialed) production transport for a sidecar
        /// endpoint, staging `CryptoFile` payloads under the OS temp dir.
        #[must_use]
        pub fn new(endpoint: SidecarEndpoint) -> Self {
            let files_dir = std::env::temp_dir().join("cairn-simplex");
            Self::with_files_dir(endpoint, files_dir)
        }

        /// Construct with an explicit `CryptoFile`-staging directory (the
        /// daemon must be able to read/write it). Used by tests + by callers
        /// that share a specific files directory with the sidecar.
        #[must_use]
        pub fn with_files_dir(endpoint: SidecarEndpoint, files_dir: PathBuf) -> Self {
            Self {
                endpoint,
                files_dir,
                conn: OnceCell::new(),
            }
        }

        /// Lazily dial the sidecar WebSocket + learn the active `userId`.
        async fn conn(&self) -> Result<&Conn, SimplexAdapterError> {
            self.conn
                .get_or_try_init(|| async {
                    let url = format!("ws://{}:{}", self.endpoint.host, self.endpoint.port);
                    let (client, events) = connect(&url)
                        .await
                        .map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
                    let user_id = query_active_user_id(&client).await?;
                    Ok(Conn {
                        client,
                        events: AsyncMutex::new(events),
                        user_id,
                    })
                })
                .await
        }

        /// Issue a command + return the parsed response frame, mapping a WS
        /// failure to `Network` and a simplex-chat error reply to
        /// `SidecarProtocol`.
        async fn command(&self, cmd: String) -> Result<serde_json::Value, SimplexAdapterError> {
            let conn = self.conn().await?;
            send_command(&conn.client, cmd).await
        }
    }

    /// Send one command over a ws-core client + parse the response, mapping
    /// transport + protocol failures to the typed surface.
    async fn send_command(
        client: &RawClient,
        cmd: String,
    ) -> Result<serde_json::Value, SimplexAdapterError> {
        let raw = client
            .send(cmd)
            .await
            .map_err(|_| SimplexAdapterError::Network {
                retry_budget_used: 0,
            })?;
        let frame = protocol::parse_frame(&raw).ok_or(SimplexAdapterError::SidecarProtocol)?;
        if Resp::from_frame(&frame).is_some_and(|r| r.is_error()) {
            return Err(SimplexAdapterError::SidecarProtocol);
        }
        Ok(frame)
    }

    /// Query + parse the active `userId` (`/user`), required by `/_connect`
    /// + `/_send`.
    async fn query_active_user_id(client: &RawClient) -> Result<i64, SimplexAdapterError> {
        let frame = send_command(client, protocol::cmd_show_active_user()).await?;
        let resp = Resp::from_frame(&frame).ok_or(SimplexAdapterError::SidecarProtocol)?;
        protocol::parse_active_user_id(&resp).ok_or(SimplexAdapterError::SidecarProtocol)
    }

    impl SidecarTransport for SimploxideTransport {
        async fn create_invitation(&self) -> Result<Invitation, SimplexAdapterError> {
            let user_id = self.conn().await?.user_id;
            let frame = self
                .command(protocol::cmd_create_invitation(user_id))
                .await?;
            let resp = Resp::from_frame(&frame).ok_or(SimplexAdapterError::SidecarProtocol)?;
            let uri = protocol::parse_invitation_link(&resp)
                .ok_or(SimplexAdapterError::SidecarProtocol)?;
            Ok(Invitation { uri })
        }

        async fn accept_invitation(
            &self,
            invitation: Invitation,
        ) -> Result<ConnectionId, SimplexAdapterError> {
            let user_id = self.conn().await?.user_id;
            let frame = self
                .command(protocol::cmd_connect_via_link(user_id, &invitation.uri))
                .await?;
            let resp = Resp::from_frame(&frame).ok_or(SimplexAdapterError::SidecarProtocol)?;
            let id =
                protocol::parse_connection_id(&resp).ok_or(SimplexAdapterError::SidecarProtocol)?;
            Ok(ConnectionId(id))
        }

        async fn send(&self, conn: &ConnectionId, raw: &[u8]) -> Result<(), SimplexAdapterError> {
            // Stage the envelope bytes on disk for the daemon's XFTP upload
            // (the uniform CryptoFile carrier, D0026 §2.4).
            let path = self.stage_outgoing(raw)?;
            let chat_ref = format!("@{}", conn.0);
            let frame = self
                .command(protocol::cmd_send_file(&chat_ref, &path))
                .await?;
            // The chat-item id is a SimpleX-layer ACK only; Cairn's per-pair
            // number is the adapter's chain position (D0026 §3.2 (c)). Parse
            // it solely to confirm a well-formed send response.
            let resp = Resp::from_frame(&frame).ok_or(SimplexAdapterError::SidecarProtocol)?;
            if resp.is_error() {
                return Err(SimplexAdapterError::SidecarProtocol);
            }
            Ok(())
        }

        async fn recv(&self, conn: &ConnectionId) -> Result<Vec<u8>, SimplexAdapterError> {
            self.recv_next_file(conn).await
        }
    }

    impl SimploxideTransport {
        /// Write outgoing envelope bytes to a freshly-named file in the
        /// shared `files_dir` for the daemon to XFTP-upload; return its path.
        ///
        /// A local staging-IO failure surfaces as
        /// [`SimplexAdapterError::SidecarUnavailable`] — from the caller's
        /// view the sidecar handoff could not be completed locally (the
        /// Android-shell remedy is the same: check the sidecar + its files
        /// dir, D0020 §1.6). A dedicated carrier-IO variant is a documented
        /// follow-up.
        fn stage_outgoing(&self, raw: &[u8]) -> Result<String, SimplexAdapterError> {
            std::fs::create_dir_all(&self.files_dir)
                .map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
            let mut name = [0u8; 16];
            getrandom::getrandom(&mut name).map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
            let file_name = format!("cairn-out-{}.bin", hex_lower(&name));
            let path = self.files_dir.join(file_name);
            std::fs::write(&path, raw).map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
            path.to_str()
                .map(ToString::to_string)
                .ok_or(SimplexAdapterError::SidecarUnavailable)
        }

        /// Drain incoming events until a `CryptoFile` for `conn` arrives:
        /// accept each offered file, then read the bytes the daemon writes on
        /// completion. Other events (text, status, contact lifecycle) are
        /// skipped.
        ///
        /// **Live-validated only** (`integration-tests`, D0026 §12): the
        /// offer→accept→complete event sequence + the completed-file path
        /// shape are reference-derived and exercised hermetically against the
        /// mock WS server, not a live daemon.
        async fn recv_next_file(
            &self,
            _conn: &ConnectionId,
        ) -> Result<Vec<u8>, SimplexAdapterError> {
            // `_conn` demultiplexing is live-gated (D0026 §12): the v1 1:1
            // group-minimization property (D0026 §5) means a single active
            // conversation, so the loop consumes the next completed file.
            // Per-connection routing by `contactId` lands with live-CLI
            // validation.
            loop {
                let frame = self.next_event().await?;
                let Some(resp) = Resp::from_frame(&frame) else {
                    continue; // non-conforming event frame; skip
                };
                if let Some(offer) = protocol::parse_received_file_offer(&resp) {
                    // Accept the offered file so the daemon XFTP-downloads it.
                    let _ = self
                        .command(protocol::cmd_receive_file(offer.file_id))
                        .await?;
                    continue;
                }
                if let Some(path) = protocol::parse_rcv_file_complete_path(&resp) {
                    return read_completed_file(&path);
                }
                // Unrelated event — keep draining.
            }
        }

        /// Await the next incoming event frame, mapping a WS failure to
        /// `SidecarUnavailable` (the daemon dropped the connection).
        async fn next_event(&self) -> Result<serde_json::Value, SimplexAdapterError> {
            let conn = self.conn().await?;
            let mut queue = conn.events.lock().await;
            let event = queue
                .next_event()
                .await
                .ok_or(SimplexAdapterError::SidecarUnavailable)?
                .map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
            drop(queue);
            protocol::parse_frame(&event).ok_or(SimplexAdapterError::SidecarProtocol)
        }
    }

    /// Read a daemon-completed download back as the envelope bytes.
    fn read_completed_file(path: &str) -> Result<Vec<u8>, SimplexAdapterError> {
        std::fs::read(path).map_err(|_| SimplexAdapterError::SidecarUnavailable)
    }

    /// Lower-hex encode (no external dep; the bytes are a random file-name
    /// nonce, not a secret).
    fn hex_lower(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().saturating_mul(2));
        for b in bytes {
            out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
        }
        out
    }
}

pub use simploxide::SimploxideTransport;

// ===================================================================
// In-memory mock transport (D0026 §1.2)
// ===================================================================
//
// `#[cfg(test)]`-gated for this cycle (the round-trip tests live in
// `adapter.rs`). Per the D0026 revision-note (c), the seam no longer carries
// a message number, so the mock just FIFOs opaque bytes per connection (the
// adapter owns the numbering now).

#[cfg(test)]
#[derive(Default)]
struct MockWire {
    /// Per-connection FIFO of opaque envelope bytes.
    queues: HashMap<ConnectionId, VecDeque<Vec<u8>>>,
    /// Next mock connection id.
    next_conn: u64,
}

/// An in-memory [`SidecarTransport`] for hermetic tests. Cloning shares the
/// same wire (an `Arc`), so two adapters constructed over clones can
/// round-trip a message through a shared `ConnectionId`.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct MockSidecarTransport {
    wire: Arc<Mutex<MockWire>>,
}

#[cfg(test)]
impl MockSidecarTransport {
    /// A fresh mock with an empty wire.
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
impl SidecarTransport for MockSidecarTransport {
    async fn create_invitation(&self) -> Result<Invitation, SimplexAdapterError> {
        Ok(Invitation {
            uri: "simplex://invitation/mock".to_string(),
        })
    }

    async fn accept_invitation(
        &self,
        _invitation: Invitation,
    ) -> Result<ConnectionId, SimplexAdapterError> {
        let mut wire = self
            .wire
            .lock()
            .map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
        let id = ConnectionId(format!("mock-conn-{}", wire.next_conn));
        wire.next_conn = wire.next_conn.saturating_add(1);
        drop(wire);
        Ok(id)
    }

    async fn send(&self, conn: &ConnectionId, raw: &[u8]) -> Result<(), SimplexAdapterError> {
        let mut wire = self
            .wire
            .lock()
            .map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
        wire.queues
            .entry(conn.clone())
            .or_default()
            .push_back(raw.to_vec());
        drop(wire);
        Ok(())
    }

    async fn recv(&self, conn: &ConnectionId) -> Result<Vec<u8>, SimplexAdapterError> {
        let mut wire = self
            .wire
            .lock()
            .map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
        let msg = wire.queues.get_mut(conn).and_then(VecDeque::pop_front);
        drop(wire);
        msg.ok_or(SimplexAdapterError::ConnectionNotFound)
    }
}

// ===================================================================
// Hermetic mock-WS-server tests for the ws-core SimploxideTransport
// ===================================================================
//
// These validate the genuinely-verifiable Layer-1 machinery — the ws-core
// dial, the `/user` handshake, the command RPC round-trip, and response
// parsing — against a localhost WebSocket server speaking the simplex-chat
// corrId/resp framing (mirrors the mock-SOCKS5 / mock-control-port harnesses
// in cairn-tor-transport). The simplex-chat *wire fidelity* against a live
// daemon (esp. the CryptoFile/XFTP recv lifecycle) is the `integration-tests`
// gate per D0026 §12, NOT asserted here.

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests assert on known-shape fixtures; index/unwrap panics ARE the failure signal"
)]
mod mock_ws_tests {
    use super::{SidecarTransport, SimploxideTransport};
    use crate::adapter::{Invitation, SidecarEndpoint};

    use futures::{SinkExt as _, StreamExt as _};
    use serde_json::{Value, json};
    use simploxide_ws_core::tokio_tungstenite::{accept_async, tungstenite::Message};
    use tokio::net::TcpListener;

    /// A minimal mock SimpleX Chat CLI sidecar: accepts one WebSocket and
    /// answers each `{"corrId","cmd"}` command frame with a reference-shaped
    /// `{"corrId","resp":{...}}` response.
    async fn run_mock_sidecar(listener: TcpListener) {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut ws) = accept_async(stream).await else {
            return;
        };
        while let Some(Ok(msg)) = ws.next().await {
            let Message::Text(frame) = msg else { continue };
            let Ok(request) = serde_json::from_str::<Value>(&frame) else {
                continue;
            };
            let corr = request["corrId"].as_str().unwrap_or("");
            let command = request["cmd"].as_str().unwrap_or("");
            let reply: Value = if command == "/user" {
                json!({"corrId": corr, "resp": {"type": "activeUser", "user": {"userId": 1}}})
            } else if command.starts_with("/_connect 1 ") {
                // accept_invitation (has a link argument)
                json!({"corrId": corr, "resp": {"type": "sentConfirmation", "connection": {"pccConnId": "42"}}})
            } else if command == "/_connect 1" {
                // create_invitation (no link argument)
                json!({"corrId": corr, "resp": {"type": "invitation", "connLinkInvitation": "simplex:/inv#mock"}})
            } else if command.starts_with("/_send ") {
                json!({"corrId": corr, "resp": {"type": "newChatItems", "chatItems": [{"chatItem": {"file": {"fileId": 1}}}]}})
            } else {
                json!({"corrId": corr, "resp": {"type": "cmdOk"}})
            };
            if ws.send(Message::text(reply.to_string())).await.is_err() {
                break;
            }
        }
    }

    /// Bind an ephemeral localhost port, spawn the mock sidecar, and return a
    /// transport pointed at it with a unique staging dir.
    async fn transport_against_mock() -> SimploxideTransport {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(run_mock_sidecar(listener));
        let files_dir = std::env::temp_dir().join(format!("cairn-simplex-test-{port}"));
        SimploxideTransport::with_files_dir(
            SidecarEndpoint {
                host: "127.0.0.1".to_string(),
                port,
            },
            files_dir,
        )
    }

    #[tokio::test]
    async fn create_invitation_round_trips_over_ws_core() {
        // Exercises: lazy ws-core dial → `/user` handshake → `/_connect 1`
        // command RPC → invitation-link response parse.
        let transport = transport_against_mock().await;
        let invitation = transport.create_invitation().await.unwrap();
        assert_eq!(invitation.uri, "simplex:/inv#mock");
    }

    #[tokio::test]
    async fn accept_invitation_parses_connection_id() {
        let transport = transport_against_mock().await;
        let conn = transport
            .accept_invitation(Invitation {
                uri: "simplex:/peer#abc".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(conn.0, "42");
    }

    #[tokio::test]
    async fn send_stages_file_and_round_trips_command() {
        // Exercises the send command RPC: the envelope bytes are staged to
        // the files dir + a `/_send` file command round-trips to a
        // well-formed `newChatItems` response (Ok(())).
        let transport = transport_against_mock().await;
        let conn = transport
            .accept_invitation(Invitation {
                uri: "simplex:/peer#abc".to_string(),
            })
            .await
            .unwrap();
        transport
            .send(&conn, b"cairn-envelope-bytes")
            .await
            .unwrap();
    }
}
