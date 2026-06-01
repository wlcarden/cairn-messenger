// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! The internal sidecar-transport seam (D0020 §1.10 / D0026 §1.2).
//!
//! [`SidecarTransport`] abstracts the raw byte transport BELOW Cairn's
//! message envelope: invitation pairing + opaque-byte `send`/`recv` over an
//! established connection. Inverting the dependency this way lets
//! [`crate::adapter::SimplexAdapter`] implement its security-critical
//! envelope flow (build → sign → pad / verify → unpad → chain) generically
//! over the seam, testable with an in-memory mock and with a real
//! SimpleX-backed transport injected in production.
//!
//! ## Two concrete transports, one shared flow (D0026 §12)
//!
//! The simplex-chat command/response/event protocol is the same underlying
//! core whether the daemon is reached over a loopback WebSocket (a separate
//! CLI process) or in-process via the JNI library — the command strings and
//! the inner `{"type": ..}` payloads are identical; only the outer reply
//! envelope key differs (`resp` for ws-core/CLI, `result` for the FFI —
//! D0026 §12 host-runtime finding), which `crate::protocol`'s
//! `Resp::from_frame` absorbs. The seam therefore factors into:
//!
//! - `RawChannel` — the minimal raw-frame transport (`send` one command →
//!   response, `next_event` → the next incoming event). Two impls:
//!   - **`wscore::WsChannel`** (`simploxide-ws-core`): a loopback-WebSocket
//!     client of the SimpleX Chat CLI sidecar. The **desktop / dev / CI**
//!     transport (live-validated, D0026 §12); backs [`SimploxideTransport`].
//!   - **`ffi::FfiChannel`** (`simploxide-ffi-core`, **`target_os = "android"`
//!     only**): the in-process JNI `libsimplex` library. The **Android**
//!     transport (D0020 §1.9); backs `FfiSidecarTransport`. There is no
//!     standalone Android CLI binary, so on-device the daemon runs in-process
//!     (D0026 §12 Android-transport finding).
//! - `flow` — the entire transport-agnostic protocol flow (command RPC,
//!   `/user` handshake, invitation pairing, `contactConnected` await, the
//!   `CryptoFile`/XFTP send/recv file lifecycle) generic over `RawChannel`.
//!   Both transports delegate to it; it is exercised once, against the
//!   ws-core path's hermetic mock.
//!
//! ### Why the FFI dependency is `target_os = "android"`-gated
//!
//! `simploxide-ffi-core` pulls `simploxide-sxcrt-sys` (`links = "simplex"`),
//! whose build script **hard-fails** unless it can locate a `libsimplex`
//! bundle (`SXCRT` / `SIMPLEX_STATIC_DIR` / autobuild). Cairn's CI clippy +
//! test gates run `--all-features` on an x86_64-linux host with no such
//! bundle. Declaring the dependency under
//! `[target.'cfg(target_os = "android")'.dependencies]` keeps it out of the
//! host dependency graph entirely — `--all-features` on the CI host never
//! builds `sxcrt-sys` — while Android target builds (the APK cycle) get it.
//! The cfg is both the architectural truth (the in-process path only exists
//! on Android) and the CI guardrail.
//!
//! **Verification boundary (honest):** the ws-core `RawChannel` + the whole
//! `flow` are hermetically tested against a localhost mock WS server (the
//! `mock_ws_tests`). The simplex-chat command strings + response/event
//! parsing are reference-derived (`crate::protocol`); their wire fidelity
//! against a live daemon — especially the `CryptoFile`/XFTP file lifecycle —
//! is the `integration-tests` gate (D0026 §12), NOT here. The FFI transport's
//! in-process `libsimplex` bring-up is type-checked for `aarch64-linux-android`
//! and runtime-proven out-of-tree against the host `libsimplex` bundle (D0026
//! §12 FFI revision note); its on-device link + run is the APK cycle.
//!
//! ## Message numbers (D0026 §3.2 + revision note (c))
//!
//! Per the corrected D0026 design the per-`(sender, recipient)` message
//! number is **Cairn's chain position** (derived by the adapter from the
//! `MESSAGES` history), NOT a transport-assigned value: SimpleX's chat-item
//! id is local-DB-global-monotonic + sparse-per-pair, which would break the
//! contiguous-walk `rehydrate_chain`. The seam therefore carries NO number —
//! `send` returns `()` and `recv` returns the raw bytes; the adapter owns
//! the numbering.

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

    /// Accept a peer's invitation and **await the connection becoming
    /// established**, returning the established [`ConnectionId`].
    ///
    /// Per the D0026 §12 live-validation finding, a real sidecar reports only
    /// a *pending* connection synchronously; the usable connection id arrives
    /// with a later async establishment event, so this awaits it.
    fn accept_invitation(
        &self,
        invitation: Invitation,
    ) -> impl Future<Output = Result<ConnectionId, SimplexAdapterError>> + Send;

    /// Await an inbound connection becoming established after this side
    /// created + shared an [`Invitation`] (the peer accepted it). Returns the
    /// established [`ConnectionId`]. This is the inviter-side counterpart to
    /// [`Self::accept_invitation`]'s establishment wait (D0026 §12): the
    /// inviter learns its connection id only once the peer connects.
    fn await_connection(
        &self,
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
// Transport-agnostic protocol flow (D0026 §12)
// ===================================================================

/// Shared simplex-chat protocol flow over an abstract [`RawChannel`].
///
/// Everything Cairn does with the SimpleX daemon — the `/user` handshake, the
/// invitation pairing, the `contactConnected` establishment await, and the
/// `CryptoFile`/XFTP send/recv file lifecycle — depends only on sending a
/// command string and awaiting event strings. Both the ws-core (WebSocket)
/// and the FFI (in-process) transports provide that via [`RawChannel`], so
/// this flow is written once and reused by both.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) lets the sibling wscore/ffi transport modules call \
              the flow; the items are not crate-exported (private mod)."
)]
pub(crate) mod flow {
    use serde_json::Value;

    use crate::adapter::{ConnectionId, Invitation};
    use crate::error::SimplexAdapterError;
    use crate::protocol::{self, Resp};

    use std::future::Future;
    use std::path::Path;

    /// The minimal raw-frame transport the [`super::flow`] is generic over: a
    /// command→response RPC and an incoming-event stream, both carrying the
    /// opaque simplex-chat JSON frame as a `String`.
    ///
    /// Error mapping is the impl's responsibility (a WebSocket drop and an
    /// FFI worker shutdown both surface as the same typed errors), so the
    /// flow stays transport-neutral.
    pub(crate) trait RawChannel: Send + Sync {
        /// Send one simplex-chat command frame; await its response frame.
        ///
        /// A transport-level failure maps to
        /// [`SimplexAdapterError::Network`] (the command did not complete).
        fn send(
            &self,
            cmd: String,
        ) -> impl Future<Output = Result<String, SimplexAdapterError>> + Send;

        /// Await the next incoming event frame.
        ///
        /// A closed/dropped channel maps to
        /// [`SimplexAdapterError::SidecarUnavailable`] (the daemon went away).
        fn next_event(&self) -> impl Future<Output = Result<String, SimplexAdapterError>> + Send;
    }

    /// An established channel plus the active `userId` the `/_connect` /
    /// `/_send` commands require. Both transports cache this lazily.
    pub(crate) struct Conn<C> {
        pub(crate) chan: C,
        pub(crate) user_id: i64,
    }

    /// Issue a command + return the parsed response frame, mapping a
    /// simplex-chat error reply to [`SimplexAdapterError::SidecarProtocol`].
    pub(crate) async fn command<C: RawChannel>(
        chan: &C,
        cmd: String,
    ) -> Result<Value, SimplexAdapterError> {
        let raw = chan.send(cmd).await?;
        let frame = protocol::parse_frame(&raw).ok_or(SimplexAdapterError::SidecarProtocol)?;
        if Resp::from_frame(&frame).is_some_and(|r| r.is_error()) {
            return Err(SimplexAdapterError::SidecarProtocol);
        }
        Ok(frame)
    }

    /// Query + parse the active `userId` (`/user`), required by `/_connect`
    /// + `/_send`.
    pub(crate) async fn query_active_user_id<C: RawChannel>(
        chan: &C,
    ) -> Result<i64, SimplexAdapterError> {
        let frame = command(chan, protocol::cmd_show_active_user()).await?;
        let resp = Resp::from_frame(&frame).ok_or(SimplexAdapterError::SidecarProtocol)?;
        protocol::parse_active_user_id(&resp).ok_or(SimplexAdapterError::SidecarProtocol)
    }

    /// Create an identifier-less queue + return its out-of-band invitation.
    pub(crate) async fn create_invitation<C: RawChannel>(
        chan: &C,
        user_id: i64,
    ) -> Result<Invitation, SimplexAdapterError> {
        let frame = command(chan, protocol::cmd_create_invitation(user_id)).await?;
        let resp = Resp::from_frame(&frame).ok_or(SimplexAdapterError::SidecarProtocol)?;
        let uri =
            protocol::parse_invitation_link(&resp).ok_or(SimplexAdapterError::SidecarProtocol)?;
        Ok(Invitation { uri })
    }

    /// Accept a peer's invitation, then await the async `contactConnected`
    /// event for the usable established [`ConnectionId`].
    ///
    /// The `/_connect <link>` response only confirms acceptance
    /// (`sentConfirmation` with a *pending* pccConnId); the usable contactId
    /// arrives with the async `contactConnected` event (D0026 §12
    /// live-validation finding), so this awaits it.
    pub(crate) async fn accept_invitation<C: RawChannel>(
        chan: &C,
        user_id: i64,
        uri: &str,
    ) -> Result<ConnectionId, SimplexAdapterError> {
        let _ = command(chan, protocol::cmd_connect_via_link(user_id, uri)).await?;
        await_contact_connected(chan).await
    }

    /// Inviter side: after `create_invitation` + sharing the link out of
    /// band, await the peer connecting (the `contactConnected` event), which
    /// yields the established contactId.
    pub(crate) async fn await_connection<C: RawChannel>(
        chan: &C,
    ) -> Result<ConnectionId, SimplexAdapterError> {
        await_contact_connected(chan).await
    }

    /// Send `raw` envelope bytes over `conn` as a `CryptoFile`/XFTP payload.
    ///
    /// The bytes are staged on disk in `files_dir` for the daemon's XFTP
    /// upload (the uniform `CryptoFile` carrier, D0026 §2.4). The returned
    /// chat-item id is a SimpleX-layer ACK only; Cairn's per-pair number is
    /// the adapter's chain position (D0026 §3.2 (c)), so it is parsed solely
    /// to confirm a well-formed send response.
    pub(crate) async fn send_envelope<C: RawChannel>(
        chan: &C,
        files_dir: &Path,
        conn: &ConnectionId,
        raw: &[u8],
    ) -> Result<(), SimplexAdapterError> {
        let path = stage_outgoing(files_dir, raw)?;
        let chat_ref = format!("@{}", conn.0);
        let frame = command(chan, protocol::cmd_send_file(&chat_ref, &path)).await?;
        let resp = Resp::from_frame(&frame).ok_or(SimplexAdapterError::SidecarProtocol)?;
        if resp.is_error() {
            return Err(SimplexAdapterError::SidecarProtocol);
        }
        Ok(())
    }

    /// Receive the next `CryptoFile` envelope for `conn`: accept each offered
    /// file (so the daemon XFTP-downloads it), then read the bytes the daemon
    /// writes on completion. Other events (text, status, contact lifecycle)
    /// are skipped.
    ///
    /// **Live-validated only** (`integration-tests`, D0026 §12): the
    /// offer→accept→complete event sequence + the completed-file path shape
    /// are reference-derived and exercised hermetically against the mock WS
    /// server, not a live daemon.
    pub(crate) async fn recv_envelope<C: RawChannel>(
        chan: &C,
        _conn: &ConnectionId,
    ) -> Result<Vec<u8>, SimplexAdapterError> {
        // `_conn` demultiplexing is live-gated (D0026 §12): the v1 1:1
        // group-minimization property (D0026 §5) means a single active
        // conversation, so the loop consumes the next completed file.
        // Per-connection routing by `contactId` lands with live-CLI
        // validation.
        loop {
            let frame = next_event_frame(chan).await?;
            let Some(resp) = Resp::from_frame(&frame) else {
                continue; // non-conforming event frame; skip
            };
            if let Some(offer) = protocol::parse_received_file_offer(&resp) {
                // Accept the offered file so the daemon XFTP-downloads it.
                let _ = command(chan, protocol::cmd_receive_file(offer.file_id)).await?;
                continue;
            }
            if let Some(path) = protocol::parse_rcv_file_complete_path(&resp) {
                return read_completed_file(&path);
            }
            // Unrelated event — keep draining.
        }
    }

    /// Drain incoming events until a `contactConnected` arrives, returning its
    /// `contact.contactId` as the established [`ConnectionId`] (D0026 §12
    /// finding: the pending `pccConnId` from the create/accept response is NOT
    /// usable for `/_send`; the usable id arrives only with this event).
    /// Intermediate establishment events (`contactConnecting`, the peer's
    /// profile `newChatItems`, etc.) are skipped.
    async fn await_contact_connected<C: RawChannel>(
        chan: &C,
    ) -> Result<ConnectionId, SimplexAdapterError> {
        loop {
            let frame = next_event_frame(chan).await?;
            let Some(resp) = Resp::from_frame(&frame) else {
                continue;
            };
            if let Some(contact_id) = protocol::parse_contact_connected(&resp) {
                return Ok(ConnectionId(contact_id.to_string()));
            }
        }
    }

    /// Await the next incoming event frame + parse it. A malformed (non-JSON)
    /// frame maps to [`SimplexAdapterError::SidecarProtocol`]; a dropped
    /// channel surfaces from [`RawChannel::next_event`] as
    /// [`SimplexAdapterError::SidecarUnavailable`].
    async fn next_event_frame<C: RawChannel>(chan: &C) -> Result<Value, SimplexAdapterError> {
        let event = chan.next_event().await?;
        protocol::parse_frame(&event).ok_or(SimplexAdapterError::SidecarProtocol)
    }

    /// Write outgoing envelope bytes to a freshly-named file in `files_dir`
    /// for the daemon to XFTP-upload; return its path.
    ///
    /// A local staging-IO failure surfaces as
    /// [`SimplexAdapterError::SidecarUnavailable`] — from the caller's view
    /// the sidecar handoff could not be completed locally (the Android-shell
    /// remedy is the same: check the sidecar + its files dir, D0020 §1.6). A
    /// dedicated carrier-IO variant is a documented follow-up.
    fn stage_outgoing(files_dir: &Path, raw: &[u8]) -> Result<String, SimplexAdapterError> {
        std::fs::create_dir_all(files_dir).map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
        let mut name = [0u8; 16];
        getrandom::getrandom(&mut name).map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
        let file_name = format!("cairn-out-{}.bin", hex_lower(&name));
        let path = files_dir.join(file_name);
        std::fs::write(&path, raw).map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
        path.to_str()
            .map(ToString::to_string)
            .ok_or(SimplexAdapterError::SidecarUnavailable)
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

// ===================================================================
// ws-core-backed transport — the desktop / dev / CI transport
// ===================================================================

mod wscore {
    use std::path::PathBuf;

    use simploxide_ws_core::{EventQueue, RawClient, connect};
    use tokio::sync::{Mutex as AsyncMutex, OnceCell};

    use super::SidecarTransport;
    use super::flow::{self, Conn, RawChannel};
    use crate::adapter::{ConnectionId, Invitation, SidecarEndpoint};
    use crate::error::SimplexAdapterError;

    /// A `simploxide-ws-core` raw-frame channel: the command RPC client + the
    /// (exclusively-locked) incoming-event queue.
    struct WsChannel {
        client: RawClient,
        events: AsyncMutex<EventQueue>,
    }

    impl RawChannel for WsChannel {
        async fn send(&self, cmd: String) -> Result<String, SimplexAdapterError> {
            self.client
                .send(cmd)
                .await
                .map_err(|_| SimplexAdapterError::Network {
                    retry_budget_used: 0,
                })
        }

        async fn next_event(&self) -> Result<String, SimplexAdapterError> {
            let mut queue = self.events.lock().await;
            let event = queue
                .next_event()
                .await
                .ok_or(SimplexAdapterError::SidecarUnavailable)?
                .map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
            drop(queue);
            Ok(event)
        }
    }

    /// The desktop / dev / CI [`SidecarTransport`] — a `simploxide-ws-core`
    /// WebSocket client of the SimpleX Chat CLI sidecar (D0026 §1.3).
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
        conn: OnceCell<Conn<WsChannel>>,
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
        async fn conn(&self) -> Result<&Conn<WsChannel>, SimplexAdapterError> {
            self.conn
                .get_or_try_init(|| async {
                    let url = format!("ws://{}:{}", self.endpoint.host, self.endpoint.port);
                    let (client, events) = connect(&url)
                        .await
                        .map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
                    let chan = WsChannel {
                        client,
                        events: AsyncMutex::new(events),
                    };
                    let user_id = flow::query_active_user_id(&chan).await?;
                    Ok(Conn { chan, user_id })
                })
                .await
        }
    }

    impl SidecarTransport for SimploxideTransport {
        async fn create_invitation(&self) -> Result<Invitation, SimplexAdapterError> {
            let conn = self.conn().await?;
            flow::create_invitation(&conn.chan, conn.user_id).await
        }

        async fn accept_invitation(
            &self,
            invitation: Invitation,
        ) -> Result<ConnectionId, SimplexAdapterError> {
            let conn = self.conn().await?;
            flow::accept_invitation(&conn.chan, conn.user_id, &invitation.uri).await
        }

        async fn await_connection(&self) -> Result<ConnectionId, SimplexAdapterError> {
            let conn = self.conn().await?;
            flow::await_connection(&conn.chan).await
        }

        async fn send(&self, conn: &ConnectionId, raw: &[u8]) -> Result<(), SimplexAdapterError> {
            let c = self.conn().await?;
            flow::send_envelope(&c.chan, &self.files_dir, conn, raw).await
        }

        async fn recv(&self, conn: &ConnectionId) -> Result<Vec<u8>, SimplexAdapterError> {
            let c = self.conn().await?;
            flow::recv_envelope(&c.chan, conn).await
        }
    }
}

pub use wscore::SimploxideTransport;

// ===================================================================
// FFI (in-process libsimplex)-backed transport — the Android transport
// ===================================================================
//
// `target_os = "android"`-gated (see the module docs): the dependency only
// enters the build graph for Android targets, so the x86_64-linux CI host
// (clippy/test `--all-features`) never builds `simploxide-sxcrt-sys`. On
// device the SimpleX daemon runs in-process via JNI `libsimplex` (D0020 §1.9
// / D0026 §12 Android-transport finding); there is no Android CLI binary to
// reach over a WebSocket.

#[cfg(target_os = "android")]
mod ffi {
    use std::path::PathBuf;

    use simploxide_ffi_core::{DbOpts, DefaultUser, RawClient, RawEventQueue, init};
    use tokio::sync::{Mutex as AsyncMutex, OnceCell};

    use super::SidecarTransport;
    use super::flow::{self, Conn, RawChannel};
    use crate::adapter::{ConnectionId, Invitation};
    use crate::error::SimplexAdapterError;

    /// A fixed, ASCII, author-chosen profile name for the in-process chat
    /// instance. NOT user input (the FFI layer interpolates it into a
    /// `/create` command, so user input would be a command-injection vector —
    /// see `simploxide_ffi_core::DefaultUser` security note).
    const PROFILE_NAME: &str = "cairn";

    /// A `simploxide-ffi-core` raw-frame channel: the in-process command RPC
    /// client + the (exclusively-locked) incoming-event queue. Structurally
    /// identical to the ws-core channel — the FFI worker thread replaces the
    /// WebSocket as the byte transport.
    struct FfiChannel {
        client: RawClient,
        events: AsyncMutex<RawEventQueue>,
    }

    impl RawChannel for FfiChannel {
        async fn send(&self, cmd: String) -> Result<String, SimplexAdapterError> {
            self.client
                .send(cmd)
                .await
                .map_err(|_| SimplexAdapterError::Network {
                    retry_budget_used: 0,
                })
        }

        async fn next_event(&self) -> Result<String, SimplexAdapterError> {
            let mut queue = self.events.lock().await;
            let event = queue
                .next_event()
                .await
                .ok_or(SimplexAdapterError::SidecarUnavailable)?
                .map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
            drop(queue);
            Ok(event)
        }
    }

    /// The Android [`SidecarTransport`] — an in-process JNI `libsimplex`
    /// instance (`simploxide-ffi-core`) rather than a separate CLI process
    /// (D0020 §1.9 / D0026 §12). Identical envelope flow as
    /// [`super::SimploxideTransport`]; only the bring-up differs (in-process
    /// `init` with an app-private DB + profile vs. a WebSocket dial).
    ///
    /// The chat instance is initialised **lazily** on first use (the
    /// constructor is synchronous to mirror `cairn-uniffi`'s
    /// `uniffi::constructor`), so an init failure surfaces on the first
    /// `create_invitation` / `send` / `recv`.
    ///
    /// **Deferred to the on-device cycle (D0026 §12):** (a) the DB is opened
    /// `unencrypted` here — on device it should be `DbOpts::encrypted` with a
    /// key from the storage/StrongBox layer; (b) routing the in-process
    /// daemon's outbound traffic through the C-Tor SOCKS proxy (D0020 §2.2)
    /// is a post-init `/network socks=…` command, wired when the proxy port
    /// is known.
    pub struct FfiSidecarTransport {
        /// App-private path prefix for the in-process SimpleX chat DB.
        db_path: PathBuf,
        /// Directory for `CryptoFile`/XFTP staging (same role as the ws-core
        /// transport's `files_dir`, D0026 §2.4).
        files_dir: PathBuf,
        conn: OnceCell<Conn<FfiChannel>>,
    }

    impl FfiSidecarTransport {
        /// Construct the (lazily-initialised) in-process transport with an
        /// app-private DB-path prefix + `CryptoFile`-staging directory.
        #[must_use]
        pub fn new(db_path: PathBuf, files_dir: PathBuf) -> Self {
            Self {
                db_path,
                files_dir,
                conn: OnceCell::new(),
            }
        }

        /// Lazily bring up the in-process `libsimplex` instance + learn the
        /// active `userId`.
        async fn conn(&self) -> Result<&Conn<FfiChannel>, SimplexAdapterError> {
            self.conn
                .get_or_try_init(|| async {
                    let (client, events) = init(
                        DefaultUser::regular(PROFILE_NAME),
                        DbOpts::unencrypted(&self.db_path),
                    )
                    .await
                    .map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
                    let chan = FfiChannel {
                        client,
                        events: AsyncMutex::new(events),
                    };
                    let user_id = flow::query_active_user_id(&chan).await?;
                    Ok(Conn { chan, user_id })
                })
                .await
        }
    }

    impl SidecarTransport for FfiSidecarTransport {
        async fn create_invitation(&self) -> Result<Invitation, SimplexAdapterError> {
            let conn = self.conn().await?;
            flow::create_invitation(&conn.chan, conn.user_id).await
        }

        async fn accept_invitation(
            &self,
            invitation: Invitation,
        ) -> Result<ConnectionId, SimplexAdapterError> {
            let conn = self.conn().await?;
            flow::accept_invitation(&conn.chan, conn.user_id, &invitation.uri).await
        }

        async fn await_connection(&self) -> Result<ConnectionId, SimplexAdapterError> {
            let conn = self.conn().await?;
            flow::await_connection(&conn.chan).await
        }

        async fn send(&self, conn: &ConnectionId, raw: &[u8]) -> Result<(), SimplexAdapterError> {
            let c = self.conn().await?;
            flow::send_envelope(&c.chan, &self.files_dir, conn, raw).await
        }

        async fn recv(&self, conn: &ConnectionId) -> Result<Vec<u8>, SimplexAdapterError> {
            let c = self.conn().await?;
            flow::recv_envelope(&c.chan, conn).await
        }
    }
}

#[cfg(target_os = "android")]
pub use ffi::FfiSidecarTransport;

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

    async fn await_connection(&self) -> Result<ConnectionId, SimplexAdapterError> {
        // Mock connections establish instantly; mirror accept_invitation.
        self.accept_invitation(Invitation { uri: String::new() })
            .await
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
// gate per D0026 §12, NOT asserted here. The shared `flow` is transport-
// agnostic, so this also exercises the flow the FFI transport reuses.

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
            // After an accept (/_connect with a link), push the async
            // `contactConnected` event the real daemon emits once established,
            // so accept_invitation's establishment-await (D0026 §12) resolves
            // with the contactId.
            if command.starts_with("/_connect 1 ") {
                let evt =
                    json!({"resp": {"type": "contactConnected", "contact": {"contactId": 42}}});
                if ws.send(Message::text(evt.to_string())).await.is_err() {
                    break;
                }
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
    async fn accept_invitation_awaits_contact_connected() {
        // accept_invitation sends `/_connect <uid> <link>` then awaits the
        // async contactConnected event (D0026 §12); the ConnectionId is the
        // established contact.contactId (42), NOT the pending pccConnId.
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
