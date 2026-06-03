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
    use tokio::sync::{Mutex as AsyncMutex, Notify};

    use crate::adapter::{ConnectionId, Invitation};
    use crate::error::SimplexAdapterError;
    use crate::protocol::{self, Resp};

    use std::collections::{HashMap, HashSet, VecDeque};
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

    /// Per-connection recv demultiplexing state (D0026 §12). A single daemon
    /// event stream carries incoming files for ALL conversations; this routes
    /// each completed file to the connection whose offer it accepted, and
    /// buffers files that complete while a `recv` is waiting on a *different*
    /// connection (so they are not lost / mis-delivered).
    #[derive(Default)]
    pub(crate) struct RecvDemux {
        /// `fileId` → the [`ConnectionId`] whose offer we accepted, so a later
        /// completion for that `fileId` routes to the right connection.
        pending: HashMap<i64, ConnectionId>,
        /// Completed envelope bytes that arrived for a connection OTHER than
        /// the one a given `recv` is waiting on — held until that connection's
        /// own `recv` drains them.
        buffered: HashMap<ConnectionId, VecDeque<Vec<u8>>>,
        /// `fileId`s whose outbound `sndFileCompleteXFTP` was routed by the
        /// shared drainer (D0026 §12). A concurrent `send`'s
        /// `await_snd_file_complete` consumes its own id here instead of racing
        /// the recv-loop for the event — the fix for the single-stream /
        /// two-consumers hazard where a `send` running alongside the recv-loop
        /// had its completion event stolen and hung.
        snd_completed: HashSet<i64>,
    }

    /// An established channel plus the active `userId` the `/_connect` /
    /// `/_send` commands require, and the per-connection recv demux state.
    /// Both transports cache this lazily.
    pub(crate) struct Conn<C> {
        pub(crate) chan: C,
        pub(crate) user_id: i64,
        /// Routes incoming files to the right connection across the shared
        /// event stream (D0026 §12). Locked only briefly for map updates,
        /// never across the network drain, so concurrent `recv`s on different
        /// connections don't starve each other.
        pub(crate) demux: AsyncMutex<RecvDemux>,
        /// The single-drainer token (D0026 §12). Exactly one task at a time
        /// reads `next_event` and routes it for ALL waiters (recv + concurrent
        /// send-completion awaits) via [`pump_one`]; others park on
        /// [`Self::notify`]. Held only across one event read, so it hands off
        /// between events.
        pub(crate) drain: AsyncMutex<()>,
        /// Woken after each routed event so parked waiters re-check their
        /// condition promptly (a bounded park backstops any missed wake).
        pub(crate) notify: Notify,
    }

    /// Issue a command + return the parsed response frame, mapping a
    /// simplex-chat error reply to [`SimplexAdapterError::SidecarProtocol`].
    pub(crate) async fn command<C: RawChannel>(
        chan: &C,
        cmd: String,
    ) -> Result<Value, SimplexAdapterError> {
        // Diagnostic: the leading verb only (avoids logging the full invitation
        // URI / message body), so logcat shows the command sequence. The `debug`
        // trace + the `warn` failure paths below de-opaque a stalled handshake /
        // rejected command (D0026 §12) — every command failure now names its
        // verb + reason instead of bubbling up an unattributed SidecarProtocol.
        let verb: String = cmd.chars().take_while(|c| !c.is_whitespace()).collect();
        log::debug!("cairn-smp: cmd '{verb}' →");
        let raw = chan.send(cmd).await.map_err(|e| {
            log::warn!("cairn-smp: cmd '{verb}' transport send failed: {e}");
            e
        })?;
        let Some(frame) = protocol::parse_frame(&raw) else {
            log::warn!(
                "cairn-smp: cmd '{verb}' → unparseable reply: {}",
                raw.chars().take(200).collect::<String>()
            );
            return Err(SimplexAdapterError::SidecarProtocol);
        };
        if Resp::from_frame(&frame).is_some_and(|r| r.is_error()) {
            log::warn!(
                "cairn-smp: cmd '{verb}' → ERROR reply: {}",
                raw.chars().take(400).collect::<String>()
            );
            return Err(SimplexAdapterError::SidecarProtocol);
        }
        log::debug!("cairn-smp: cmd '{verb}' → ok");
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

    /// Route the daemon's outbound SMP/XFTP traffic through a SOCKS5 proxy
    /// (the C-Tor service, D0020 §2.2) via `/network socks=<addr>`. Issued
    /// once at bring-up, BEFORE any network command (`/_connect` / `/_send`),
    /// so the `.onion` relay addresses resolve over Tor.
    ///
    /// Setting the proxy only configures the client; it does not test
    /// reachability, so this succeeds even when the proxy is down (the failure
    /// surfaces at the first connect). A simplex-chat error reply still maps to
    /// [`SimplexAdapterError::SidecarProtocol`] via [`command`].
    ///
    /// Gated to `any(test, target_os = "android")`: only the Android FFI
    /// transport's bring-up calls this (the ws-core desktop transport defers to
    /// the external CLI's own network config, D0020 §2.2), plus the host flow
    /// tests.
    #[cfg(any(test, target_os = "android"))]
    pub(crate) async fn configure_socks<C: RawChannel>(
        chan: &C,
        addr: &str,
    ) -> Result<(), SimplexAdapterError> {
        log::info!("cairn-smp: configure_socks -> {addr}");
        let _ = command(chan, protocol::cmd_set_socks_proxy(addr)).await?;
        Ok(())
    }

    /// Set libsimplex's RECEIVED-files folder + XFTP temp/work folder (D0026
    /// §12). REQUIRED on Android: without explicit folders, the XFTP receive
    /// path (`getXFTPWorkPath`) computes a default via
    /// `System.Directory.getHomeDirectory`, which faults in `getpwuid` on
    /// Bionic (no passwd DB) — a SIGSEGV the moment an incoming file is
    /// accepted. Issued once at bring-up, before any receive.
    ///
    /// Gated to `any(test, target_os = "android")`: only the Android in-process
    /// transport's bring-up issues it (the ws-core CLI sidecar owns its own
    /// folders), plus the host flow tests.
    #[cfg(any(test, target_os = "android"))]
    pub(crate) async fn configure_folders<C: RawChannel>(
        chan: &C,
        files_folder: &str,
        temp_folder: &str,
    ) -> Result<(), SimplexAdapterError> {
        log::info!("cairn-smp: configure_folders files={files_folder} temp={temp_folder}");
        let _ = command(chan, protocol::cmd_set_files_folder(files_folder)).await?;
        let _ = command(chan, protocol::cmd_set_temp_folder(temp_folder)).await?;
        Ok(())
    }

    /// Create an identifier-less queue + return its out-of-band invitation.
    pub(crate) async fn create_invitation<C: RawChannel>(
        chan: &C,
        user_id: i64,
    ) -> Result<Invitation, SimplexAdapterError> {
        let frame = command(chan, protocol::cmd_create_invitation(user_id)).await?;
        let Some(resp) = Resp::from_frame(&frame) else {
            log::warn!(
                "cairn-smp: create_invitation — /_connect reply not a Resp; head: {}",
                format!("{frame:?}").chars().take(400).collect::<String>()
            );
            return Err(SimplexAdapterError::SidecarProtocol);
        };
        let Some(uri) = protocol::parse_invitation_link(&resp) else {
            // De-opaque (D0026 §12): `/_connect` returned a NON-error response
            // that carries no invitation link — log its tag + head so the
            // unexpected shape is diagnosable instead of a bare SidecarProtocol
            // (this is the failure the de-opaque pass surfaced on Bastille).
            log::warn!(
                "cairn-smp: create_invitation — /_connect reply has no invitation link (tag={}); head: {}",
                resp.tag,
                format!("{frame:?}").chars().take(400).collect::<String>()
            );
            return Err(SimplexAdapterError::SidecarProtocol);
        };
        log::info!("cairn-smp: create_invitation -> link created, awaiting peer");
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
        log::info!("cairn-smp: accept_invitation -> connect sent, awaiting contactConnected");
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

    /// Send `raw` envelope bytes over `conn` as a `CryptoFile`/XFTP payload,
    /// **awaiting the XFTP upload completion** before returning.
    ///
    /// The bytes are staged on disk in `files_dir` for the daemon's XFTP
    /// upload (the uniform `CryptoFile` carrier, D0026 §2.4). The `/_send`
    /// response only *queues* the upload; for delivery assurance (D0026 §12)
    /// this then drains events until the daemon reports `sndFileCompleteXFTP`
    /// for the sent `fileId` — so `send` returning means the envelope actually
    /// reached the XFTP relay, not merely that it was enqueued. (Cairn's
    /// per-pair message number is the adapter's chain position, D0026 §3.2 (c);
    /// the `fileId` is a SimpleX-layer transfer handle, used only to match the
    /// completion event.)
    pub(crate) async fn send_envelope<C: RawChannel>(
        conn: &Conn<C>,
        files_dir: &Path,
        files_base: &Path,
        conn_id: &ConnectionId,
        raw: &[u8],
    ) -> Result<(), SimplexAdapterError> {
        let path = stage_outgoing(files_dir, raw)?;
        // Send-path diagnostic (D0026 §12, two-device B→A): pinpoint exactly
        // where a send stalls — local staging, the `/_send` command's return, or
        // the XFTP upload emitting progress.
        log::info!(
            "cairn-smp: send_envelope staged {} bytes at {path} (conn={})",
            raw.len(),
            conn_id.0
        );
        let chat_ref = format!("@{}", conn_id.0);
        let frame = command(&conn.chan, protocol::cmd_send_file(&chat_ref, &path)).await?;
        let resp = Resp::from_frame(&frame).ok_or(SimplexAdapterError::SidecarProtocol)?;
        log::info!("cairn-smp: send_envelope /_send returned tag={}", resp.tag);
        if resp.is_error() {
            return Err(SimplexAdapterError::SidecarProtocol);
        }
        let file_id =
            protocol::parse_sent_file_id(&resp).ok_or(SimplexAdapterError::SidecarProtocol)?;
        log::info!("cairn-smp: send_envelope awaiting sndFileCompleteXFTP file_id={file_id}");
        // Await the upload completion over the SHARED drainer so a recv-loop
        // running concurrently can't steal the `sndFileCompleteXFTP` event
        // (D0026 §12 two-device fix). `conn_id` is the fallback owner for any
        // incoming completion this drainer routes (1:1 single conversation).
        await_snd_file_complete(conn, files_base, conn_id, file_id).await
    }

    /// Drain events until the daemon reports `sndFileCompleteXFTP` for
    /// `file_id` (the XFTP upload finished). `sndFileProgressXFTP` + unrelated
    /// events are skipped.
    /// Upper bound on the XFTP send-complete await. The `CryptoFile` upload to
    /// an XFTP relay over Tor is several round-trips; bounded so a stalled
    /// upload fails loudly (logged) instead of hanging the caller forever (the
    /// same unbounded-await class as `await_contact_connected`, D0026 §12).
    const XFTP_COMPLETE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

    async fn await_snd_file_complete<C: RawChannel>(
        conn: &Conn<C>,
        files_base: &Path,
        fallback_conn: &ConnectionId,
        file_id: i64,
    ) -> Result<(), SimplexAdapterError> {
        // Drive the SHARED drainer until THIS upload's completion is routed into
        // `snd_completed` (by whichever task drained the event — possibly a
        // concurrent recv-loop), then consume it. The recv-loop no longer steals
        // the `sndFileCompleteXFTP` event (D0026 §12 two-device fix).
        let drive_fut = drive(conn, files_base, fallback_conn, |demux| {
            demux.snd_completed.remove(&file_id).then_some(())
        });
        match tokio::time::timeout(XFTP_COMPLETE_TIMEOUT, drive_fut).await {
            Ok(result) => result,
            Err(_elapsed) => {
                log::warn!(
                    "cairn-smp: await_snd_file_complete TIMEOUT after {}s — XFTP upload did not complete (fileId={file_id})",
                    XFTP_COMPLETE_TIMEOUT.as_secs()
                );
                Err(SimplexAdapterError::SidecarUnavailable)
            }
        }
    }

    /// Receive the next `CryptoFile` envelope **for `conn`**, demultiplexing
    /// the shared daemon event stream by connection (D0026 §12).
    ///
    /// Each offered file is accepted (so the daemon XFTP-downloads it) and its
    /// `fileId` recorded against the offer's `contactId`; on completion the
    /// bytes route to the owning connection. A completion for a connection
    /// OTHER than `conn` is buffered in `demux` (not lost / mis-delivered) and
    /// returned when that connection's own `recv` runs. Files whose offer had
    /// no `contactId` (non-direct-contact shapes) attribute to the requesting
    /// `conn` — the v1 1:1 single-conversation default (D0026 §5).
    ///
    /// `demux` is locked only briefly (map reads/writes), never across the
    /// network drain, so concurrent `recv`s on different connections progress
    /// independently. The offer→accept→complete sequence + the completed-file
    /// path shape are reference-derived; their live-daemon fidelity is the
    /// `integration-tests` gate (D0026 §12), exercised hermetically here.
    pub(crate) async fn recv_envelope<C: RawChannel>(
        conn: &Conn<C>,
        conn_id: &ConnectionId,
        files_base: &Path,
    ) -> Result<Vec<u8>, SimplexAdapterError> {
        // Drive the SHARED drainer until a completed envelope is buffered for
        // THIS connection. `pump_one` routes EVERY event (incl. a concurrent
        // send's `sndFileCompleteXFTP`), so the recv-loop and a send no longer
        // steal each other's events (D0026 §12 two-device fix).
        drive(conn, files_base, conn_id, |demux| {
            demux.buffered.get_mut(conn_id).and_then(VecDeque::pop_front)
        })
        .await
    }

    /// The bounded park a non-drainer waits before re-checking (D0026 §12). The
    /// drainer's `notify_waiters` wakes parked waiters promptly; this backstops
    /// any missed wake (and lets a waiter take over draining if the previous
    /// drainer handed off).
    const PUMP_PARK: std::time::Duration = std::time::Duration::from_millis(500);

    /// Make progress toward a per-waiter `ready` condition over the SHARED event
    /// stream (D0026 §12). The first caller to grab `conn.drain` becomes THE
    /// drainer — it reads + routes one event for ALL waiters via [`pump_one`],
    /// then wakes parked waiters; others park on `conn.notify` (bounded) and
    /// re-check. This is the fix for the single-stream / two-consumers hazard:
    /// `recv_envelope` and a concurrent send's `await_snd_file_complete` both
    /// pull from the one `next_event` queue, and without a single routing
    /// drainer each silently dropped the other's events (a `send` alongside the
    /// recv-loop hung — D0026 §12 two-device finding). Unchanged for the
    /// sequential CLI/test flow: the sole caller simply becomes the drainer.
    async fn drive<C, T>(
        conn: &Conn<C>,
        files_base: &Path,
        fallback_conn: &ConnectionId,
        mut ready: impl FnMut(&mut RecvDemux) -> Option<T>,
    ) -> Result<T, SimplexAdapterError>
    where
        C: RawChannel,
    {
        loop {
            // Hold the demux lock ONLY for the readiness check, in its own scope
            // so the guard drops before the drain/pump below (`pump_one`
            // re-locks demux — holding it here would deadlock).
            let ready_value = {
                let mut demux = conn.demux.lock().await;
                ready(&mut demux)
            };
            if let Some(value) = ready_value {
                return Ok(value);
            }
            match conn.drain.try_lock() {
                Ok(_guard) => {
                    pump_one(&conn.chan, &conn.demux, files_base, fallback_conn).await?;
                    conn.notify.notify_waiters();
                }
                Err(_) => {
                    // Someone else is draining (and routing OUR events too);
                    // wait to be woken, with a bounded backstop.
                    let _ = tokio::time::timeout(PUMP_PARK, conn.notify.notified()).await;
                }
            }
        }
    }

    /// Read ONE event from the shared stream and route it into `demux` so a
    /// single drainer serves BOTH the recv path (incoming offers/completions)
    /// AND concurrent send-completion awaits (D0026 §12). `fallback_conn` owns a
    /// completion whose offer carried no contactId / was untracked (the v1 1:1
    /// single-conversation default, D0026 §5).
    async fn pump_one<C: RawChannel>(
        chan: &C,
        demux: &AsyncMutex<RecvDemux>,
        files_base: &Path,
        fallback_conn: &ConnectionId,
    ) -> Result<(), SimplexAdapterError> {
        let frame = next_event_frame(chan).await?;
        let Some(resp) = Resp::from_frame(&frame) else {
            return Ok(()); // non-conforming event frame; skip
        };
        // Per-event diagnostic (D0026 §12): the offer→accept→complete receive
        // sequence + the outbound sndFileProgress/Complete are silent otherwise.
        log::info!("cairn-smp: pump event type={}", resp.tag);
        // Compact per-item summary of a `newChatItems` event (content type +
        // whether each item carries a file id) so the received-file offer's
        // location is visible without the giant `chatInfo` blob.
        if resp.tag == "newChatItems"
            && let Some(items) = resp.body.get("chatItems").and_then(Value::as_array)
        {
            let summary: Vec<String> = items
                .iter()
                .enumerate()
                .map(|(i, it)| {
                    let ci = it.get("chatItem");
                    let ctype = ci
                        .and_then(|c| c.get("content"))
                        .and_then(|c| c.get("type"))
                        .and_then(Value::as_str)
                        .unwrap_or("?");
                    let file = ci
                        .and_then(|c| c.get("file"))
                        .and_then(|f| f.get("fileId"))
                        .and_then(Value::as_i64);
                    format!("[{i}]{ctype} file={file:?}")
                })
                .collect();
            log::info!("cairn-smp: pump items: {}", summary.join(" "));
        }

        // Outbound XFTP upload completion → satisfy a concurrent send's await.
        if let Some(file_id) = protocol::parse_snd_file_complete(&resp) {
            demux.lock().await.snd_completed.insert(file_id);
            return Ok(());
        }

        // Incoming file offer → accept (so the daemon XFTP-downloads it; no
        // demux lock held across the command), then record the owning conn.
        if let Some(offer) = protocol::parse_received_file_offer(&resp) {
            let _ = command(chan, protocol::cmd_receive_file(offer.file_id)).await?;
            let owner = offer
                .contact_id
                .map_or_else(|| fallback_conn.clone(), |id| ConnectionId(id.to_string()));
            demux.lock().await.pending.insert(offer.file_id, owner);
            return Ok(());
        }

        // Incoming file completion → read bytes + buffer for the owning conn
        // (the waiting `recv` for that conn pops it on its next `ready` check).
        if let Some(done) = protocol::parse_rcv_file_complete(&resp) {
            let bytes = read_completed_file(files_base, &done.path)?;
            let owner = {
                let mut state = demux.lock().await;
                done.file_id
                    .and_then(|fid| state.pending.remove(&fid))
                    .unwrap_or_else(|| fallback_conn.clone())
            };
            demux
                .lock()
                .await
                .buffered
                .entry(owner)
                .or_default()
                .push_back(bytes);
        }
        Ok(())
    }

    /// Drain incoming events until a `contactConnected` arrives, returning its
    /// `contact.contactId` as the established [`ConnectionId`] (D0026 §12
    /// finding: the pending `pccConnId` from the create/accept response is NOT
    /// usable for `/_send`; the usable id arrives only with this event).
    /// Intermediate establishment events (`contactConnecting`, the peer's
    /// profile `newChatItems`, etc.) are skipped.
    /// Upper bound on the `contactConnected` await. The SimpleX duplex
    /// handshake is several SMP round-trips over Tor (each a fresh circuit to a
    /// `.onion` relay), so this is generous — but bounded, so a stalled
    /// handshake fails loudly (logged) instead of hanging the caller forever
    /// (the prior unbounded loop, D0026 §12 two-party on-device finding).
    const CONTACT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

    async fn await_contact_connected<C: RawChannel>(
        chan: &C,
    ) -> Result<ConnectionId, SimplexAdapterError> {
        let drain = async {
            loop {
                let frame = next_event_frame(chan).await?;
                let Some(resp) = Resp::from_frame(&frame) else {
                    continue;
                };
                // Per-event diagnostic: the type tag of every event drained
                // while awaiting establishment, so a stalled handshake shows
                // exactly which events did (and did not) arrive on-device.
                log::info!("cairn-smp: await_contact_connected event type={}", resp.tag);
                if let Some(contact_id) = protocol::parse_contact_connected(&resp) {
                    return Ok::<ConnectionId, SimplexAdapterError>(ConnectionId(
                        contact_id.to_string(),
                    ));
                }
            }
        };
        match tokio::time::timeout(CONTACT_CONNECT_TIMEOUT, drain).await {
            Ok(result) => result,
            Err(_elapsed) => {
                log::warn!(
                    "cairn-smp: await_contact_connected TIMEOUT after {}s — no contactConnected event arrived",
                    CONTACT_CONNECT_TIMEOUT.as_secs()
                );
                Err(SimplexAdapterError::SidecarUnavailable)
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
    ///
    /// With a files folder configured (Android bring-up, D0026 §12), the daemon
    /// reports the completed file's path RELATIVE to that folder, so it is
    /// resolved against `files_base`. An absolute path (no files folder — e.g.
    /// the ws-core CLI sidecar) is read as-is.
    fn read_completed_file(files_base: &Path, path: &str) -> Result<Vec<u8>, SimplexAdapterError> {
        let p = Path::new(path);
        let full = if p.is_absolute() {
            p.to_path_buf()
        } else {
            files_base.join(p)
        };
        std::fs::read(full).map_err(|_| SimplexAdapterError::SidecarUnavailable)
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
                    Ok(Conn {
                        chan,
                        user_id,
                        demux: AsyncMutex::new(flow::RecvDemux::default()),
                        drain: AsyncMutex::new(()),
                        notify: tokio::sync::Notify::new(),
                    })
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
            flow::send_envelope(c, &self.files_dir, &self.files_dir.join("sx-files"), conn, raw)
                .await
        }

        async fn recv(&self, conn: &ConnectionId) -> Result<Vec<u8>, SimplexAdapterError> {
            let c = self.conn().await?;
            // Received files land in the configured `sx-files` folder; the
            // daemon reports their paths relative to it on Android (D0026 §12).
            // The ws-core CLI path is absolute, so the base is ignored there.
            flow::recv_envelope(c, conn, &self.files_dir.join("sx-files")).await
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
    /// **Tor routing (D0020 §2.2):** when `socks_proxy` is `Some`, a
    /// `/network socks=<addr>` command is issued at bring-up so the daemon's
    /// outbound SMP/XFTP traffic (incl. the `.onion` relay addresses) routes
    /// through the C-Tor SOCKS proxy; `None` leaves it on direct connections.
    /// What remains for an on-device Tor run is a *running* proxy on the
    /// device (Orbot / the C-Tor `ForegroundService`), not adapter code.
    ///
    /// **Still deferred to the on-device cycle (D0026 §12):** the DB is opened
    /// `unencrypted` here — on device it should be `DbOpts::encrypted` with a
    /// key from the storage/StrongBox layer.
    pub struct FfiSidecarTransport {
        /// App-private path prefix for the in-process SimpleX chat DB.
        db_path: PathBuf,
        /// Directory for `CryptoFile`/XFTP staging (same role as the ws-core
        /// transport's `files_dir`, D0026 §2.4).
        files_dir: PathBuf,
        /// Optional SOCKS5 proxy `<ip>:<port>` (the C-Tor service, D0020 §2.2).
        /// `Some` → a `/network socks=<addr>` command at bring-up routes
        /// outbound traffic over Tor; `None` → direct connections.
        socks_proxy: Option<String>,
        conn: OnceCell<Conn<FfiChannel>>,
    }

    impl FfiSidecarTransport {
        /// Construct the (lazily-initialised) in-process transport with an
        /// app-private DB-path prefix + `CryptoFile`-staging directory, with
        /// outbound traffic on direct (non-Tor) connections.
        #[must_use]
        pub fn new(db_path: PathBuf, files_dir: PathBuf) -> Self {
            Self::with_socks_proxy(db_path, files_dir, None)
        }

        /// As [`Self::new`], but route the daemon's outbound SMP/XFTP traffic
        /// through the SOCKS5 proxy at `socks_proxy` (`<ip>:<port>`, the C-Tor
        /// service, D0020 §2.2) via a `/network socks=` command issued at
        /// bring-up. `None` is equivalent to [`Self::new`].
        #[must_use]
        pub fn with_socks_proxy(
            db_path: PathBuf,
            files_dir: PathBuf,
            socks_proxy: Option<String>,
        ) -> Self {
            Self {
                db_path,
                files_dir,
                socks_proxy,
                conn: OnceCell::new(),
            }
        }

        /// Lazily bring up the in-process `libsimplex` instance + learn the
        /// active `userId`.
        async fn conn(&self) -> Result<&Conn<FfiChannel>, SimplexAdapterError> {
            self.conn
                .get_or_try_init(|| async {
                    // Bring-up cause-logging (D0026 §12): a createInvitation/send
                    // `SidecarFailure` is most often a failed bring-up step here,
                    // previously opaque. `init` discards its rich error into
                    // SidecarUnavailable — log the real cause first.
                    log::debug!("cairn-smp: FFI conn bring-up — init libsimplex");
                    let (client, events) = init(
                        DefaultUser::regular(PROFILE_NAME),
                        DbOpts::unencrypted(&self.db_path),
                    )
                    .await
                    .map_err(|e| {
                        log::error!("cairn-smp: libsimplex init FAILED: {e:?}");
                        SimplexAdapterError::SidecarUnavailable
                    })?;
                    log::info!("cairn-smp: FFI conn — libsimplex init ok, configuring");
                    let chan = FfiChannel {
                        client,
                        events: AsyncMutex::new(events),
                    };
                    // Route outbound SMP/XFTP through the C-Tor SOCKS proxy
                    // (D0020 §2.2) before any network command, when configured.
                    if let Some(addr) = self.socks_proxy.as_deref() {
                        flow::configure_socks(&chan, addr).await?;
                    }
                    // Point libsimplex at explicit files + temp folders (subdirs
                    // of files_dir) so the XFTP RECEIVE path skips
                    // getHomeDirectory→getpwuid — a Bionic SIGSEGV on Android
                    // (D0026 §12 on-device receive finding).
                    let files_folder = self.files_dir.join("sx-files");
                    let temp_folder = self.files_dir.join("sx-temp");
                    let _ = std::fs::create_dir_all(&files_folder);
                    let _ = std::fs::create_dir_all(&temp_folder);
                    flow::configure_folders(
                        &chan,
                        &files_folder.to_string_lossy(),
                        &temp_folder.to_string_lossy(),
                    )
                    .await?;
                    let user_id = flow::query_active_user_id(&chan).await?;
                    log::info!("cairn-smp: FFI conn ESTABLISHED (userId={user_id})");
                    Ok(Conn {
                        chan,
                        user_id,
                        demux: AsyncMutex::new(flow::RecvDemux::default()),
                        drain: AsyncMutex::new(()),
                        notify: tokio::sync::Notify::new(),
                    })
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
            flow::send_envelope(c, &self.files_dir, &self.files_dir.join("sx-files"), conn, raw)
                .await
        }

        async fn recv(&self, conn: &ConnectionId) -> Result<Vec<u8>, SimplexAdapterError> {
            let c = self.conn().await?;
            // Received files land in the configured `sx-files` folder; the
            // daemon reports their paths relative to it on Android (D0026 §12).
            // The ws-core CLI path is absolute, so the base is ignored there.
            flow::recv_envelope(c, conn, &self.files_dir.join("sx-files")).await
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
            // After a `/_send`, push the async `sndFileCompleteXFTP` the real
            // daemon emits once the XFTP upload finishes (fileId 1, matching
            // the send response), so `send_envelope`'s delivery-assurance
            // await (D0026 §12) resolves.
            if command.starts_with("/_send ") {
                let evt = json!({"resp": {"type": "sndFileCompleteXFTP", "chatItem": {"file": {"fileId": 1}}}});
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

// ===================================================================
// Recv-demultiplexing unit tests (D0026 §12)
// ===================================================================
//
// Drive `flow::recv_envelope` directly with a scripted `RawChannel` to prove
// per-connection routing + the buffer path (a file that completes for one
// connection while a `recv` waits on another must be buffered, not lost or
// mis-delivered). No daemon / WS server needed.

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests assert on known-shape fixtures; unwrap panics ARE the failure signal"
)]
mod demux_tests {
    use super::flow::{self, Conn, RawChannel, RecvDemux};
    use crate::adapter::ConnectionId;
    use crate::error::SimplexAdapterError;

    use std::collections::VecDeque;
    use tokio::sync::{Mutex as AsyncMutex, Notify};

    /// A `RawChannel` that replays a scripted event sequence + records the
    /// commands sent (the `/freceive` accepts).
    struct ScriptChannel {
        events: AsyncMutex<VecDeque<String>>,
        sent: AsyncMutex<Vec<String>>,
    }

    impl RawChannel for ScriptChannel {
        async fn send(&self, cmd: String) -> Result<String, SimplexAdapterError> {
            self.sent.lock().await.push(cmd);
            Ok(r#"{"resp":{"type":"cmdOk"}}"#.to_string())
        }
        async fn next_event(&self) -> Result<String, SimplexAdapterError> {
            self.events
                .lock()
                .await
                .pop_front()
                .ok_or(SimplexAdapterError::SidecarUnavailable)
        }
    }

    fn offer(file_id: i64, contact_id: i64) -> String {
        format!(
            r#"{{"resp":{{"type":"newChatItems","chatItems":[{{"chatInfo":{{"contact":{{"contactId":{contact_id}}}}},"chatItem":{{"file":{{"fileId":{file_id}}}}}}}]}}}}"#
        )
    }
    fn complete(file_id: i64, path: &str) -> String {
        format!(
            r#"{{"resp":{{"type":"rcvFileComplete","chatItem":{{"chatItem":{{"file":{{"fileId":{file_id},"fileSource":{{"filePath":"{path}"}}}}}}}}}}}}"#
        )
    }

    #[tokio::test]
    async fn recv_demux_routes_and_buffers_by_connection() {
        // conn-20's file completes FIRST while we recv on conn-10 — it must be
        // buffered (not mis-delivered) + returned by conn-20's own recv.
        let dir = std::env::temp_dir().join(format!("cairn-demux-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path_a = dir.join("a.bin");
        let path_b = dir.join("b.bin");
        std::fs::write(&path_a, b"envelope-A").unwrap();
        std::fs::write(&path_b, b"envelope-B").unwrap();

        let events: VecDeque<String> = [
            offer(2, 20),
            complete(2, path_b.to_str().unwrap()),
            offer(1, 10),
            complete(1, path_a.to_str().unwrap()),
        ]
        .into_iter()
        .collect();
        let chan = ScriptChannel {
            events: AsyncMutex::new(events),
            sent: AsyncMutex::new(Vec::new()),
        };
        let conn = Conn {
            chan,
            user_id: 0,
            demux: AsyncMutex::new(RecvDemux::default()),
            drain: AsyncMutex::new(()),
            notify: Notify::new(),
        };
        let conn_a = ConnectionId("10".to_string());
        let conn_b = ConnectionId("20".to_string());

        // recv(conn-10) drains conn-20's offer+completion (buffering B), then
        // conn-10's offer+completion → returns A.
        let got_a = flow::recv_envelope(&conn, &conn_a, &dir).await.unwrap();
        assert_eq!(got_a, b"envelope-A");

        // recv(conn-20) returns the buffered envelope WITHOUT draining (the
        // event queue is now empty; draining would error).
        let got_b = flow::recv_envelope(&conn, &conn_b, &dir).await.unwrap();
        assert_eq!(got_b, b"envelope-B");

        // Both offers were accepted (two `/freceive` commands).
        let sent = conn.chan.sent.lock().await;
        assert_eq!(sent.len(), 2);
        assert!(sent.iter().all(|c| c.starts_with("/freceive ")));
        drop(sent);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn configure_socks_issues_network_command() {
        // flow::configure_socks (D0020 §2.2) issues exactly one `/network`
        // command at bring-up (socks + clearnet-via-Tor host mode) + tolerates
        // the cmdOk reply (it only configures the client; reachability untested).
        let chan = ScriptChannel {
            events: AsyncMutex::new(VecDeque::new()),
            sent: AsyncMutex::new(Vec::new()),
        };
        flow::configure_socks(&chan, "127.0.0.1:9050")
            .await
            .unwrap();
        let sent: Vec<String> = chan.sent.lock().await.clone();
        assert_eq!(
            sent.as_slice(),
            ["/network socks=127.0.0.1:9050 socks-mode=always host-mode=public"]
        );
    }

    #[tokio::test]
    async fn configure_folders_issues_files_and_temp_commands() {
        // flow::configure_folders (D0026 §12) issues `/_files_folder` then
        // `/_temp_folder` at bring-up so the Android XFTP receive path does not
        // fall back to getHomeDirectory→getpwuid (a Bionic SIGSEGV).
        let chan = ScriptChannel {
            events: AsyncMutex::new(VecDeque::new()),
            sent: AsyncMutex::new(Vec::new()),
        };
        flow::configure_folders(&chan, "/files", "/temp")
            .await
            .unwrap();
        let sent: Vec<String> = chan.sent.lock().await.clone();
        assert_eq!(
            sent.as_slice(),
            ["/_files_folder /files", "/_temp_folder /temp"]
        );
    }

    /// A BLOCKING channel: `next_event` awaits an mpsc receiver (so a recv-loop
    /// genuinely WAITS for the next event, as on-device — not the script
    /// channel's error-on-empty), and `send` returns a canned non-error
    /// `/_send` reply carrying a fixed fileId.
    struct MpscChannel {
        rx: AsyncMutex<tokio::sync::mpsc::UnboundedReceiver<String>>,
        sent: AsyncMutex<Vec<String>>,
        send_reply: String,
    }

    impl RawChannel for MpscChannel {
        async fn send(&self, cmd: String) -> Result<String, SimplexAdapterError> {
            self.sent.lock().await.push(cmd);
            Ok(self.send_reply.clone())
        }
        async fn next_event(&self) -> Result<String, SimplexAdapterError> {
            self.rx
                .lock()
                .await
                .recv()
                .await
                .ok_or(SimplexAdapterError::SidecarUnavailable)
        }
    }

    fn sent_reply(file_id: i64) -> String {
        format!(
            r#"{{"resp":{{"type":"newChatItems","chatItems":[{{"chatItem":{{"file":{{"fileId":{file_id}}}}}}}]}}}}"#
        )
    }
    fn snd_complete(file_id: i64) -> String {
        format!(
            r#"{{"resp":{{"type":"sndFileCompleteXFTP","chatItem":{{"file":{{"fileId":{file_id}}}}}}}}}"#
        )
    }

    #[tokio::test]
    async fn send_completes_while_recv_loop_drains_shared_stream() {
        // The D0026 §12 two-device bug: a `send`'s sndFileCompleteXFTP await and
        // the recv-loop both consume the ONE event stream. With the OLD code the
        // recv-loop ate + discarded the send's completion event and the send
        // hung (no progress, no timeout — exactly device B's symptom). Here both
        // run CONCURRENTLY over a blocking channel; the unified drainer routes
        // each event to the right waiter, so BOTH must finish. The send's
        // completion is fed FIRST — the ordering that broke the old code.
        let dir = std::env::temp_dir().join(format!("cairn-concurrent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let inbound = dir.join("inbound.bin");
        std::fs::write(&inbound, b"hi-from-peer").unwrap();

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let conn = Conn {
            chan: MpscChannel {
                rx: AsyncMutex::new(rx),
                sent: AsyncMutex::new(Vec::new()),
                send_reply: sent_reply(99),
            },
            user_id: 0,
            demux: AsyncMutex::new(RecvDemux::default()),
            drain: AsyncMutex::new(()),
            notify: Notify::new(),
        };
        let conn_id = ConnectionId("7".to_string());

        tx.send(snd_complete(99)).unwrap(); // the SEND's completion — fed first
        tx.send(offer(1, 7)).unwrap(); // then the recv's incoming file…
        tx.send(complete(1, inbound.to_str().unwrap())).unwrap();

        // A hard timeout turns a regression (the hang) into a clean failure.
        let (recv_res, send_res) =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(
                    flow::recv_envelope(&conn, &conn_id, &dir),
                    flow::send_envelope(&conn, &dir, &dir, &conn_id, b"hello-peer"),
                )
            })
            .await
            .expect("deadlock: send + recv did not both complete (the two-consumers bug)");

        assert_eq!(recv_res.unwrap(), b"hi-from-peer"); // recv got its message
        send_res.unwrap(); // send completed — its sndFileCompleteXFTP was routed

        let _ = std::fs::remove_dir_all(&dir);
    }
}
