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
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

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

    /// Forward [`RawChannel`] through an `Arc`, so the shared single owner of a
    /// channel — the background drainer holds an `Arc<C>`, and every [`Conn`]
    /// stores its channel as `Arc<C>` (D0026 §12) — can be used wherever a
    /// `&C: RawChannel` is expected. Generic functions like [`command`] take
    /// `&C` and do NOT deref-coerce through `&Arc<C>` during type inference, so
    /// this blanket impl (not auto-deref) is what makes `&conn.chan` resolve.
    impl<C: RawChannel> RawChannel for Arc<C> {
        fn send(
            &self,
            cmd: String,
        ) -> impl Future<Output = Result<String, SimplexAdapterError>> + Send {
            (**self).send(cmd)
        }

        fn next_event(&self) -> impl Future<Output = Result<String, SimplexAdapterError>> + Send {
            (**self).next_event()
        }
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
        /// `fileId`s whose outbound XFTP upload completed, routed by the
        /// background drainer (D0026 §12). A `send_envelope`'s completion wait
        /// consumes its own id here. Completion arrives either as a discrete
        /// `sndFileCompleteXFTP` (ws-core CLI) or a `chatItemsStatusesUpdated`
        /// with `sndProgress=complete` (Android / in-process libsimplex).
        snd_completed: HashSet<i64>,
        /// Established [`ConnectionId`]s from `contactConnected` events, FIFO.
        /// The inviter/accept side's `await_connection` pops its established
        /// contactId here — routed by the SAME background drainer that handles
        /// recv/send completions, so establishment no longer needs a separate
        /// `next_event` consumer that would contend with it (D0026 §12).
        connected: VecDeque<ConnectionId>,
    }

    /// Per-connection shared state the background drainer routes events into
    /// and that `send` / `recv` / `await_connection` await — behind an `Arc`
    /// so the spawned drainer task and the waiters share one copy.
    pub(crate) struct Shared {
        /// Routes incoming files + send/recv completions + establishment across
        /// the ONE event stream (D0026 §12). Locked only briefly for map
        /// updates, never across the network drain.
        pub(crate) demux: AsyncMutex<RecvDemux>,
        /// Woken after each routed event so parked waiters re-check promptly
        /// (a bounded [`WAIT_PARK`] backstops any missed wake).
        pub(crate) notify: Notify,
    }

    /// An established channel plus the active `userId` the `/_connect` /
    /// `/_send` commands require, plus the shared demux a dedicated background
    /// drainer task feeds.
    ///
    /// The drainer (spawned once at bring-up, [`spawn_drainer`]) is the **sole**
    /// `next_event` consumer (D0026 §12): one task reads the event stream and
    /// routes every event for ALL waiters, so a `send`'s completion-await never
    /// contends with the recv loop for the stream. That contention — two tasks
    /// each trying to drain `next_event` while the other held the event-queue
    /// lock — wedged a send-then-receive on the single-threaded FFI runtime
    /// (the on-device "B→A right after A→B" finding): the upload completed and
    /// the offer arrived, but neither task could make progress. With a single
    /// drainer, waiters only read `shared.demux`; they never touch the stream.
    pub(crate) struct Conn<C> {
        pub(crate) chan: Arc<C>,
        pub(crate) user_id: i64,
        pub(crate) shared: Arc<Shared>,
        /// The background drainer handle, aborted on drop so the task (which
        /// holds an `Arc` to `chan` + `shared`) does not outlive the transport.
        /// `pub(crate)` so the sibling wscore/ffi `conn()` builders (and tests)
        /// can move a [`spawn_drainer`] handle in.
        pub(crate) drainer: tokio::task::JoinHandle<()>,
    }

    impl<C> Drop for Conn<C> {
        fn drop(&mut self) {
            self.drainer.abort();
        }
    }

    /// The bucket key for a completion/offer that carried no identifiable owner
    /// (an offer whose `chatInfo` is not a direct contact). Contact ids are
    /// non-empty numeric strings, so the empty string is a safe sentinel; v1 is
    /// 1:1 so `recv` also drains this default bucket (D0026 §5).
    const fn untracked_conn() -> ConnectionId {
        ConnectionId(String::new())
    }

    /// How long a waiter parks before re-checking its condition. The drainer's
    /// `notify_waiters` wakes it promptly; this only backstops a missed wake
    /// (`notify_waiters` stores no permit), bounding post-notify re-check
    /// latency. Correctness does not depend on it — the drainer makes
    /// independent progress and waiters never block the stream.
    const WAIT_PARK: std::time::Duration = std::time::Duration::from_millis(200);

    /// Spawn the sole `next_event` consumer for `chan`: read each event and
    /// route it (via [`pump_one`]) into `shared.demux`, then wake waiters.
    /// Runs until the event channel closes or the owning [`Conn`] aborts it on
    /// drop. `C: 'static` + the `RawChannel: Send + Sync` bound make the task
    /// spawnable on the (persistent) tokio runtime UniFFI drives.
    pub(crate) fn spawn_drainer<C: RawChannel + 'static>(
        chan: Arc<C>,
        shared: Arc<Shared>,
        files_base: PathBuf,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                match pump_one(&chan, &shared.demux, &files_base).await {
                    Ok(()) => shared.notify.notify_waiters(),
                    Err(e) => {
                        log::debug!("cairn-smp: event drainer exiting: {e}");
                        break;
                    }
                }
            }
        })
    }

    /// Park until `ready` is satisfied by the background-drained `demux`. The
    /// drainer wakes waiters after each event; [`WAIT_PARK`] backstops a missed
    /// wake. Waiters NEVER read the event stream (the drainer is the sole
    /// consumer), so this cannot contend with draining and cannot wedge it
    /// (D0026 §12) — the structural fix for the send-then-receive deadlock.
    async fn wait_for<T>(
        shared: &Shared,
        mut ready: impl FnMut(&mut RecvDemux) -> Option<T>,
    ) -> Result<T, SimplexAdapterError> {
        loop {
            // Register intent before checking so a wake between the check and
            // the park is not lost (the park also has a bounded backstop).
            let notified = shared.notify.notified();
            {
                let mut demux = shared.demux.lock().await;
                if let Some(value) = ready(&mut demux) {
                    return Ok(value);
                }
            }
            let _ = tokio::time::timeout(WAIT_PARK, notified).await;
        }
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
        // Top-level `{"error": {...}}` agent error (D0026 §12): a relay
        // BROKER/TIMEOUT etc. arrives in THIS shape, NOT `{"resp":{type:
        // chatError}}`, so the `is_error()` check below misses it. Classify it
        // so a transient relay timeout becomes a RETRYABLE Network error
        // (callers retry) instead of an unattributed SidecarProtocol.
        if let Some(class) = protocol::classify_command_error(&frame) {
            log::warn!(
                "cairn-smp: cmd '{verb}' → agent error ({class:?}): {}",
                raw.chars().take(300).collect::<String>()
            );
            return Err(match class {
                protocol::CommandErrorClass::TransientRelay => SimplexAdapterError::Network {
                    retry_budget_used: 0,
                },
                protocol::CommandErrorClass::Fatal => SimplexAdapterError::SidecarProtocol,
            });
        }
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

    /// Max retries for a transient relay (`BROKER`/`NETWORK`) command error
    /// before giving up (D0026 §12). A Tor relay timing out once while creating
    /// or connecting to a queue is routine; bounded retries with linear backoff
    /// recover it without hanging the caller forever.
    const RELAY_RETRY_MAX: u8 = 3;

    /// Linear backoff between relay-timeout retries (attempt is 1-based).
    fn relay_backoff(attempt: u8) -> std::time::Duration {
        std::time::Duration::from_millis(750_u64.saturating_mul(u64::from(attempt)))
    }

    /// Create an identifier-less queue + return its out-of-band invitation,
    /// RETRYING transient relay timeouts (D0026 §12). The SMP relay returning
    /// `errorAgent`/`BROKER`/`TIMEOUT` over Tor is routine — a single timeout
    /// must not fail invitation creation, so a transient `Network` error is
    /// retried up to [`RELAY_RETRY_MAX`].
    pub(crate) async fn create_invitation<C: RawChannel>(
        chan: &C,
        user_id: i64,
    ) -> Result<Invitation, SimplexAdapterError> {
        let mut attempt = 0u8;
        loop {
            match try_create_invitation(chan, user_id).await {
                Ok(inv) => return Ok(inv),
                Err(SimplexAdapterError::Network { .. }) if attempt < RELAY_RETRY_MAX => {
                    attempt = attempt.saturating_add(1);
                    let backoff = relay_backoff(attempt);
                    log::warn!(
                        "cairn-smp: create_invitation — transient relay timeout, retry {attempt}/{RELAY_RETRY_MAX} in {}ms",
                        backoff.as_millis()
                    );
                    tokio::time::sleep(backoff).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// One invitation-creation attempt (wrapped by [`create_invitation`]'s retry).
    async fn try_create_invitation<C: RawChannel>(
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
        conn: &Conn<C>,
        uri: &str,
    ) -> Result<ConnectionId, SimplexAdapterError> {
        // Retry the connect command on a transient relay timeout (D0026 §12),
        // same as create_invitation; the subsequent contactConnected await has
        // its own bounded timeout.
        let mut attempt = 0u8;
        loop {
            match command(
                &conn.chan,
                protocol::cmd_connect_via_link(conn.user_id, uri),
            )
            .await
            {
                Ok(_) => break,
                Err(SimplexAdapterError::Network { .. }) if attempt < RELAY_RETRY_MAX => {
                    attempt = attempt.saturating_add(1);
                    let backoff = relay_backoff(attempt);
                    log::warn!(
                        "cairn-smp: accept_invitation — transient relay timeout, retry {attempt}/{RELAY_RETRY_MAX} in {}ms",
                        backoff.as_millis()
                    );
                    tokio::time::sleep(backoff).await;
                }
                Err(e) => return Err(e),
            }
        }
        log::info!("cairn-smp: accept_invitation -> connect sent, awaiting contactConnected");
        // The established contactId is routed into `shared.demux.connected` by
        // the background drainer (the SOLE `next_event` consumer, D0026 §12), so
        // we only pop it here — never read the stream — bounded by the same
        // generous handshake timeout the unbounded loop used to lack.
        match tokio::time::timeout(
            CONTACT_CONNECT_TIMEOUT,
            wait_for(&conn.shared, |d| d.connected.pop_front()),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                log::warn!(
                    "cairn-smp: accept_invitation TIMEOUT after {}s — no contactConnected event arrived",
                    CONTACT_CONNECT_TIMEOUT.as_secs()
                );
                Err(SimplexAdapterError::SidecarUnavailable)
            }
        }
    }

    /// Inviter side: after `create_invitation` + sharing the link out of
    /// band, await the peer connecting (the `contactConnected` event), which
    /// yields the established contactId — popped from `shared.demux.connected`
    /// where the background drainer routes it (D0026 §12).
    pub(crate) async fn await_connection<C: RawChannel>(
        conn: &Conn<C>,
    ) -> Result<ConnectionId, SimplexAdapterError> {
        match tokio::time::timeout(
            CONTACT_CONNECT_TIMEOUT,
            wait_for(&conn.shared, |d| d.connected.pop_front()),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                log::warn!(
                    "cairn-smp: await_connection TIMEOUT after {}s — no contactConnected event arrived",
                    CONTACT_CONNECT_TIMEOUT.as_secs()
                );
                Err(SimplexAdapterError::SidecarUnavailable)
            }
        }
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
        // The completed-download base is read by the background drainer, not by
        // the send path; kept in the signature so both transports' `send` call
        // sites stay symmetric with `recv` (D0026 §12).
        _files_base: &Path,
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
        // Await the upload completion over the SHARED state the background
        // drainer feeds: the drainer (sole `next_event` consumer) routes THIS
        // upload's completion into `snd_completed`; we only pop it, so a recv-loop
        // running concurrently can't steal the completion event and we never
        // touch the stream (D0026 §12 two-device fix). Bounded so a stalled
        // upload fails loudly instead of hanging the caller forever.
        match tokio::time::timeout(
            XFTP_COMPLETE_TIMEOUT,
            wait_for(&conn.shared, |d| {
                d.snd_completed.remove(&file_id).then_some(())
            }),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                log::warn!(
                    "cairn-smp: send_envelope TIMEOUT after {}s — XFTP upload did not complete (fileId={file_id})",
                    XFTP_COMPLETE_TIMEOUT.as_secs()
                );
                Err(SimplexAdapterError::SidecarUnavailable)
            }
        }
    }

    /// Upper bound on the XFTP send-complete await. The `CryptoFile` upload to
    /// an XFTP relay over Tor is several round-trips; bounded so a stalled
    /// upload fails loudly (logged) instead of hanging the caller forever (the
    /// same unbounded-await class as the `contactConnected` await, D0026 §12).
    const XFTP_COMPLETE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

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
    ) -> Result<Vec<u8>, SimplexAdapterError> {
        // Wait on the SHARED state the background drainer feeds until a completed
        // envelope is buffered for THIS connection (or the untracked default
        // bucket — the v1 1:1 single-conversation case, D0026 §5). The drainer
        // (sole `next_event` consumer) routes EVERY event, incl. a concurrent
        // send's completion, so the recv-loop and a send no longer steal each
        // other's events (D0026 §12 two-device fix). No timeout: a `recv` blocks
        // until a message arrives, as a network transport does.
        wait_for(&conn.shared, |demux| {
            demux
                .buffered
                .get_mut(conn_id)
                .and_then(VecDeque::pop_front)
                .or_else(|| {
                    demux
                        .buffered
                        .get_mut(&untracked_conn())
                        .and_then(VecDeque::pop_front)
                })
        })
        .await
    }

    /// Read ONE event from the shared stream and route it into `demux` so the
    /// single background drainer serves the recv path (incoming offers/
    /// completions), concurrent send-completion awaits, AND establishment
    /// (`contactConnected`) for ALL waiters (D0026 §12). A completion/offer whose
    /// `chatInfo` carried no contactId attributes to [`untracked_conn`] — the v1
    /// 1:1 single-conversation default (D0026 §5), which `recv_envelope` also
    /// drains.
    async fn pump_one<C: RawChannel>(
        chan: &C,
        demux: &AsyncMutex<RecvDemux>,
        files_base: &Path,
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

        // Connection establishment → push the established contactId onto the
        // FIFO so the inviter/accept side's `await_connection` / `accept_invitation`
        // pops it (D0026 §12). The background drainer is the SOLE `next_event`
        // consumer, so establishment no longer needs a separate consumer that
        // would contend with the recv/send drains.
        if let Some(contact_id) = protocol::parse_contact_connected(&resp) {
            demux
                .lock()
                .await
                .connected
                .push_back(ConnectionId(contact_id.to_string()));
            return Ok(());
        }

        // Outbound XFTP upload completion (ws-core CLI shape) → satisfy a
        // concurrent send's await.
        if let Some(file_id) = protocol::parse_snd_file_complete(&resp) {
            demux.lock().await.snd_completed.insert(file_id);
            return Ok(());
        }

        // Outbound XFTP upload completion, **Android / in-process libsimplex
        // shape** (D0026 §12): completion arrives as `chatItemsStatusesUpdated`
        // (chat item file → `sndComplete`), NOT a discrete `sndFileCompleteXFTP`.
        // Route every completed `fileId` into `snd_completed` so a concurrent
        // send's `await_snd_file_complete` is satisfied — otherwise it hangs to
        // its 180 s timeout AND, as the single drainer while parked, blocks the
        // sender's own recv loop for that whole window (the on-device two-device
        // "B→A right after A→B" finding).
        if resp.tag == "chatItemsStatusesUpdated" {
            let completed = protocol::parse_snd_complete_file_ids(&resp);
            if completed.is_empty() {
                // Diagnostic (debug builds): a file-bearing status update that did
                // NOT reach completion — normal for in-progress sends, but logged
                // compactly (fileId + sndProgress) so a future libsimplex shape
                // change that silently breaks the completion match stays visible
                // without the (large) full frame.
                if let Some(items) = resp.body.get("chatItems").and_then(Value::as_array) {
                    for ci in items.iter().filter_map(|it| it.get("chatItem")) {
                        if let Some(fid) = ci
                            .get("file")
                            .and_then(|f| f.get("fileId"))
                            .and_then(Value::as_i64)
                        {
                            let prog = ci
                                .get("meta")
                                .and_then(|m| m.get("itemStatus"))
                                .and_then(|s| s.get("sndProgress"))
                                .and_then(Value::as_str)
                                .unwrap_or("?");
                            log::debug!(
                                "cairn-smp: chatItemsStatusesUpdated fileId={fid} sndProgress={prog} (not complete)"
                            );
                        }
                    }
                }
            } else {
                let mut state = demux.lock().await;
                for file_id in completed {
                    log::info!(
                        "cairn-smp: snd-complete via chatItemsStatusesUpdated fileId={file_id}"
                    );
                    state.snd_completed.insert(file_id);
                }
            }
            return Ok(());
        }

        // Incoming file offer → accept (so the daemon XFTP-downloads it; no
        // demux lock held across the command), then record the owning conn.
        if let Some(offer) = protocol::parse_received_file_offer(&resp) {
            let _ = command(chan, protocol::cmd_receive_file(offer.file_id)).await?;
            let owner = offer
                .contact_id
                .map_or_else(untracked_conn, |id| ConnectionId(id.to_string()));
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
                    .unwrap_or_else(untracked_conn)
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

    /// Upper bound on the `contactConnected` await (`accept_invitation` /
    /// `await_connection`). The SimpleX duplex handshake is several SMP
    /// round-trips over Tor (each a fresh circuit to a `.onion` relay), so this
    /// is generous — but bounded, so a stalled handshake fails loudly (logged)
    /// instead of hanging the caller forever (the prior unbounded loop, D0026
    /// §12 two-party on-device finding). The establishment event itself is
    /// routed into `shared.demux.connected` by the background drainer; the
    /// awaiters only pop it.
    const CONTACT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

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
    use std::sync::Arc;

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

        /// Lazily dial the sidecar WebSocket + learn the active `userId`, then
        /// spawn the dedicated background drainer (the sole `next_event`
        /// consumer, D0026 §12).
        async fn conn(&self) -> Result<&Conn<WsChannel>, SimplexAdapterError> {
            self.conn
                .get_or_try_init(|| async {
                    let url = format!("ws://{}:{}", self.endpoint.host, self.endpoint.port);
                    let (client, events) = connect(&url)
                        .await
                        .map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
                    let chan = Arc::new(WsChannel {
                        client,
                        events: AsyncMutex::new(events),
                    });
                    // Bring-up RPC before spawning the drainer (the drainer only
                    // consumes events, not command replies, so ordering is not
                    // load-bearing — spawned last for clarity).
                    let user_id = flow::query_active_user_id(&chan).await?;
                    let shared = Arc::new(flow::Shared {
                        demux: AsyncMutex::new(flow::RecvDemux::default()),
                        notify: tokio::sync::Notify::new(),
                    });
                    let drainer = flow::spawn_drainer(
                        Arc::clone(&chan),
                        Arc::clone(&shared),
                        self.files_dir.clone(),
                    );
                    Ok(Conn {
                        chan,
                        user_id,
                        shared,
                        drainer,
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
            flow::accept_invitation(conn, &invitation.uri).await
        }

        async fn await_connection(&self) -> Result<ConnectionId, SimplexAdapterError> {
            let conn = self.conn().await?;
            flow::await_connection(conn).await
        }

        async fn send(&self, conn: &ConnectionId, raw: &[u8]) -> Result<(), SimplexAdapterError> {
            let c = self.conn().await?;
            flow::send_envelope(
                c,
                &self.files_dir,
                &self.files_dir.join("sx-files"),
                conn,
                raw,
            )
            .await
        }

        async fn recv(&self, conn: &ConnectionId) -> Result<Vec<u8>, SimplexAdapterError> {
            let c = self.conn().await?;
            // Received files land in the configured `sx-files` folder; the
            // background drainer reads them relative to that base on Android
            // (D0026 §12). `recv` itself no longer needs the base — the drainer
            // owns the file read.
            flow::recv_envelope(c, conn).await
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
    use std::sync::Arc;

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
    /// **At-rest encryption (D0006 §3.5 / D0022 §2.2 / D0026 §12):** when `db_key` is `Some`,
    /// the chat DB is opened with `DbOpts::encrypted` (SQLCipher) so the SMP
    /// agent/chat databases — which hold queue secrets and message metadata —
    /// are AES-encrypted on disk; `None` opens `unencrypted` (the ws-core/dev
    /// default, where the external CLI owns its own DB). The key is supplied by
    /// the storage layer (a demo passphrase for now; the Argon2id-derived
    /// storage KEK in v1). **Migration caveat:** a DB first created
    /// `unencrypted` cannot later be opened `encrypted` (no SQLCipher header);
    /// switching an existing install requires a SimpleX rekey
    /// (`apiStorageEncryption`) or a fresh DB. v1 fresh-installs create the DB
    /// encrypted from the start.
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
        /// Optional SQLCipher passphrase for the at-rest chat DB (D0006 §3.5 / D0022 §2.2).
        /// `Some` → `DbOpts::encrypted`; `None` → `DbOpts::unencrypted`.
        db_key: Option<String>,
        conn: OnceCell<Conn<FfiChannel>>,
    }

    impl FfiSidecarTransport {
        /// Construct the (lazily-initialised) in-process transport with an
        /// app-private DB-path prefix + `CryptoFile`-staging directory, with
        /// outbound traffic on direct (non-Tor) connections and an
        /// **unencrypted** DB (dev default).
        #[must_use]
        pub fn new(db_path: PathBuf, files_dir: PathBuf) -> Self {
            Self::with_options(db_path, files_dir, None, None)
        }

        /// As [`Self::new`], but with the two optional bring-up knobs:
        ///
        /// - `socks_proxy` (`Some(<ip>:<port>)`) routes the daemon's outbound
        ///   SMP/XFTP traffic through that SOCKS5 proxy (the C-Tor service,
        ///   D0020 §2.2) via a `/network socks=` command issued at bring-up;
        ///   `None` = direct connections.
        /// - `db_key` (`Some(passphrase)`) opens the chat DB with
        ///   `DbOpts::encrypted` (SQLCipher at-rest encryption, D0006 §3.5 / D0022 §2.2);
        ///   `None` opens it `unencrypted`.
        ///
        /// `with_options(db_path, files_dir, None, None)` is equivalent to
        /// [`Self::new`].
        #[must_use]
        pub fn with_options(
            db_path: PathBuf,
            files_dir: PathBuf,
            socks_proxy: Option<String>,
            db_key: Option<String>,
        ) -> Self {
            Self {
                db_path,
                files_dir,
                socks_proxy,
                db_key,
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
                    //
                    // At-rest encryption (D0006 §3.5 / D0022 §2.2): `Some(key)` →
                    // `DbOpts::encrypted` (SQLCipher); `None` → `unencrypted`.
                    // NB a DB first created unencrypted cannot later be opened
                    // encrypted (no SQLCipher header) — fresh installs only.
                    let db_opts = match self.db_key.as_deref() {
                        Some(key) => DbOpts::encrypted(&self.db_path, key.to_owned()),
                        None => DbOpts::unencrypted(&self.db_path),
                    };
                    log::debug!(
                        "cairn-smp: FFI conn bring-up — init libsimplex (db at-rest: {})",
                        if self.db_key.is_some() {
                            "encrypted"
                        } else {
                            "unencrypted"
                        }
                    );
                    let (client, events) = init(DefaultUser::regular(PROFILE_NAME), db_opts)
                        .await
                        .map_err(|e| {
                            log::error!("cairn-smp: libsimplex init FAILED: {e:?}");
                            SimplexAdapterError::SidecarUnavailable
                        })?;
                    log::info!("cairn-smp: FFI conn — libsimplex init ok, configuring");
                    let chan = Arc::new(FfiChannel {
                        client,
                        events: AsyncMutex::new(events),
                    });
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
                    // The drainer reads completed downloads relative to the same
                    // configured files folder (D0026 §12); spawned last (it only
                    // consumes events, so it cannot race the bring-up RPCs above).
                    let shared = Arc::new(flow::Shared {
                        demux: AsyncMutex::new(flow::RecvDemux::default()),
                        notify: tokio::sync::Notify::new(),
                    });
                    let drainer =
                        flow::spawn_drainer(Arc::clone(&chan), Arc::clone(&shared), files_folder);
                    Ok(Conn {
                        chan,
                        user_id,
                        shared,
                        drainer,
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
            flow::accept_invitation(conn, &invitation.uri).await
        }

        async fn await_connection(&self) -> Result<ConnectionId, SimplexAdapterError> {
            let conn = self.conn().await?;
            flow::await_connection(conn).await
        }

        async fn send(&self, conn: &ConnectionId, raw: &[u8]) -> Result<(), SimplexAdapterError> {
            let c = self.conn().await?;
            flow::send_envelope(
                c,
                &self.files_dir,
                &self.files_dir.join("sx-files"),
                conn,
                raw,
            )
            .await
        }

        async fn recv(&self, conn: &ConnectionId) -> Result<Vec<u8>, SimplexAdapterError> {
            let c = self.conn().await?;
            // The background drainer reads completed downloads relative to the
            // configured `sx-files` folder (D0026 §12); `recv` only pops the
            // routed bytes, so it no longer needs the base path.
            flow::recv_envelope(c, conn).await
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

    /// Build a [`Conn`] over `chan` whose dedicated background drainer
    /// (the sole `next_event` consumer, D0026 §12) is already spawned, reading
    /// completed downloads relative to `files_base`. Returns the `Conn` plus an
    /// `Arc` to the same channel so a test can still inspect `chan.sent`.
    fn conn_with_drainer<C: RawChannel + 'static>(
        chan: C,
        files_base: std::path::PathBuf,
    ) -> (Conn<C>, std::sync::Arc<C>) {
        let chan = std::sync::Arc::new(chan);
        let shared = std::sync::Arc::new(flow::Shared {
            demux: AsyncMutex::new(RecvDemux::default()),
            notify: Notify::new(),
        });
        let drainer = flow::spawn_drainer(
            std::sync::Arc::clone(&chan),
            std::sync::Arc::clone(&shared),
            files_base,
        );
        let conn = Conn {
            chan: std::sync::Arc::clone(&chan),
            user_id: 0,
            shared,
            drainer,
        };
        (conn, chan)
    }

    #[tokio::test]
    async fn recv_demux_routes_and_buffers_by_connection() {
        // conn-20's file completes FIRST while conn-10 also has an incoming
        // file — the unified background drainer routes EACH completion to its
        // owning connection (by the offer's contactId), so conn-20's bytes are
        // buffered under "20" (not mis-delivered to conn-10) and each recv pops
        // its own connection's envelope.
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
        let (conn, chan) = conn_with_drainer(chan, dir.clone());
        let conn_a = ConnectionId("10".to_string());
        let conn_b = ConnectionId("20".to_string());

        // The drainer routes B→"20" and A→"10"; each recv pops its connection's
        // own buffered envelope (order-independent — both are routed by owner).
        let got_a = flow::recv_envelope(&conn, &conn_a).await.unwrap();
        assert_eq!(got_a, b"envelope-A");
        let got_b = flow::recv_envelope(&conn, &conn_b).await.unwrap();
        assert_eq!(got_b, b"envelope-B");

        // Both offers were accepted (two `/freceive` commands) by the drainer.
        let sent = chan.sent.lock().await;
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
        // the recv-loop both used to consume the ONE event stream. With the OLD
        // code the recv-loop ate + discarded the send's completion event and the
        // send hung (no progress, no timeout — exactly device B's symptom). Now a
        // DEDICATED background drainer is the sole stream consumer and routes each
        // event to the right waiter, so BOTH must finish. The send's completion is
        // fed FIRST — the ordering that broke the old code.
        let dir = std::env::temp_dir().join(format!("cairn-concurrent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let inbound = dir.join("inbound.bin");
        std::fs::write(&inbound, b"hi-from-peer").unwrap();

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (conn, _chan) = conn_with_drainer(
            MpscChannel {
                rx: AsyncMutex::new(rx),
                sent: AsyncMutex::new(Vec::new()),
                send_reply: sent_reply(99),
            },
            dir.clone(),
        );
        let conn_id = ConnectionId("7".to_string());

        tx.send(snd_complete(99)).unwrap(); // the SEND's completion — fed first
        tx.send(offer(1, 7)).unwrap(); // then the recv's incoming file…
        tx.send(complete(1, inbound.to_str().unwrap())).unwrap();

        // A hard timeout turns a regression (the hang) into a clean failure.
        let (recv_res, send_res) =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(
                    flow::recv_envelope(&conn, &conn_id),
                    flow::send_envelope(&conn, &dir, &dir, &conn_id, b"hello-peer"),
                )
            })
            .await
            .expect("deadlock: send + recv did not both complete (the two-consumers bug)");

        assert_eq!(recv_res.unwrap(), b"hi-from-peer"); // recv got its message
        send_res.unwrap(); // send completed — its sndFileCompleteXFTP was routed

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_send_and_recv_loop_complete_on_current_thread() {
        // The exact on-device wedge, reproduced on the host (D0026 §12 "B→A right
        // after A→B"): a single-threaded runtime, a `recv` loop already parked
        // waiting for an incoming message, and a `send` issued whose XFTP-upload
        // completion arrives — and THEN the recv's inbound message arrives, AFTER
        // the send. With the OLD single-drainer-by-contention design these two
        // tasks fought over the one `next_event` stream and neither progressed
        // (the upload completed + the offer landed, but both tasks stalled). With
        // the dedicated background drainer as the SOLE stream consumer, `send` and
        // `recv` only read shared state, so BOTH make progress on one thread.
        //
        // The interleaving is forced by a feeder task that yields control between
        // events: the send-completion is delivered while the recv is parked, and
        // the recv's own message is delivered only afterwards — the precise order
        // that wedged the old code. `current_thread` flavor guarantees no hidden
        // second worker masks a stream-ownership deadlock.
        let dir = std::env::temp_dir().join(format!("cairn-ct-wedge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let inbound = dir.join("inbound.bin");
        std::fs::write(&inbound, b"reply-from-A").unwrap();

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let (conn, _chan) = conn_with_drainer(
            MpscChannel {
                rx: AsyncMutex::new(rx),
                sent: AsyncMutex::new(Vec::new()),
                send_reply: sent_reply(42),
            },
            dir.clone(),
        );
        let conn_id = ConnectionId("3".to_string());

        // Feeder: delays each event so the recv loop is genuinely PARKED first,
        // then the send's completion arrives, then — last — the recv's inbound
        // message. Spawned onto the same current_thread runtime, so it shares the
        // single worker with the drainer, the send, and the recv.
        let inbound_path = inbound.to_str().unwrap().to_string();
        let feeder = tokio::spawn(async move {
            // Let recv + send park on shared state first.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            // (b) the SEND's completion arrives while recv is still waiting.
            tx.send(snd_complete(42)).unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            // (c) the recv's incoming file arrives AFTER the send completed.
            tx.send(offer(1, 3)).unwrap();
            tx.send(complete(1, &inbound_path)).unwrap();
            // Hold tx open until both waiters have surely drained, so the
            // drainer's `next_event` keeps blocking (not error-exiting) during
            // the window under test.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        let (recv_res, send_res) =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(
                    flow::recv_envelope(&conn, &conn_id),
                    flow::send_envelope(&conn, &dir, &dir, &conn_id, b"to-A"),
                )
            })
            .await
            .expect("deadlock: send + recv did not both complete on current_thread (the wedge)");

        // BOTH completed on the single-threaded runtime — the regression check.
        assert_eq!(recv_res.unwrap(), b"reply-from-A");
        send_res.unwrap();
        feeder.await.unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }
}
