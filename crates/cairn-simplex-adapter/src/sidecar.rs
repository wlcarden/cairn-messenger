// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! The internal sidecar-transport seam (D0020 §1.10 / D0026 §1.2).
//!
//! [`SidecarTransport`] abstracts the raw byte transport BELOW Cairn's
//! message envelope: invitation pairing + opaque-byte `send`/`recv` over
//! an established connection. Inverting the dependency this way lets
//! [`crate::adapter::SimplexAdapter`] implement its security-critical
//! envelope flow (build → sign → pad / verify → unpad → chain) generically
//! over the seam, testable with an in-memory mock and with the real
//! SimplOxide-backed transport injected in production.
//!
//! ## Why a seam (and not a direct `simploxide-client` dependency)
//!
//! D0026 §1.1 specifies the production transport as `simploxide-client`
//! (with the `ws` feature) over loopback WebSocket to the SimpleX Chat CLI
//! sidecar. That crate is not yet available to this build, and — per
//! D0026 §1.2/§1.3 — the adapter's value-add is the envelope, not the SMP
//! wire. The seam keeps the envelope logic decoupled from SimpleX (D0020
//! §1.10), admits the v1.5 Briar tier, and admits this mock for hermetic
//! tests "without the CLI sidecar" (D0026 §1.2). The concrete
//! [`SimploxideTransport`] stays a documented stub until the crate lands
//! (D0026 §12).
//!
//! ## Message numbers
//!
//! Per D0026 §3.2 the per-`(sender, recipient)` message number is assigned
//! by the SMP ratchet, not by the Cairn envelope. The seam therefore
//! carries it: [`SidecarTransport::send`] returns the assigned number and
//! [`SidecarTransport::recv`] returns `(number, bytes)`. Cairn's own chain
//! integrity rides on the envelope `prior_envelope_hash` (D0026 §2.1 key
//! 5), independent of the transport's numbering.

use std::future::Future;

#[cfg(test)]
use std::collections::{HashMap, VecDeque};
#[cfg(test)]
use std::sync::{Arc, Mutex};

use crate::adapter::{ConnectionId, Invitation, SidecarEndpoint};
use crate::error::SimplexAdapterError;

/// The raw byte transport below the Cairn envelope (D0020 §1.10).
///
/// Implementations own the SMP wire, the PQ double-ratchet, the queue
/// lifecycle, and the out-of-band invitation flow (D0026 §1.3); Cairn
/// rides its signed + padded envelope over the opaque `send`/`recv`.
///
/// Methods return `impl Future + Send` (RPITIT) rather than `async fn`,
/// and the supertrait `Sync` bound makes `&SimplexAdapter<T>` `Send`, so
/// the generic [`crate::adapter::SimplexAdapter`]'s public async surface
/// is `Send` (spawnable on a multi-threaded executor).
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

    /// Send `raw` envelope bytes over `conn`; returns the ratchet-assigned
    /// message number (D0026 §3.2).
    fn send(
        &self,
        conn: &ConnectionId,
        raw: &[u8],
    ) -> impl Future<Output = Result<u64, SimplexAdapterError>> + Send;

    /// Receive the next `(message_number, raw_bytes)` on `conn`.
    fn recv(
        &self,
        conn: &ConnectionId,
    ) -> impl Future<Output = Result<(u64, Vec<u8>), SimplexAdapterError>> + Send;
}

// ===================================================================
// In-memory mock transport (D0026 §1.2)
// ===================================================================
//
// `#[cfg(test)]`-gated for this cycle (the round-trip tests live in
// `adapter.rs`). Exposing it publicly for `cairn-cli` integration tests
// "without the CLI sidecar" (D0026 §1.2) is a follow-up when that crate
// grows those tests.

#[cfg(test)]
#[derive(Default)]
struct MockWire {
    /// Per-connection FIFO of `(message_number, bytes)`.
    queues: HashMap<ConnectionId, VecDeque<(u64, Vec<u8>)>>,
    /// Per-connection next send number (the ratchet's role).
    send_counters: HashMap<ConnectionId, u64>,
    /// Next mock connection id.
    next_conn: u64,
}

/// An in-memory [`SidecarTransport`] for hermetic tests. Cloning shares
/// the same wire (an `Arc`), so two adapters constructed over clones can
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
        let id = {
            let mut wire = self
                .wire
                .lock()
                .map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
            let id = ConnectionId(format!("mock-conn-{}", wire.next_conn));
            wire.next_conn = wire.next_conn.saturating_add(1);
            id
        };
        Ok(id)
    }

    async fn send(&self, conn: &ConnectionId, raw: &[u8]) -> Result<u64, SimplexAdapterError> {
        let mut wire = self
            .wire
            .lock()
            .map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
        let number = *wire.send_counters.get(conn).unwrap_or(&0);
        wire.send_counters
            .insert(conn.clone(), number.saturating_add(1));
        wire.queues
            .entry(conn.clone())
            .or_default()
            .push_back((number, raw.to_vec()));
        drop(wire);
        Ok(number)
    }

    async fn recv(&self, conn: &ConnectionId) -> Result<(u64, Vec<u8>), SimplexAdapterError> {
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
// SimplOxide-backed transport (deferred concrete impl)
// ===================================================================

/// The production [`SidecarTransport`] — a `simploxide-client` WebSocket
/// to the SimpleX Chat CLI sidecar (D0026 §1.1).
///
/// **Deferred**: `simploxide-client` is not yet available to this build,
/// so every method returns [`SimplexAdapterError::NetworkUnreached`]. The
/// envelope flow in [`crate::adapter`] is fully implemented + tested over
/// the `MockSidecarTransport`; only this concrete transport's body waits
/// on the crate (D0026 §12). The type exists so production code can name
/// `SimplexAdapter<SimploxideTransport>` stably.
#[derive(Debug, Clone)]
pub struct SimploxideTransport {
    #[allow(
        dead_code,
        reason = "held for the SimplOxide WebSocket dial once simploxide-client lands (D0026 §12)"
    )]
    endpoint: SidecarEndpoint,
}

impl SimploxideTransport {
    /// Construct the (deferred) production transport for a sidecar endpoint.
    #[must_use]
    pub const fn new(endpoint: SidecarEndpoint) -> Self {
        Self { endpoint }
    }
}

impl SidecarTransport for SimploxideTransport {
    async fn create_invitation(&self) -> Result<Invitation, SimplexAdapterError> {
        Err(SimplexAdapterError::NetworkUnreached)
    }
    async fn accept_invitation(
        &self,
        _invitation: Invitation,
    ) -> Result<ConnectionId, SimplexAdapterError> {
        Err(SimplexAdapterError::NetworkUnreached)
    }
    async fn send(&self, _conn: &ConnectionId, _raw: &[u8]) -> Result<u64, SimplexAdapterError> {
        Err(SimplexAdapterError::NetworkUnreached)
    }
    async fn recv(&self, _conn: &ConnectionId) -> Result<(u64, Vec<u8>), SimplexAdapterError> {
        Err(SimplexAdapterError::NetworkUnreached)
    }
}
