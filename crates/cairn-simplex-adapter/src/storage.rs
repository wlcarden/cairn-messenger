// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! Storage record-id derivation per D0026 §3.2.
//!
//! Two record-id schemes:
//!
//! - **Ratchet state**: one record per conversation.
//!   `record_id = SHA-256(local_operational_pubkey ‖ peer_operational_pubkey)`.
//!   Lives in [`cairn_storage::categories::RATCHET_STATE`].
//! - **Message history**: one record per message.
//!   `record_id = SHA-256(sender_operational_pubkey ‖ recipient_operational_pubkey ‖ envelope_message_number_be)`.
//!   Lives in [`cairn_storage::categories::MESSAGES`].
//!
//! Both ids are 32 bytes; the storage layer's AAD-binding per
//! D0022 §2.4 binds them to their categories so cross-category swap
//! fails AEAD.
//!
//! ## v1 skeleton status
//!
//! The record-id helpers are real + tested. The put/get wrappers
//! that consume them via [`cairn_storage::Storage`] live in
//! [`crate::client`] once the ratchet + SMP bodies land; the
//! skeleton stops at the id-derivation layer so consumers can pin
//! the deterministic-id property before the wire body exists.

use cairn_crypto::ed25519::PUBLIC_KEY_LEN;
use sha2::{Digest, Sha256};

/// Length of the on-disk record id (SHA-256 digest). 32 bytes.
pub const RECORD_ID_LEN: usize = 32;

/// Compute the [`cairn_storage::categories::RATCHET_STATE`] record
/// id for a conversation pair per D0026 §3.2.
///
/// Deterministic: same `(local, peer)` pair always produces the
/// same id.
#[must_use]
pub fn ratchet_record_id_for(
    local_operational_pubkey: &[u8; PUBLIC_KEY_LEN],
    peer_operational_pubkey: &[u8; PUBLIC_KEY_LEN],
) -> [u8; RECORD_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(local_operational_pubkey);
    hasher.update(peer_operational_pubkey);
    let out = hasher.finalize();
    let mut arr = [0u8; RECORD_ID_LEN];
    arr.copy_from_slice(&out);
    arr
}

/// Compute the [`cairn_storage::categories::MESSAGES`] record id for
/// one message per D0026 §3.2.
///
/// `envelope_message_number` is the SimpleX-protocol message number
/// the ratchet assigns; the receiver computes the same id to look
/// up by message-number under the same `(sender, recipient)` pair.
#[must_use]
pub fn message_record_id_for(
    sender_operational_pubkey: &[u8; PUBLIC_KEY_LEN],
    recipient_operational_pubkey: &[u8; PUBLIC_KEY_LEN],
    envelope_message_number: u64,
) -> [u8; RECORD_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(sender_operational_pubkey);
    hasher.update(recipient_operational_pubkey);
    hasher.update(envelope_message_number.to_be_bytes());
    let out = hasher.finalize();
    let mut arr = [0u8; RECORD_ID_LEN];
    arr.copy_from_slice(&out);
    arr
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use cairn_crypto::ed25519::SigningKey;
    use rand_core::OsRng;

    fn random_pubkey(rng: &mut OsRng) -> [u8; PUBLIC_KEY_LEN] {
        SigningKey::generate(rng).verifying_key().to_bytes()
    }

    #[test]
    fn ratchet_record_id_is_deterministic_for_same_pair() {
        let mut rng = OsRng;
        let local = random_pubkey(&mut rng);
        let peer = random_pubkey(&mut rng);
        assert_eq!(
            ratchet_record_id_for(&local, &peer),
            ratchet_record_id_for(&local, &peer)
        );
    }

    #[test]
    fn ratchet_record_id_differs_for_swapped_local_and_peer() {
        // The (local, peer) ordering matters: a message FROM Alice
        // TO Bob has a different ratchet record than a message
        // FROM Bob TO Alice, because each party stores its own
        // ratchet state under its own (self, peer) ordering.
        let mut rng = OsRng;
        let alice = random_pubkey(&mut rng);
        let bob = random_pubkey(&mut rng);
        assert_ne!(
            ratchet_record_id_for(&alice, &bob),
            ratchet_record_id_for(&bob, &alice)
        );
    }

    #[test]
    fn ratchet_record_ids_differ_for_distinct_pairs() {
        let mut rng = OsRng;
        let alice = random_pubkey(&mut rng);
        let bob = random_pubkey(&mut rng);
        let charlie = random_pubkey(&mut rng);
        assert_ne!(
            ratchet_record_id_for(&alice, &bob),
            ratchet_record_id_for(&alice, &charlie)
        );
    }

    #[test]
    fn message_record_id_is_deterministic_for_same_triple() {
        let mut rng = OsRng;
        let sender = random_pubkey(&mut rng);
        let recipient = random_pubkey(&mut rng);
        let n: u64 = 42;
        assert_eq!(
            message_record_id_for(&sender, &recipient, n),
            message_record_id_for(&sender, &recipient, n)
        );
    }

    #[test]
    fn message_record_ids_differ_across_message_numbers() {
        let mut rng = OsRng;
        let sender = random_pubkey(&mut rng);
        let recipient = random_pubkey(&mut rng);
        assert_ne!(
            message_record_id_for(&sender, &recipient, 0),
            message_record_id_for(&sender, &recipient, 1)
        );
    }

    #[test]
    fn message_record_id_differs_for_swapped_sender_and_recipient() {
        // FROM Alice TO Bob is a different record than FROM Bob
        // TO Alice even at the same message number, because the
        // message-history view is per-(sender, recipient) directed
        // pair.
        let mut rng = OsRng;
        let alice = random_pubkey(&mut rng);
        let bob = random_pubkey(&mut rng);
        let n: u64 = 7;
        assert_ne!(
            message_record_id_for(&alice, &bob, n),
            message_record_id_for(&bob, &alice, n)
        );
    }

    #[test]
    fn record_ids_are_32_bytes() {
        let mut rng = OsRng;
        let local = random_pubkey(&mut rng);
        let peer = random_pubkey(&mut rng);
        assert_eq!(ratchet_record_id_for(&local, &peer).len(), RECORD_ID_LEN);
        assert_eq!(message_record_id_for(&local, &peer, 0).len(), RECORD_ID_LEN);
    }
}
