// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

//! v1 self-issued capability token for the collapsed single-key identity
//! (D0035 §1 / §4).
//!
//! v1 collapses the operational identity onto the device key
//! (`cairn-uniffi/src/messaging.rs:470` — operational pubkey == device
//! signing key), so there is no separate operational key to certify the
//! device. To mint trust-graph ops through the **unchanged** three-hop
//! verifier ([`crate::SignedTrustGraphOp::verify_chain`]), the single key
//! self-issues a capability token whose issuer (operational identity) and
//! subject (device) are **both** that key. Nothing in `verify_chain`
//! requires issuer ≠ subject, so this verifies cleanly — activation needs
//! no verifier change (proven by `self_issued_token_verifies_collapsed_identity`).
//!
//! When the master/operational hierarchy lands (deferred per D0035 §7),
//! the self-issued token is replaced by a master-certified operational
//! token; the op schema and verifier are unchanged by that root swap.

use cairn_crypto::ed25519::VerifyingKey;
use cairn_identity::{CapabilityToken, capabilities};

/// The capability scopes a v1 self-issued trust-graph token carries: the
/// attest scope plus both revoke kinds, so the single device key can mint
/// every trust-graph op type (D0035 §4).
#[must_use]
pub fn self_issued_scopes() -> Vec<String> {
    vec![
        capabilities::TRUST_GRAPH_ATTEST.to_string(),
        capabilities::TRUST_GRAPH_REVOKE_WITHDRAW.to_string(),
        capabilities::TRUST_GRAPH_REVOKE_COMPROMISE.to_string(),
    ]
}

/// Build the **unsigned** v1 self-issued capability token (D0035 §1 / §4).
///
/// `key` is BOTH the issuer (operational identity) and the subject
/// (device). The caller signs it — in-process via
/// [`cairn_identity::CapabilityToken::sign`] (tests / CLI), or
/// out-of-process against an Android `StrongBox` device key in Stage 2.
/// `expiry_unix` is the token's expiry in Unix-seconds (0 = no explicit
/// expiry, per the capability-token schema).
#[must_use]
pub fn self_issued_token(key: VerifyingKey, expiry_unix: u64) -> CapabilityToken {
    CapabilityToken::new(key, key, self_issued_scopes(), expiry_unix, vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SignedTrustGraphOp, Strength, TrustGraphOp};
    use cairn_crypto::ed25519::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn self_issued_token_verifies_collapsed_identity() {
        // The collapsed v1 identity: ONE key is device + operational.
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        let key_vk = key.verifying_key();
        let peer = SigningKey::generate(&mut rng).verifying_key();

        // Self-issue + sign the capability token with the single key.
        let token = self_issued_token(key_vk, 2_000_000_000);
        let token_bytes = token.sign(&key).unwrap().encode(false).unwrap();

        // Mint an Attest op as that identity, signed by the same key.
        let op = TrustGraphOp::new_attest(
            key_vk,
            peer,
            1_700_000_000,
            vec![],
            vec![],
            Strength::InPerson,
        );
        let signed = SignedTrustGraphOp::sign(op, &key).unwrap();

        // The unchanged three-hop verifier accepts it — D0035 §1.
        let verified = signed.verify_chain(&token_bytes, &key_vk).unwrap();
        assert_eq!(verified.subject, peer);
        assert_eq!(verified.strength, Some(Strength::InPerson));
    }

    #[test]
    fn self_issued_token_authorizes_all_op_types() {
        let mut rng = OsRng;
        let token = self_issued_token(
            SigningKey::generate(&mut rng).verifying_key(),
            2_000_000_000,
        );
        for scope in [
            capabilities::TRUST_GRAPH_ATTEST,
            capabilities::TRUST_GRAPH_REVOKE_WITHDRAW,
            capabilities::TRUST_GRAPH_REVOKE_COMPROMISE,
        ] {
            assert!(token.has_capability(scope));
        }
    }
}
