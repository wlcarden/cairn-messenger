# D0006 — Cryptographic envelope completion: schema additions, cascade semantics, vocabulary precision

**Status:** Accepted
**Date:** 2026-05-27

## Context

The Section 5 adversarial review surfaced three related cryptographic-correctness findings that this decision bundles:

- **F5.** The eight-field signed-operation schema in 5.2 does not cryptographically bind the operational key being used to its specific master attestation. The signature commits to the seven preceding fields but not to a reference of the master certification of the issuer key.
- **F4.** Cascade quarantine soft-flag enables an attestation-laundering attack. A compromised peer can issue attestations that, after revocation, are soft-flagged but remain operationally usable; users re-attest the subjects they trust, converting flagged paths into clean ones. The cascade lacks revocation time semantics and stale-flag escalation.
- **F23.** Cryptographic vocabulary imprecisions: the Shamir input is described as "the private key" rather than the Ed25519 seed; COSE structure choice is not specified; forward-secrecy claims conflate FS with PCS and elide at-rest persistence.

These findings cluster naturally as a single cryptographic-envelope completion pass, with edits cross-cutting Section 5.1, 5.2, 5.3, 3.5, and the operation-signing implementation in the Rust core ([D0003](D0003-implementation-language.md)).

## Decision

Three coordinated specifications.

### 1. Add a ninth field to the signed-operation schema (F5)

The eight-field schema in Section 5.2 becomes a nine-field schema with the addition of `issuer_cert_hash`: a SHA-256 hash of the master attestation certifying the operational key being used to sign. The signature now commits to all nine fields including this hash. A verifier follows the chain:

1. Verify the operation's signature against the issuer's operational public key.
2. Fetch the master attestation referenced by `issuer_cert_hash`; verify its signature against the user's master public key.
3. Confirm that the master attestation's subject matches the operation's issuer.

For key-rotation operations specifically, the rotation includes the master's signature over the new operational key (or its hash) as an additional inline field so the rotation is cryptographically anchored to the master, not merely asserted by the previous operational key.

### 2. Replace single revocation with two operation types and add stale-flag escalation (F4)

The four operation types in Section 5.2 expand to five (or, equivalently, the existing "revocation" splits into two variants distinguished by a `revocation_kind` field):

- **Attestation withdrawal** (`revocation_kind = withdrawal`). Soft-flags downstream attestations from the withdrawal timestamp forward. Attestations issued by the withdrawn-from issuer _before_ the withdrawal timestamp are unaffected. Used when a user is retracting their endorsement of a subject without claiming the issuer key was compromised.
- **Key compromise revocation** (`revocation_kind = compromise`). Hard-suspends all attestations from the revoked operational key, with a `revoked_as_of` timestamp. Attestations _after_ the timestamp hard-fail; attestations _before_ are soft-flagged (the compromise may have begun earlier than the user detected). Used when a user (or their network) has reason to believe the operational key was used outside the user's control.

Additionally:

- **Stricter re-attestation.** Re-attesting a subject whose only path was through a key-compromise-revoked issuer requires either (a) fresh in-person verification with `context` field recording it, or (b) two independent unflagged attestation paths to the same subject. The client UI refuses the simpler one-click re-attestation in this case.
- **Stale-flag escalation.** A soft-flagged attestation that remains flagged for 90 days without the user taking explicit action (re-attest, accept-with-acknowledgment, or quarantine) auto-quarantines. The 90-day clock is per-attestation and resets if the user touches it.

Together these close the laundering attack: post-compromise attestations are hard-failed by the `revoked_as_of` timestamp; the user cannot accidentally launder adversary plants by clicking "re-attest"; and inaction defaults to quarantine rather than acceptance.

### 3. Cryptographic vocabulary precision (F23)

Three specific clarifications applied to the design brief:

- **Shamir input.** Section 5.1 and 5.3 specify: "The 32-byte Ed25519 seed (RFC 8032 §5.1.5) is split using Shamir Secret Sharing over GF(256) byte-wise with threshold 3 of 5; reconstruction yields the seed, from which standard Ed25519 key expansion regenerates the signing key." Splitting the seed (not the derived scalar) preserves Ed25519's deterministic nonce contract.
- **COSE structure.** Section 5.1 and 5.2 specify: capability tokens and trust-graph operations are carried as `COSE_Sign1` structures (RFC 9052) with the protected header carrying the `alg` parameter and the payload carrying the application claim set. Signed content uses deterministic CBOR encoding (RFC 8949 §4.2.1) for signature reproducibility. The reference Rust implementation uses the [`coset`](https://crates.io/crates/coset) crate per [D0003](D0003-implementation-language.md).
- **Forward secrecy scope.** Section 3.5 in-scope and Section 5.4 SimpleX paragraph specify: "Forward secrecy of on-wire message content via the SimpleX double-ratchet derivative; at-rest message history on the device remains decryptable under unlock regardless of ratchet state." The distinction between on-wire FS and at-rest persistence is now explicit; the distinction between FS and post-compromise security is named where Section 5.4 describes SimpleX's double-ratchet derivative.

## Alternatives considered

**Keep single revocation operation type.** Considered for F4. Rejected because the time semantics are essential for the laundering-attack mitigation: without a `revoked_as_of` field, the cascade has no basis to distinguish pre-compromise from post-compromise attestations. Adding the field requires distinguishing the two cases (withdrawal vs. compromise), which is what the two-operation-type split makes explicit. The split makes the user's intent legible in the operation itself rather than inferring it from the field's presence.

**Looser re-attestation behavior.** Considered. Rejected because the user behavior under stress is the attacker's lever; making the re-attestation default strict closes the laundering window at the cost of UX friction during legitimate post-revocation recovery. The friction is acceptable: re-attestation is rare; when it does happen, the user is reconstructing a non-trivial fraction of their trust graph, and a slower process with verification is appropriate.

**Algorithm identifier in a separate field rather than COSE protected header.** Considered. Rejected because the COSE protected header carries `alg` by specification; placing the identifier outside the header would be a custom envelope rather than COSE, which loses the interoperability the COSE choice was made for.

**CBOR not made deterministic.** Considered (relying on canonical signing-over-bytes rather than canonicalizing the encoding). Rejected because deterministic CBOR is the standard practice for signed CBOR content and avoids implementation drift between two clients that produce CBOR slightly differently and so produce non-verifying signatures of the same logical content.

## Consequences

### Section 5.1 (Identity Model) updates

- The "Master identity" paragraph specifies the Shamir input as the 32-byte Ed25519 seed over GF(256), threshold 3-of-5.
- The "Operational identity" paragraph clarifies that rotation operations include the master's signature over the new operational key as an inline field (not just a reference).
- The "Device capability tokens" paragraph specifies `COSE_Sign1` envelope and deterministic CBOR encoding.

### Section 5.2 (Trust Graph) updates

- The "Four operation types" paragraph becomes "five operation types" or retains four with the `revocation_kind` field — the brief uses the five-type framing for clarity.
- The "Signed-operation schema" paragraph adds the `issuer_cert_hash` field and the `revocation_kind` / `revoked_as_of` fields where applicable. The eight-field schema is now nine-field (or ten depending on the operation type).
- The "Cascade quarantine on revocation" paragraph specifies the distinct semantics for withdrawal vs. compromise revocation, the stricter re-attestation requirements, and the 90-day stale-flag escalation.
- The "Signed-operation schema" paragraph also specifies `COSE_Sign1` envelope and deterministic CBOR encoding.

### Section 3.5 updates

- The in-scope forward-secrecy framing is tightened to "Forward secrecy of on-wire message content via the SimpleX double-ratchet derivative; at-rest message history on the device remains decryptable under unlock regardless of ratchet state."

### Section 5.3 updates

- The recovery flow specifies that the master is reconstructed from the Shamir-split _seed_, not from a "private key" (terminology); the 32-byte seed is reconstructed and the Ed25519 key expansion is reapplied locally.

### Implementation implications

- The Rust core's signed-operation types include the new fields by construction (typestate pattern per [D0003](D0003-implementation-language.md) enforces presence).
- Stale-flag escalation requires a background task that checks for 90-day-old flagged attestations and auto-quarantines them. The task runs on app open; no continuous background processing required.
- The verification path is two-hop in the common case (operation → master attestation → user master key); the master attestations are themselves logged in Sigsum and fetched as needed.

### Reversibility

- The schema additions are not reversible without breaking deployed signatures; they must be specified correctly from day one of implementation. The forward-compatibility property in 6.4 (operation types unknown to a client are retained but ignored) covers later schema additions; this decision is the v1 baseline.
- The cascade semantics can be revised in v1.x if the chosen behavior produces user-visible problems; the 90-day escalation period in particular is tunable.
- The vocabulary precision edits are pure documentation changes; they neither add nor remove implementation behavior.

## References

- [docs/section-5-review.md](../section-5-review.md) F4, F5, F23
- [docs/decisions/D0003-implementation-language.md](D0003-implementation-language.md) — Rust core; `coset` crate; typestate enforcement.
- RFC 9052 (COSE), RFC 9053 (algorithms), RFC 8949 (CBOR), RFC 8032 (Ed25519).
- Shamir's Secret Sharing: original construction (Shamir, 1979); GF(256) practical implementations widely audited (Trezor's `slips`, OpenBao's secret-sharing code, the `vsss-rs` crate).
