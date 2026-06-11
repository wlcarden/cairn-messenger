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

### 4. Canonical nine-field schema designation (per consolidated external-reads triage C1 / H1)

The earlier brief versions documented the nine-field schema in two places with three differing fields between the diagrams enumeration (`docs/architecture-diagrams.md:275` — operation type, issuer, subject, prior hash, issuer-cert-hash, scope, timestamp, payload, signature) and the brief enumeration (`docs/design-brief.md:457-465` — Issuer, Issuer-cert-hash, Subject, Context, Strength, Timestamp, Expiry, Prior-hash, Signature). This decision designates **D0006 as the canonical schema spec**; the architecture-diagrams.md enumeration and the design-brief.md enumeration both reference this section by verbatim, and any conflict is resolved by reading D0006 as authoritative.

**Canonical Signed_Operation schema (v1):**

```
Signed_Operation := COSE_Sign1 {
    protected_header: { alg: EdDSA },
    unprotected_header: {},
    payload: deterministic_cbor_encoded({
        // Common fields (all operation types):
        operation_type: enum { attestation, withdrawal, revocation, introduction, rotation },
        issuer: bstr (Ed25519 operational public key),
        issuer_cert_hash: bstr (SHA-256 hash; see §7 below for byte input),
        subject: bstr (Ed25519 public key being attested/revoked/introduced),
        prior_hash: bstr (SHA-256 hash; see §5 below for byte input and chain scope),
        context: text (free-form contextual string, application-specific),
        strength: enum { in-person, channel-verified, asserted } (attestation only; null for other types),
        timestamp: uint (seconds since Unix epoch),
        expiry: uint (seconds since Unix epoch; 0 = no explicit expiry),
        // Operation-type-conditional fields:
        revocation_kind: enum { withdrawal, compromise } (revocation only),
        revoked_as_of: uint (compromise revocation only; seconds since Unix epoch),
    }),
    signature: bstr (Ed25519 signature over Sig_structure; see §6 below)
}
```

The common-fields count is 9 (including operation_type); operation-type-conditional fields add 0–2 fields depending on operation_type. The brief's "nine-field" framing refers to the common fields. **The canonical encoding is specified in this section; if architecture-diagrams.md or design-brief.md disagrees, the editing pass per the consolidated triage updates them to match this section.**

### 5. `prior_hash` hash function and byte input specification (per consolidated external-reads triage C2 / H2)

The earlier brief versions did not specify the hash function for `prior_hash` or the byte input it covers, and the chain scope was documented inconsistently across diagrams (per-issuer) and brief (per-(issuer, subject)). This decision:

- **Hash function: SHA-256.** Consistent with `issuer_cert_hash` (also SHA-256) and with COSE's RFC 9053 standard hash. Specified for forward consistency.
- **Byte input:** `prior_hash := SHA-256( COSE_Sign1.signature_bytes( prior_operation ) )`. The hash covers the prior operation's signature bytes (the 64-byte Ed25519 signature), not the prior operation's payload or full COSE envelope. Rationale: the signature bytes are the unambiguous canonical commitment to the prior operation's content (the signature covers the Sig_structure, which covers payload + protected header + external_aad); hashing the signature itself avoids re-canonicalization and produces a fixed-size input regardless of payload complexity.
- **Chain scope: per-(issuer, subject).** The chain links operations by the same issuer against the same subject, not all operations by the issuer globally. Cross-subject equivocation detection depends on observers comparing operations they receive against the Sigsum commitment log, not on a single global chain. **The architecture-diagrams.md diagram 4 statement that the chain is "an append-only sequence per issuer" is incorrect and is updated by the consolidated-triage edit pass to match this section.**

A test vector for `prior_hash`:

```
prior_operation = (example_signed_operation_1)
prior_operation.signature = 64-byte Ed25519 signature
SHA-256( prior_operation.signature ) = 32-byte hash
```

Test vector to be added to the v1 implementation's test suite as part of the audit-target verification.

### 6. COSE_Sign1 `Sig_structure` construction (per consolidated external-reads triage C3 / H3)

Earlier brief versions specified deterministic CBOR encoding for the payload but did not address what bytes the Ed25519 signature actually covers. RFC 9052 §4.4 defines `Sig_structure` as the synthetic CBOR array the signature is computed over. This decision specifies:

**Sig_structure form:**

```
Sig_structure = [
    context: "Signature1",       // string literal per RFC 9052 §4.4
    body_protected: bstr,         // deterministic CBOR-encoded protected header
    external_aad: bstr,           // domain-separation tag (see §8 below)
    payload: bstr                 // deterministic CBOR-encoded payload (per §4 above)
]
Signed_bytes = deterministic_cbor_encode( Sig_structure )
signature = Ed25519_sign( issuer_operational_private_key, Signed_bytes )
```

**Determinism requirements:**

- The protected header is encoded with deterministic CBOR (RFC 8949 §4.2.1), not just the payload. Earlier brief versions specified deterministic encoding only for the payload.
- The payload bstr in Sig_structure contains the deterministic-CBOR-encoded canonical schema (per §4 above).
- The external_aad bstr is non-empty and carries the domain-separation tag (per §8 below).

**COSE-tagged vs untagged:** The reference implementation uses `coset::CoseSign1::to_vec()` to produce the canonical signed bytes (untagged COSE_Sign1). Tagged COSE_Sign1 (with CBOR tag 18) is not used; verifiers parse untagged structure. This is consistent across capability tokens and trust-graph operations.

**Test vector:** A reference (key, payload, expected Sig_structure bytes, expected signature) triple is added to the v1 implementation test suite to make the canonicalization decisions verifiable by future implementers without re-deriving them.

### 7. `issuer_cert_hash` byte input definition (per consolidated external-reads triage C4 / H4)

Earlier brief versions specified `issuer_cert_hash` as "a SHA-256 hash of the master attestation" without defining what bytes constituted "the master attestation." This decision specifies:

```
issuer_cert_hash := SHA-256( deterministic_cbor_encode( master_attestation.Sig_structure ) )
```

Rationale: hashing the master attestation's `Sig_structure` (the bytes the master's signature covers) is the canonical commitment to the master attestation's content. This is what most attesters intuitively expect ("the bytes that were signed") and what verifiers can independently reconstruct from the master attestation envelope without ambiguity. Alternatives considered (hash of outer-COSE bytes; hash of payload-bytes-only; hash of master signature bytes only) each produce different hashes for the same logical master attestation; the specification of `Sig_structure` over alternatives is documented for any future implementer.

**Test vector:** A reference (master_attestation, expected issuer_cert_hash bytes) pair is added to the v1 implementation test suite.

### 8. `external_aad` domain separation between capability tokens and trust-graph operations (per consolidated external-reads triage C7 / M1)

Earlier brief versions had capability tokens and trust-graph operations both using COSE_Sign1 with the same `alg` (Ed25519) and deterministic-CBOR payload, with no domain separation. Without separation, an adversary who obtains a signature produced for one domain might be able to reinterpret the signed bytes as belonging to the other domain. This decision uses the COSE_Sign1 `external_aad` field as a domain tag:

- For capability tokens: `external_aad := "cairn-v1-capability-token"` (UTF-8 byte string).
- For trust-graph operations: `external_aad := "cairn-v1-trust-graph-operation"` (UTF-8 byte string).

The Sig_structure binds to external_aad (per §6 above); a signature produced for one domain cannot verify in the other even with payload-bit overlap. This is the standard COSE pattern for cross-protocol signature separation.

**Version evolution.** Future versions extend the tag with version-suffix (`cairn-v2-capability-token`, etc.) when the envelope schema changes. v1 clients verify only against the v1 tags; v2+ clients accept multiple version-suffixed tags as protocol-versioning support per §6.4.

### 9. Capability-token authority model: device-key co-signature (per consolidated external-reads triage C6 / H6)

Earlier brief versions documented capability tokens as scope-bounding ("a device with a `messaging-send` token cannot issue trust graph attestations even if its key material is fully extracted by forensic tooling" — `docs/design-brief.md:422`) but did not specify whether enforcement was cryptographic or software-permission-only. This decision adopts **Register 1: cryptographic enforcement via device-key co-signature.** The H6 finding identified that without device-key co-signature, the scope-bounding claim is false: a forensic extractor who pulls the operational identity's hardware-gated signing oracle credential can sign anything, regardless of any device's token.

**Device-key construction (v1 commitment):**

- Each device generates a device key in the device's hardware element (StrongBox where Ed25519 is supported on the target Pixel generation; TEE-backed otherwise; consistent with operational identity's hardware substrate).
- The operational identity signs a **capability token** naming the device key as subject; the token is COSE_Sign1 with payload containing { issuer: operational_identity_pubkey, subject: device_pubkey, scope: enumerated capability strings, expiry, signature_chain_to_master }.
- Operations the device issues (messaging sends, trust-graph operations within scope) are **signed by the device key**, not directly by the operational identity. The operation envelope additionally references or inlines the capability token so verifiers can chain: device-key-signature → capability-token (signed by operational identity) → operational-identity-signature → master-attestation.
- Verifier's verification path becomes three-hop: (a) verify operation's signature against device key (the operation's signer is the device); (b) verify the capability token names the device key as subject and is signed by the operational identity; (c) verify the capability token's scope encompasses the operation type the device is issuing; (d) verify the operational identity's master attestation chain as before.

**Engineering implications:**

- v1 client manages a device-keypair per operational identity (generated at provisioning; not exportable from the hardware element).
- Capability-token construction at provisioning includes the operational-identity signature over the device-key-as-subject token; this is part of the v1 cryptographic engineering scope.
- Operation signing flows route through device-key signing rather than directly through operational-identity signing. Operational identity signs capability tokens (long-lived); device key signs operations (short-lived, per-op).
- The device-key operation signature (hop (a)) is produced via the COSE_Sign1 external-signer path (D0018 §2.2): the `Sig_structure` is built in-process, signed by the hardware-resident device key (StrongBox; the key never leaves the element), and the `COSE_Sign1` is assembled in-process from the returned 64-byte signature. This realizes "the operation's signer is the device" without the device key entering application memory — the same in-process-build / hardware-sign / in-process-assemble shape the operational-identity capability-token + Sigsum-leaf signers use. The messaging adapter's `EnvelopeSigner` (D0026 §2.3) is the first consumer; software-key signing (the `cairn-cli` demo + tests) is the same path with an in-process key.
- Token expiry / renewal flow exercises the operational identity's signing oracle periodically; renewal requires unlock (per Section 5.1's compelled-unlock framing).
- Device-key revocation flow: revoking a device's capability token (via the trust-graph revocation operations from §2 above) makes the device's signatures unverifiable against the revoked token; the device cannot continue to issue operations under that token after the revocation propagates.

This makes `docs/design-brief.md:422`'s scope-bounding claim true: a forensic extractor who pulls a device's key material can sign operations only within that device's capability-token scope (cryptographically enforced), not arbitrary operational-identity operations.

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

- [docs/section-5-review.md](../archive/section-5-review.md) F4, F5, F23
- [docs/decisions/D0003-implementation-language.md](D0003-implementation-language.md) — Rust core; `coset` crate; typestate enforcement.
- RFC 9052 (COSE), RFC 9053 (algorithms), RFC 8949 (CBOR), RFC 8032 (Ed25519).
- Shamir's Secret Sharing: original construction (Shamir, 1979); GF(256) practical implementations widely audited (Trezor's `slips`, OpenBao's secret-sharing code, the `vsss-rs` crate).
