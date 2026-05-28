# D0007 — Multi-device commitment demoted: v1 and v2 single-device-per-identity de facto

**Status:** Accepted
**Date:** 2026-05-27

## Context

Section 6.4 (Forward-compatibility design choices in v1) of the design brief listed "Multi-device awareness in the protocol layer even though v1 ships only phones" as a forward-compatibility commitment. Section 5.1 (Identity Model) implicitly supports multi-device through capability tokens (each device key is a separate subject for the operational identity's delegation). Section 5.2 (Trust Graph) does not specify multi-device semantics — how multiple device keys for the same operational identity are advertised in the trust graph, how peers reason about same-identity-multi-device, or how cascade quarantine handles multi-device.

The Section 5 adversarial review (finding F11) flagged the inconsistency: the 6.4 claim implies multi-device is a v1 design commitment that v2 will extend without breaking, but Section 5 does not specify the data model that would make the commitment honest. The reviewer estimated that specifying it properly in v1 is multi-month engineering, and the v1 timeline post-D0004 scope cuts does not have room for it.

## Decision

**Demote the 6.4 multi-device commitment.** v1 and v2 are single-device-per-identity de facto. v2 (USB form factor) and v3 (mesh radio integration) may extend the protocol to introduce multi-device data structures, with the understanding that v2/v3 protocol additions are forward-compatible (older clients gracefully ignore unknown operations per the existing 6.4 protocol-versioning property) but may require user-facing migration on a per-user basis.

Specifically:

- **v1 identity model.** Each Cairn user has one operational identity associated with one device. The capability-token data structure in Section 5.1 supports multiple device keys per operational identity at the schema level (any operational identity can sign tokens for any number of device keys), but v1 does not surface this — the v1 client manages one device key per operational identity.
- **v2 USB form factor.** When v2 adds a USB-bootable variant, the user's operational identity may sign capability tokens for both the phone's device key and the USB's device key. The trust graph treats both device keys as keys-of-the-same-operational-identity; how peers verify operations issued by either device is specified at that point. v2 may require introducing a new operation type (e.g., `device_attestation`) that links multiple device keys to the same operational identity in the trust graph; v1 clients gracefully ignore the new operation type per 6.4 protocol-versioning, and they continue to treat each device key independently in their local computations.
- **v3 mesh radio integration.** Mesh nodes are devices, not users. Their device keys are signed by the user's operational identity (the user authorizes a mesh node to send messages on their behalf). The data model is the same as v2's; the differences are in transport (LoRa rather than IP) and capability scope (`mesh-relay` rather than `messaging-send`).
- **v1.5 and beyond cannot assume a multi-device user model.** Features that would have depended on it must be designed against single-device-per-identity until v2 actually delivers the extended model.

## Alternatives considered

**Build minimal multi-device awareness in v1.** Considered. Specify the data model in Section 5 — at minimum, how multiple device keys are advertised in the trust graph; how peers handle multi-device subjects — without shipping multi-device features. Rejected because the specification work is non-trivial (the cascade quarantine semantics, the multi-device introduction operation, the peer-side verification logic all need to be designed concretely) and the v1 timeline does not have room for design work that ships no user-visible value. The demoted approach acknowledges the v2 work explicitly rather than half-building it in v1.

**Drop multi-device from the roadmap entirely.** Considered. v1 and v2 are explicitly single-device-per-identity; users with multiple devices have multiple identities. Rejected because (a) v2 (USB form factor) is meaningful only if the USB and the phone can act as the same identity — separate identities defeat the point of carrying a portable cryptographic key on a USB stick; (b) v3 (mesh radio integration) requires the mesh node and the phone to share an identity for the user to control the mesh node from their phone; (c) the property of multi-device-per-identity is widely desired in the target audience (journalists with primary and travel devices, organizers with personal and movement-specific devices) and dropping it would be a meaningful product limitation. Demoting is more honest than dropping; the architectural slot remains.

## Consequences

### Section 6.4 update

The "Multi-device awareness in the protocol layer even though v1 ships only phones" bullet is rewritten to:

"Multi-device pairing flow specified for v2 but not built in v1; v2 may require protocol extension that v1 clients accept as forward-compatible. v1 capability tokens support multiple device keys per operational identity at the schema level; v1 client behavior is single-device-per-identity."

### Section 5.1 acknowledgment

A short clarifying sentence acknowledges that the capability-token model schematically supports multiple device keys but v1 surfaces a single-device experience; multi-device support is v2 work.

### Section 7.1 v2 entry

The v2 entry expands to acknowledge that the USB form factor specifically requires the multi-device extension to be designed and built as part of v2 (not v1, not v1.5).

### Implementation implications

- v1 client code does not need to handle multi-device cases. Simpler implementation; one fewer dimension to test.
- The capability-token format still supports multi-device at the schema level — capability tokens are formatted as `COSE_Sign1` structures with the device key as the subject, and any operational identity can sign multiple such tokens. v2 builds on this without changing the format.
- The trust graph operations (per [D0006](D0006-cryptographic-envelope.md)) are designed against single-device-per-identity in v1; v2 adds the `device_attestation` operation type (or equivalent) without changing the existing five operation types.

### Reversibility

The decision is to acknowledge multi-device as v2 work; it does not foreclose any v1.x or v1.5 reintroduction of multi-device if pilot evidence justifies it. The acknowledgment is intended to manage expectations and prevent half-building the feature in v1; it is not a commitment that multi-device cannot return earlier.

## References

- [docs/section-5-review.md](../section-5-review.md) F11
- [docs/decisions/D0003-implementation-language.md](D0003-implementation-language.md) — Rust core forward-compatibility implications (the core can target USB and mesh hardware).
- [docs/decisions/D0004-v1-scope-cuts.md](D0004-v1-scope-cuts.md) — the v1 scope cuts that constrain what can be specified.
- [docs/decisions/D0006-cryptographic-envelope.md](D0006-cryptographic-envelope.md) — the five-operation trust-graph schema this decision is consistent with.
