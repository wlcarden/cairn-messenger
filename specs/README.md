# Specifications

Technical specifications as they develop. Distinct from `../docs/design-brief.md`:

- The design brief is the orientation document for external readers — funders, partner NGOs, technical reviewers deciding whether to engage.
- The specs in this directory are working documents for implementers — detailed protocol definitions, message formats, state machines, threat-model derivations at the subsystem level.

Suggested files as the project develops:

- `identity.md` — three-tier identity model, capability token format (COSE), key generation and provisioning ceremony
- `trust-graph.md` — operation types, CRDT semantics, transparency-log integration
- `recovery.md` — Shamir parameters, peer-share format, recovery flow
- `messaging.md` — SimpleX integration boundaries, Briar integration boundaries, channel selection logic
- `updates.md` — Sigstore signing, reproducible-build verification, external-reviewer attestation format
- `storage.md` — on-device schema versioning, migration framework, encrypted-at-rest construction

Each spec should be precise enough for an independent implementer to produce a compatible client.
