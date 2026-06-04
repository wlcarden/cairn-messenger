# D0035 — trust-graph activation: self-rooted attestations on the v1 single-key identity

**Status:** Accepted (Stage 1 design; implementation staged)
**Date:** 2026-06-04

> **Confirmed (2026-06-04):** activate the dormant trust graph against v1's
> **collapsed single-key identity** (operational pubkey == device signing key,
> `cairn-uniffi/src/messaging.rs:470`). Verification **mints a signed, persisted,
> cascade-revocable trust-graph attestation** carrying a D0006 §4 `strength`,
> replacing the local-only `verified` boolean. The signer self-issues a
> capability token (device key signs a token naming itself, `trust-graph:attest`
>
> - revoke scopes); `verify_chain` accepts this with **no verifier change**.
>   Master-rooted attestations and transitive introductions **defer** with the
>   master/recovery hierarchy. The op schema is completed with the `strength` field
>   (**zero ops exist on any device → no migration**). Staged: **Rust core →
>   uniffi mint → Kotlin flows + on-device**.

## Context

The trust graph is the capability that distinguishes Cairn from other E2EE
messengers (design brief §5.2), and D0034 §9 names **trust-graph activation** as
the hard prerequisite for group features: _"membership provenance needs surfaced
attestations, and the trust graph is currently dormant (TOFU pairing creates no
attestations)."_ It is also the resolution of the demo-user confusion that opened
the D0034 discussion — a user who expected "verify" to mean something durable and
legible, not a local toggle.

The machinery is **built and host-tested** (`cairn-trust-graph`: the four op
types, three-hop `verify_chain`, `verify_chain_links`, `compute_quarantine_state`
cascade, `store_signed_op` persistence, the 90-day stale-flag timer, Sigsum emit)
and **partially exported** (uniffi `trust_graph_verify_and_classify`, verify-only).
Yet nothing in the live app produces or surfaces an attestation. Three concrete
roots of that dormancy, found by reading the live path:

1. **No mint path.** uniffi exposes only the read/verify classifier
   (`cairn-uniffi/src/trust_graph.rs`); there is no `trust_graph_attest` /
   `_revoke` export, so the Kotlin shell cannot _create_ an op.
2. **No live identity hierarchy.** v1 collapses operational == device key
   (`messaging.rs:470`); there is no master, no operational/device split, and
   **no capability token** in the live path (messages carry no `issuer_cert_hash`).
   But `verify_chain_links` (`chain.rs:69`) requires a capability token threading
   D0006's three-hop chain — so even the existing verify export has no live token
   and no ops to run against. This is the deepest root.
3. **Schema incompleteness vs D0006 §4.** D0006 §1/§4 mandate a nine-field schema
   whose field 9 is `strength {in-person, channel-verified, asserted}`. The
   implemented `op.rs` (keys 1–8) omits it — yet `strength` is the _exact_ signal
   verification sets, and `Verification.kt`, D0034 §4, and design brief §5.2 all
   reference it.

The Android verify flow (`Verification.kt`) today computes a safety number and
flips a **local `verified` boolean** in `ContactStore` — its own docstring
concedes this is the human stand-in "until the automated trust graph carries
attestations." This decision makes verification mint that attestation.

## Decision summary

| Fork                           | Decision                                                                                                                                                                                                                                                                          |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Identity model**             | **Self-rooted on the v1 single key.** Operational == device key; the key self-issues a capability token (attest + revoke scopes) that satisfies the existing three-hop `verify_chain` unchanged. Master-rooted trust defers with the master/recovery hierarchy (§1)               |
| **What verification produces** | A **signed, persisted, cascade-revocable `Attest` op** carrying a `strength`, in the issuer's per-`(issuer, subject)` chain — replacing the local-only `verified` bool (§2, §5)                                                                                                   |
| **Schema completion**          | Add **`strength`** (D0006 §4 field 9) as canonical-CBOR **key 9**, required for attestation op-types, absent for revocations. Zero ops exist → free additive change. `context` / `expiry` deferred as additive-later fields (§3)                                                  |
| **Strength model**             | **Three levels per D0006 §4.** `in-person` (QR safety-number scan), `channel-verified` (number compared over a separate channel), `asserted` (TOFU, no out-of-band check). Stage 1 mints `in-person` on the QR-verify action; `asserted`-on-pair is a noted follow-on (§3)        |
| **Signing**                    | The device key signs the op via the **external-signer path** (StrongBox), mirroring the message-envelope `EnvelopeSigner` (D0026/D0027). Stage 1 threads `Sign1Builder::signing_input` through `SignedTrustGraphOp` (§4)                                                          |
| **Mint surface**               | A uniffi `TrustGraphHandle` (device signer + operational pubkey + self-token + storage): `attest` / `withdraw_revoke` / `compromise_revoke`, each building + signing + persisting the op and returning bytes (§4)                                                                 |
| **Persistence + surfacing**    | Ops persist via the trust-graph store (reachable from Kotlin); the 3-state badge is driven by `verify_and_classify` over the **real stored chain**, not the local bool (§5)                                                                                                       |
| **Revocation**                 | `WithdrawRevoke` (clean break) + `CompromiseRevoke` (cascade-quarantine) issuable from the contact UI; the cascade classifier already exists (§6)                                                                                                                                 |
| **What defers**                | Master/operational hierarchy + Shamir master recovery (D0005/D0006 §3); transitive **introductions** + `rotation` op (D0006 §4 op-types not implemented); cross-device attestation exchange over the wire; group-membership provenance (D0034); auto-mint-`asserted`-on-pair (§7) |
| **Staging**                    | **Stage 1** Rust core (schema + external-signer + self-token), **Stage 2** uniffi mint + persistence, **Stage 3** Kotlin flows + two-Pixel validation (§8)                                                                                                                        |

## 1. Identity model: self-rooted on the v1 single key

The fork was: an attestation must be signed and verified through _some_ identity
structure, and the live app collapsed that structure to a single key. Two paths
were considered — build D0006's full master → operational → token → device tree
(plus Shamir master recovery) first, or activate against the collapsed v1
identity. **This decision takes the latter.**

It is structurally clean because nothing in `CapabilityToken` or
`SignedTrustGraphOp::verify_chain` requires issuer ≠ subject: a **self-issued
token** (the one key `K` signs a token whose issuer and subject are both `K`, with
`trust-graph:attest` + revoke scopes) passes all three hops — op signed by `K`
(the token's device-subject) ✓, token authorizes `K` for the scope ✓, token signed
by `K` (the expected operational identity) ✓. **No change to the verifier.**

**Why this is not a regression.** The resulting attestations are rooted at the
device key (TOFU), not a master — D0006 §1's third hop ("trace to a known master")
is absent. But that hop is _also_ absent from the live messaging trust model
today (operational == device key, no master anywhere). Activation therefore
_adds_ signed, revocable, surfaced provenance **at the identical trust root the
app already uses** — it regresses nothing, and it does not pretend to the
master-rooted property it lacks (§5 surfacing is honest about strength).

**What it honestly lacks** (deferred, not denied): without a master, key rotation
cannot yet re-anchor the trust graph (D0006 §1's rotation hop), and without
cross-device attestation exchange, trust is not yet _transitive_ (no
introductions). Both are §7 deferrals, gated on the master hierarchy — a separate,
larger unit that this decision deliberately does not open.

## 2. What verification produces

Stage 1 makes the **QR safety-number verify action** mint an `Attest` op:
`issuer = ` the local operational/device key, `subject = ` the contact's
operational pubkey, `strength = in-person`, chained on the issuer's prior op for
that `(issuer, subject)` pair (genesis = empty `prior_hash`). The op is signed
(§4), persisted (§5), and its presence — not a local boolean — is what renders the
contact verified.

Bare TOFU pairing mints **nothing** in Stage 1 (no `asserted`-on-pair): this keeps
activation focused on "verification creates durable trust" and avoids
auto-persisting a low-signal contact-graph edge before the privacy tradeoff
(D0034 §7, compartmentalization) is deliberately weighed. `asserted`-on-pair is a
§7 follow-on.

## 3. Schema completion: add `strength` (key 9)

`TrustGraphOp` gains a `strength` field encoded as canonical-CBOR **key 9** (the
next integer key after the existing 1–8), an enum `{ in-person=1,
channel-verified=2, asserted=3 }` per D0006 §4. It is **required for attestation
op-types** (`Attest`, `ReAttest`) and **absent for revocations**
(`WithdrawRevoke`, `CompromiseRevoke`) — the same present-iff-variant discipline
the existing `revoked_as_of` (key 7) and `prior_revocation_ref` (key 8) already
use. The signature commits to it (it is in `to_canonical_cbor`); the decoder
enforces the variant rule.

**Free additive change.** The graph is dormant — **zero ops exist on any device** —
so there is no migration: the schema is completed before the first op is ever
minted. (The decoder already ignores unknown keys per D0006 §6.4, so even the
read-path is forward-compatible.)

**Scope honesty.** The implemented op (four op-types, keys 1–8) is a v1 _subset_
of D0006 §4's canonical schema: it models revocation as two op-types (rather than
one with `revocation_kind`), adds `ReAttest`, and omits the `introduction` /
`rotation` op-types and the `context` / `expiry` common fields. This decision adds
**only `strength`** — the one field the verification feature requires. `context`
(needed by D0006 §2's stricter-re-attestation rule, itself deferred) and `expiry`
remain **additive-later** fields, not added speculatively (architecture rule:
avoid premature abstraction). Full reconciliation to D0006 §4's five-op-type schema
is part of the deferred master-hierarchy + introductions work (§7).

## 4. Mint + signing surface

**Signing via the external signer.** On Android the device key lives in StrongBox;
there is no in-memory `SigningKey`. `SignedTrustGraphOp::sign` currently takes a
`&SigningKey` (`signed.rs:67`), so Stage 1 adds an **external-signer signing path**
that exposes `Sign1Builder::signing_input()` (the StrongBox-signable bytes,
`cose_sign1.rs:195`) and assembles the op from an externally-produced Ed25519
signature (`cose_sign1.rs:204`) — exactly the primitive the message-envelope
`EnvelopeSigner` already uses (D0026/D0027, task #133). No new crypto.

**The handle (Stage 2).** A uniffi `TrustGraphHandle` holds the device signer
(`Arc<dyn EnvelopeSigner>`-style), the operational pubkey, the self-issued token,
and the storage handle. Its methods — `attest(subject, strength, now)`,
`withdraw_revoke(subject, now)`, `compromise_revoke(subject, revoked_as_of, now)` —
each load the issuer's prior op for the pair from the store (to chain
`prior_hash`), build the op with `issuer_cert_hash = SHA-256(self-token
Sig_structure)` (D0006 §7), sign it externally, persist it, and return the bytes.

**The self-token.** Minted once at bootstrap: the device key signs a
`CapabilityToken` naming itself with `{ trust-graph:attest,
trust-graph:revoke-withdraw, trust-graph:revoke-compromise }`, persisted in the
`IDENTITY` storage category. It is the per-device authorization artifact the
three-hop verifier consumes.

## 5. Persistence + surfacing

Ops persist through the existing trust-graph store (`store_signed_op` /
`load_chain_for_pair`), surfaced to Kotlin so the shell holds no Rust op handles
(D0027 marshalling discipline). The **3-state contact badge** (already built, tasks
#212–215) is re-pointed from the local `verified` boolean to the output of
`trust_graph_verify_and_classify` over the **real stored chain**: verified iff a
non-revoked attestation of strength `in-person` or `channel-verified` exists.

**Honest copy (D0034 §5 req. b).** The badge reflects _strength_, never a bare
"verified." An `asserted`-only contact is not green; a `channel-verified` contact
is distinguishable from an `in-person` one. The UI states what the chain proves
("you verified this key in person on _date_"), not a transitive claim it cannot
yet make.

## 6. Revocation

`WithdrawRevoke` (clean break — soft-flags downstream from the timestamp, no
cascade) and `CompromiseRevoke` (hard-suspends post-`revoked_as_of` attestations,
triggers the cascade quarantine) are issuable from the contact overflow menu. The
classification is already implemented (`compute_quarantine_state`,
`QuarantineStatusFfi`); Stage 3 wires the UI action + the loud surfacing of a
revoked/quarantined contact. This is the first point at which the cascade
primitive does real work in the product.

## 7. What Stage 1 does NOT do

Explicitly deferred, so the floor is legible:

- **The master/operational hierarchy + Shamir master recovery** (D0005, D0006 §3).
  The single largest deferral; everything master-rooted waits on it.
- **Transitive trust / introductions** (the `introduction` op-type) — needs
  cross-device attestation exchange over the wire + a trust-path UI. The trust
  graph's "opt-in introductions" value lands here, later.
- **`rotation` op-type** + key-rotation re-anchoring (D0006 §1 rotation hop).
- **Group-membership provenance** (D0034) — group-local application of this
  primitive, gated on group features.
- **Auto-mint `asserted`-on-pair** — the who-knows-whom edge for every TOFU pair,
  pending the D0034 §7 compartmentalization-vs-connection privacy weigh-in.
- **`context` / `expiry` schema fields + stricter-re-attestation policy
  enforcement** (D0006 §2) — additive-later.

## 8. Staging + validation

Mirrors the staged units before it (D0030, D0033):

- **Stage 1 — Rust core (`cairn-trust-graph`).** Add `strength` (encode/decode +
  variant rule + tests); add the external-signer signing path to
  `SignedTrustGraphOp`; add a self-issued-token constructor helper. Host gates
  (`cargo fmt` + clippy `-D warnings` + `cargo test`). No uniffi, no Kotlin.
- **Stage 2 — uniffi mint + persistence.** `TrustGraphHandle` with the mint/revoke
  exports over the external signer + the trust-graph store; self-token bootstrap +
  persist; confirm the store category is in the uniffi allow-list. Host gates +
  aarch64 APK build.
- **Stage 3 — Kotlin flows + on-device.** QR-verify mints `in-person`; badges from
  the real chain; revocation UI; **two-Pixel validation** (the artifact is the
  oracle); reconcile docs (D0034 §9 dependency, design brief §5.2, status).

Each stage is its own host-gate-clean, propose-commit unit.

## Reversibility

- **The self-rooted identity model** is reversible _upward_: when the master
  hierarchy lands, today's self-issued tokens are replaced by master-certified
  operational tokens, and existing self-rooted attestations are re-anchored or
  re-attested — additive, not a rewrite (the op schema and verifier are unchanged
  by the root swap).
- **The `strength` field** is a permanent schema commitment (it is signed), but
  adding it before any op exists means no migration cost is incurred either way.
- **Verification-mints-only (no `asserted`-on-pair)** is freely reversible — a
  later decision can auto-mint asserted edges without touching Stage 1.

## Cross-references

- [D0006 — cryptographic envelope](D0006-cryptographic-envelope.md) — §1/§4 the
  nine-field schema + `strength` field activated here; §2 the op-types + cascade
  quarantine + stricter-re-attestation; §5 the per-`(issuer, subject)` chain; §7
  `issuer_cert_hash` byte input; §9 the capability-token device-key co-signature
  model.
- [D0034 — group chat scope](D0034-group-chat-scope.md) — §9 names this activation
  as the group-features prerequisite; §4 membership = trust-graph provenance, the
  group-local application of this primitive; §5 req. b the honest
  verified-vs-provenance surfacing.
- [D0005 — recovery peer verification](D0005-peer-verification.md) — the
  Shamir master recovery deferred with the master hierarchy (§7).
- [D0007 — multi-device demoted](D0007-multi-device.md) — the single-device v1
  posture this single-key activation is consistent with.
- [D0026 — cairn-simplex-adapter](D0026-cairn-simplex-adapter.md) /
  [D0027 — cairn-uniffi surface](D0027-cairn-uniffi-crate-surface.md) — the
  external-signer (`EnvelopeSigner`) pattern the op-signing path mirrors.
- [design brief §5.2](../design-brief.md) — the trust-graph capability this
  activates.
