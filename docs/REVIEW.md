# Reviewing Cairn's cryptography

> **Cairn is a pre-audit alpha.** This document scopes a security review: what to
> look at first, where it lives in the tree, and what is in or out of scope. It
> exists so a reviewer or an audit funder can size the work without
> reverse-engineering the codebase. To report a specific finding, see
> [`SECURITY.md`](../SECURITY.md).

## For reviewers, in one screen

Cairn is an end-to-end encrypted messenger for people facing well-resourced
adversaries: mercenary spyware, forensic device extraction, state-level
interception. It targets GrapheneOS-on-Pixel. The rationale and the full threat
model are in [`design-brief.md`](design-brief.md) §3.

The cryptographic primitives are off-the-shelf, and re-verifying them is not the
ask: Ed25519 and X25519 (RustCrypto / `ed25519-dalek` with `verify_strict`),
SHA-256 and BLAKE3, Shamir over GF(256) (`vsss-rs`), COSE_Sign1 over canonical
CBOR, Argon2id, and an AEAD for at-rest storage. On-wire message encryption is
SimpleX's post-quantum double ratchet (via SimplOxide), not a Cairn
implementation.

The original work, and what we want reviewed, is the integration that composes
those primitives. The five targets below are where the design risk concentrates.

## What we're asking you to review

**1. The COSE_Sign1 envelope and its domain separation.** Every signed object
(messages, capability tokens, master attestations, trust-graph operations) is a
COSE_Sign1 over canonical CBOR carrying a per-type `external_aad` domain tag
(`cairn-v1-message-envelope`, `cairn-v1-master-attestation`, and so on). The
property under test: an object signed for one context cannot verify in another.
Code: `cairn-envelope`, `cairn-simplex-adapter`. Spec: D0006 §8. Status:
IMPLEMENTED, with test vectors cross-validated against `veraison/go-cose`.

**2. The three-tier identity chain.** A cold master key signs an operational
key, which issues device-scoped capability tokens. A verifier checks three hops
(device → capability token → master attestation). The property under test: a
routine device compromise stays bounded to a revocable, time-scoped token and
never reaches the master. Code: `cairn-identity`,
`cairn-trust-graph::verify_chain`, `cairn-recovery`. Spec: D0006 §9. Status:
IMPLEMENTED in the core; the StrongBox operational-key binding and the Rust-side
attestation-chain verification are PARTIAL.

**3. The trust-graph operation envelope and cascade-quarantine.** Signed
operations chain per (issuer, subject) through
`prior_hash := SHA-256(prior op signature)` and bind to the issuer via
`issuer_cert_hash`. The code implements four operation types (`Attest`,
`WithdrawRevoke`, `CompromiseRevoke`, `ReAttest`); a `CompromiseRevoke`
hard-suspends post-revocation attestations and soft-flags earlier ones. The
property under test: the withdrawal-versus-compromise split closes
attestation-laundering, and the chain gives per-pair anti-equivocation
detectable from the commitments alone. Code: `cairn-trust-graph`. Spec: D0006
§2, §5, §7; introductions are separate, in D0037. Status: IMPLEMENTED (cascade
carries 11 unit tests plus cascade proptests).

**4. Social recovery.** The 32-byte master seed is Shamir-split 3-of-5 among the
user's own peers, each share carrying a BLAKE3 commitment; reconstruction runs
in `Zeroizing` scope and never crosses the FFI into Kotlin. A peer releases a
share only after an Argon2id challenge-phrase check and a 48-hour peer-clock
cooling-off. The property under test: behaviour against k colluding or coerced
peers, against share replay, and the memory hygiene of the reconstruction path.
Code: `cairn-shamir`, `cairn-recovery`. Spec: D0005, D0040, D0018 §3. Status:
IMPLEMENTED (the full 3-distinct-peer threshold is unproven for want of three
test devices; see implementation-status).

**5. Release verification.** An offline verifier composes the Fulcio
certificate chain, the OIDC/SAN-URI signer identity, the embedded SCT, a
detached P-256 manifest signature, Rekor inclusion, and a Sigsum-anchored
release log. The property under test: the soundness of that chain, and what an
attacker who controls the build pipeline still gets past it. Code:
`cairn-sigstore-verify`, `cairn-sigsum-client`. Spec: D0024, D0023, D0015.
Status: the verifier is real and runs offline against real Sigstore staging and
production anchors; the producer side is unrun, and the Sigsum half currently
runs against self-minted roots because no witness pool is recruited yet. Read
this target with that caveat in front of you.

## In scope vs. out of scope

In scope: the Cairn-authored constructions above, how they compose, and the wire
formats.

Out of scope, as trust roots Cairn assumes (per
[`design-brief.md`](design-brief.md) §3.4): GrapheneOS and Pixel hardware, the
Tor network, SimpleX and its double ratchet, the soundness of the Sigsum log
itself, and the RustCrypto primitives. Cairn does not try to defend against
compromise of these, so re-verifying them is not part of this ask.

## Maturity, stated plainly

[`implementation-status.md`](implementation-status.md) maps every defense the
brief claims to one of IMPLEMENTED / PARTIAL / ASPIRATIONAL / DEFERRED /
OUT-OF-SCOPE, with code references. Read it first so your time lands on what
exists. The short version: the primitive layer, the envelope, Shamir, the
trust-graph operations, and cascade-quarantine are implemented and tested;
hardware binding, storage-dependent timers, and the release-time emit are
partial or aspirational; on-wire forward secrecy is SimpleX's property, not
Cairn's.

## Building it

```sh
git clone https://github.com/wlcarden/cairn-messenger.git
cd cairn-messenger
cargo build --workspace      # toolchain auto-installs from rust-toolchain.toml (Rust 1.91)
cargo test --workspace
```

The crypto-bearing crates: `cairn-crypto` (primitives), `cairn-envelope`
(COSE_Sign1 and canonical CBOR), `cairn-shamir` (split and BLAKE3 commitment),
`cairn-identity` (capability tokens), `cairn-trust-graph` (operations and
cascade), `cairn-recovery` (reconstruct and re-attest), with
`cairn-sigstore-verify` and `cairn-sigsum-client` for release verification.
Building the Android app additionally needs the Android SDK/NDK and `libsimplex`;
see the README's "Building from source".

## Discipline you can lean on

The workspace enforces, through CI gates (D0018 §8.5): `unsafe_code = "forbid"`
workspace-wide, `subtle` / `secrecy` / `zeroize` for secret handling, a `dudect`
constant-time smoke test (its threshold validated out-of-band on dedicated
hardware), exact-pinned dependencies under `cargo deny` and `cargo audit`, seven
`cargo-fuzz` targets, and COSE test vectors cross-checked against an independent
implementation. None of this substitutes for review. It means the common
footguns are already gated, so your attention can go to the constructions.

## Reporting findings

Report privately through the repository's **Security → Report a vulnerability**
(GitHub private vulnerability reporting). The severity rubric and disclosure
timelines are in [`runbooks/cve-response.md`](runbooks/cve-response.md); the Safe
Harbor terms (a published preference, not yet legally enforceable per D0016) are
in [`SECURITY.md`](../SECURITY.md). A pre-pilot primitives audit is committed in
[D0011](decisions/D0011-audit-budget-and-timing.md); community review runs
alongside it, not instead of it.
