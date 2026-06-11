# D0003 — Implementation language: Rust core + Kotlin UI

**Status:** Accepted
**Date:** 2026-05-27

## Context

The Section 5 adversarial review surfaced engineering-feasibility findings (F7, F8, F4, F10) showing that several of the project's integration costs were materially underestimated, in ways that varied substantially by implementation language. The handoff (Q8 in [open-questions.md](../open-questions.md)) had recorded Kotlin native as the current preference without explicit comparison against alternatives.

The cryptographic-correctness review and red-team review also surfaced concerns (F2, F23, parts of F9) where the choice of language affects the _security_ of the implementation, not only its convenience — specifically around secret-material lifetime control, side-channel resistance, and the type-system enforcement of cryptographic invariants.

A re-evaluation of the language decision against the review findings and the threat model (Section 3) yielded the choice recorded here.

## Decision

**Adopt a Rust core + Kotlin UI architecture.** All security-relevant code lives in a Rust core compiled to a native library and bound to a Kotlin-based Android UI via [UniFFI](https://mozilla.github.io/uniffi-rs/).

### The Rust/Kotlin boundary

**In Rust (the core):**

- All cryptographic operations: signing, verification, key generation and derivation, Shamir Secret Sharing (splitting and reconstruction), COSE-format capability token issuance and verification, ratchet operations exposed by the SimpleX integration, Tor circuit handling exposed by the Briar integration (v1.5+).
- Trust graph state and operations: parsing, signature verification, conflict resolution, transparency-log proof construction and verification.
- Protocol implementations and integrations: SimpleX SMP client (or wrapper around `simplex-chat` per the integration shape chosen in [D0004](D0004-v1-scope-cuts.md)), Briar bindings when added in v1.5, Sigsum client, Tor integration (via `arti` where viable).
- Persistent storage encryption layer: the on-device encrypted-at-rest store that wraps the messaging-protocol databases.
- Anything touching secret material at any point in its lifecycle.

**In Kotlin (the UI shell):**

- UI rendering, navigation, gesture handling, animations.
- Android lifecycle integration: services, notifications, background work, permissions.
- Display-only data structures: already-encrypted blobs, public-key fingerprints rendered as text, UI state.
- Platform integration glue: Android Keystore API calls, file system access, network configuration.

**The boundary rule.** Secret material does not cross from Rust into Kotlin. The Rust core hands the UI public keys, ciphertexts, and display-safe metadata. Decryption happens in Rust and renders directly to UI primitives without intermediate Kotlin `String` or `ByteArray` that the JVM garbage collector might retain.

## Security rationale

The Rust-core choice is principally a security decision, not an engineering-ergonomics decision. Five specific properties Rust delivers that the JVM/Kotlin cannot:

1. **Memory safety without garbage collection.** Eliminates buffer overflows, use-after-free, double-free, and data races at compile time. For a product whose threat model includes commercial forensic extraction tooling (Section 3.3 Endpoint surface; D0002 references), removing whole classes of memory-corruption vulnerabilities materially reduces the device-compromise attack surface.

2. **Explicit secret-material lifetime control.** The [`zeroize`](https://crates.io/crates/zeroize) crate guarantees secret-material destruction on `Drop`. The [`secrecy`](https://crates.io/crates/secrecy) crate wraps secret types so accidental cloning, logging, or comparison is a compile error. These eliminate the F2 (master reconstruction window) leakage class that the JVM's garbage collector specifically makes unreliable — the GC may have copied a buffer before the application cleared the original, leaving residue in memory the application no longer controls.

3. **Constant-time primitives.** The [`subtle`](https://crates.io/crates/subtle) crate provides constant-time comparison and selection operations that prevent timing side channels in cryptographic verification. Kotlin's standard library has no equivalent; idiomatic Kotlin comparisons are timing-variable.

4. **Type-system enforcement of cryptographic state.** Rust's typestate pattern lets the compiler enforce protocol state machines (e.g., "you cannot sign before unlocking"; "a capability token cannot be used past its expiry"). The eight-field operation schema in Section 5.2 (per F23 in the review) is expressible as algebraic data types with compile-time field-presence enforcement, in a way the JVM's nullable-reference model cannot match.

5. **No garbage collector residue.** Secret material lifetime is bounded by lexical scope and explicit destruction, not by GC scheduling. For the F2 reconstruction-window concern specifically (the master in active memory during recovery), Rust's ownership model lets the application guarantee the master exists in memory only during the brief reassembly window, with explicit zeroization on scope exit.

These properties are not idiomatic in Kotlin. They can be approximated by hand-rolled discipline, but the discipline must hold across every developer, every refactor, and every dependency — which the threat tier this product addresses does not assume.

## Alternatives considered

**Kotlin-native single-language implementation** (the preference recorded in Q8). _Rejected._

- Hand-rolled secret-zeroization in Kotlin is fragile: the JVM may have copied buffers before the application can clear them. The threat model assumes adversaries who can examine memory; relying on developer discipline for secret-material hygiene leaves residue the application cannot guarantee to have removed.
- The SimpleX integration cost (F8) is materially higher in Kotlin because there is no Kotlin-idiomatic SMP client and the Haskell-on-Android pipeline is JVM-friendly only at the JNI boundary anyway.
- The Sigsum client cost (F4) is materially higher in Kotlin because the Rust ecosystem has the cryptographic primitives the Sigsum protocol composes; Kotlin would require building these from scratch.
- The `arti` Tor implementation (the future-direction for embedded Tor on mobile) is Rust-native; embedding C `tor` from Kotlin adds the same JNI boundary plus a more brittle native dependency.
- The hiring argument (Kotlin is easier to staff than Rust at scale) is real but does not apply at solo-developer scope and is addressable at v2+ scope when the team grows.

**Pure Rust implementation including UI.** _Rejected._

- Android UI development outside Kotlin/Java is technically possible (egui, slint, declarative-rs) but immature for the audience and use case. The user-facing application requires Android-native UI affordances — accessibility, system theming, gesture conventions, lifecycle integration — that pure-Rust UI frameworks do not yet provide at production quality.
- The Signal-familiar surface commitment in Section 5.6 depends on Android-native UI behavior; deviating into a non-Android-native UI framework would compromise that commitment.

**Kotlin Multiplatform.** _Considered, deferred._

- Worth re-evaluating for v2 if iOS support is in scope. For v1 (Android-only per Section 6.1), Kotlin Multiplatform's main advantage (shared business logic across platforms) does not apply, and its cryptographic story is identical to Kotlin-native — the same secret-material lifetime concerns apply.
- The Rust core path is forward-compatible with adding Kotlin Multiplatform for the UI shell later, so this is not a foreclosure.

## Consequences

**Engineering structure.**

- The project becomes a two-language stack with UniFFI generating Kotlin bindings from Rust definitions. UniFFI is well-traveled (used by Mozilla's Firefox, by Matrix's Rust SDK, by various other security-tooling projects); the binding-generation cost is small.
- Build tooling adds a Rust toolchain dimension. The reproducible-build pipeline (when added in v1.5 per D0004) must reproduce both the Rust artifact and the Kotlin artifact.
- Testing splits: Rust unit tests for the core (with [`proptest`](https://crates.io/crates/proptest) for property-based testing of cryptographic invariants); Kotlin tests for the UI layer; integration tests at the binding boundary.

**Integration shapes the language decision unlocks.**

- F4 (Sigsum client): writing a Sigsum Kotlin client was multi-week original work in alpha-state protocol territory. In Rust, the cryptographic primitives are mature (Merkle trees via `rs-merkle`, signature primitives via `ed25519-dalek`, etc.), and a reference Sigsum client implementation in Rust is concrete work (estimated 4-6 weeks) rather than speculative.
- F8 (SimpleX integration): the Haskell-on-Android pipeline remains an integration question, but the Kotlin-side cost vanishes — the Rust core can call SMP over a defined protocol surface without the JNI-to-Haskell bridge that Kotlin-only would have required.
- F10 (Tor on Android): `arti` (Rust Tor) becomes the natural choice, avoiding the C `tor` binary's reproducibility burden.

**Forward compatibility.**

- v2 USB form factor (handoff roadmap) becomes more achievable: the Rust core compiles to whatever platform the USB-bootable image targets, with only the UI layer needing platform-specific work.
- v3 mesh radio integration (Meshtastic/MeshCore): mesh hardware is typically embedded-friendly; a Rust core can be cross-compiled to mesh-node firmware where Kotlin cannot.
- iOS support (v2): the Rust core is reusable; the UI layer is replaced with Swift, again reducing the per-platform work to the UI.

**Hiring and team scale.** Acknowledged. At solo-developer scope, not relevant. At v2+ team-scale (per Section 8.1 placeholder), Rust hiring is harder than Kotlin but the security-critical work can be concentrated in the Rust core (where the smaller team contributes), with the Kotlin UI maintained by contributors who do not need Rust expertise. This staffing pattern is well-traveled in the security-tools space.

**Open questions resolved by this decision.**

- Q8 (specific technical library / approach choices, "Android codebase architecture") closes for the language axis. Library-specific choices (specific Rust crates, specific Kotlin libraries) remain deferred to the system design spec.

**Open questions partially resolved.**

- The COSE library question (F23 from review) is simpler with Rust core: the [`coset`](https://crates.io/crates/coset) crate is the mature option, well-maintained, no Android-specific adaptation required.
- The CRDT library question (F3 from engineering review) becomes moot if D0004 drops the CRDT permanently from v1.5; if it is reconsidered for v2+, Rust's type system makes the convergence-property enforcement substantially easier than Kotlin would have.

## Reversibility

The decision is reversible at substantial cost. Code written in Rust can be rewritten in Kotlin, but the security properties that motivated the choice (zeroize, secrecy, typestate, no GC residue) would be lost — making reversal also a security regression. The realistic reversal scenario is "v2+ team finds Rust hiring impossible and Kotlin Multiplatform becomes the substrate" — at which point the Kotlin Multiplatform crypto layer would need to be built with hand-rolled secret-material hygiene that the threat tier may or may not tolerate.

The boundary decision (what's in Rust vs. Kotlin) is reversible at small cost during v1: moving a specific responsibility across the boundary is a refactor, not a redesign.

## References

- [docs/section-5-review.md](../archive/section-5-review.md) — Section 5 adversarial review; findings F2, F4, F7, F8, F10, F23 directly motivate this decision.
- [docs/open-questions.md](../open-questions.md) Q8 — original deferred technical-choice question, now partially resolved.
- the initial design conversation (in git history) — prior conversation Q8 noting Kotlin native as the current preference; this decision re-evaluates that preference against the review findings.
- UniFFI documentation: https://mozilla.github.io/uniffi-rs/
- Relevant Rust crates: `zeroize`, `secrecy`, `subtle`, `ed25519-dalek`, `coset`, `rs-merkle`, `proptest`.
- Architectural precedents: Signal's libsignal (Rust core, multi-platform UI), the Matrix Rust SDK, the Briar project's increasing Rust adoption for cryptographic primitives.
