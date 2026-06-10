# D0002 — Duress profile: out of v1, duress wipe deferred to v1.5

**Status:** Accepted
**Date:** 2026-05-27

## Context

An early draft of Section 3.5 of the design brief claimed "duress profile support for compelled-unlock scenarios" as in-scope for v1. The claim was inconsistent with the architectural decisions captured in the project handoff, which did not specify a duress-profile mechanism. The Section 3 adversarial review flagged the inconsistency (finding #7), and the question was held in [open-questions.md Q1](../open-questions.md) as a gating decision for Section 5.6 (UX Principles) drafting.

A duress profile in the conventional sense is a feature where, under coercion to unlock a device, the user enters an alternative passphrase that opens an alternative, plausibly-benign-looking application state. The adversary takes the alternative state as the user's normal usage; the user's real data stays hidden.

## Decision

**No duress-profile concealment in v1 and not planned for any future version.**

**GrapheneOS duress PIN as v1 operational answer for OS-level whole-device wipe.** GrapheneOS itself provides a duress PIN/password feature: when entered at unlock, it triggers a factory reset of the device before unlock completes, destroying all device state including Cairn key material, message store, contact list, and operational identity along with everything else on the device. This is OS-level functionality independent of Cairn and is **available at v1** to any Cairn user running GrapheneOS-on-Pixel. The v1 provisioning ceremony (Section 6.3) includes GrapheneOS duress PIN configuration as standard operational practice. For the catastrophic-compelled-unlock scenario most pilot users face (officer demands unlock at checkpoint; primary fear is contact-list-read), the GrapheneOS-level whole-device wipe at v1 is the operational answer; the Cairn-specific selective-wipe at v1.5 (below) is a refinement adding partial-compliance capability, not a prerequisite.

**Cairn-specific selective duress wipe deferred to v1.5.** A second passphrase that triggers irreversible destruction of _Cairn-only_ key material — operational identity, on-device message store, contact list, trust-graph cache — without wiping the rest of the device. Adds the partial-compliance use case the OS-level whole-device wipe does not address (user complies with showing certain apps but destroys Cairn data; user keeps Signal and photos intact for the period after coercion when those channels are needed). v1.5 commitment.

**In-app post-coercion recovery flow moved from v1.6/v1.5 deferral to v1 commitment (per consolidated external-reads triage E3, M10).** Earlier brief versions deferred the in-app first-class compelled-unlock recovery flow to v1.6 with documentation-form guidance at v1. The consolidated external-reads triage moved this to a v1 commitment: under detention stress users will not navigate to documentation, and the cryptographic primitives the flow exercises (revoke-recover-reissue per Section 5.3 and D0005) are already v1 scope. The deferral was UX-engineering, not cryptographic. v1 ships a discoverable first-class "I've been compromised — start recovery" path from the main UI that walks the user through revocation, peer-contact mechanics, cooling-off-window monitoring, and the cancel-options-available state at each stage. Engineering scope ~60–160 hours UI work absorbed into v1's working set.

**The architectural answer to compelled unlock is tier separation, which already exists in v1.** Master identity is Shamir-split among recovery peers and not present on the device; operational identity is on-device and exposed under unlock. The realistic bounded compromise is messages and contacts at the time of seizure, recoverable to a new operational identity post-event via the social-recovery process — surfaced through the in-app post-coercion flow at v1.

## Alternatives considered

**Option A — No duress feature in v1; rely on tier separation.** _(Selected, in part.)_ Lowest implementation cost; honest about what the architecture protects and what it doesn't. The tier-separated identity model already does what a duress profile aspires to do, at a lower architectural layer: even full coerced unlock does not yield the master identity or the recovery shares.

**Option B — Duress wipe modeled on GrapheneOS duress PIN.** _(Selected for v1.5.)_ Observable destruction rather than concealment. Works with users whose threat environment treats "I wiped it" as legally cleaner than "I'm hiding something." Extends a primitive that GrapheneOS already provides at the OS level into the app's own key material. Cleanly scoped, well-understood, and credible.

**Option C — Full duress profile with separately-provisioned identity.** _(Rejected.)_ Maximally feature-rich, maximally leaky. Detectable across multiple layers: app storage footprint, hardware-element key slot occupancy, OS-level account/profile metadata, network behavior of background sync, and forensic examination by commercial extraction tooling. Maintains a parallel identity the user must "exercise" with plausible activity to look real — discipline most users will not reliably maintain. In jurisdictions with compelled-decryption laws (UK RIPA, Australia's TOLA Act, France's Article 434-15-2), detected concealment is itself prosecutable — converting "I don't have anything" into "I was hiding something." For the threat tier this product addresses, the feature would create false confidence and credible legal exposure.

**Option D — Empty-state duress unlock that looks like a fresh install.** _(Rejected.)_ Simpler than Option C but inherits the same fundamental problem: app storage footprint inconsistent with the empty state is visible to forensic tools; repeated examinations show consistent emptiness, which is itself a tell; and the user must explain why a security-focused app is installed but unused.

**Option E — Architectural compelled-unlock resistance instead of a feature toggle.** _(Underlies the v1 answer.)_ The tier-separated identity model already does the work that a duress profile aspires to do, at a lower architectural layer. Documenting this clearly in Section 3.5 and Section 5.6 is the v1 deliverable. This is what makes Option A defensible rather than a capitulation.

## Consequences

- **Section 3.5 (in-scope)** gains a "Bounded exposure under compelled unlock" paragraph articulating the architectural answer rather than claiming a feature.
- **Section 3.5 (out of scope)** gains language documenting why duress-profile concealment is not planned for any version, with the v1.5 duress wipe noted as the alternative.
- **Section 5.6 (UX Principles)** replaces the duress-profile bullet with a compelled-unlock-guidance bullet describing an in-app post-coercion recovery flow.
- **Section 6.2 (deferred items)** gains v1.5 duress wipe as a scheduled item.
- **Section 7.1 (release sequence)** updates the v1.5 entry to include duress wipe.
- **Open question Q1** closes with reference to this decision.
- **Pilot user expectations.** Documentation will need to explicitly describe what compelled-unlock costs the user and how recovery proceeds. This is more honest than a feature claim and likely more useful to pilot users who will face the scenario in their casework.

**Reversibility.**

- The duress wipe is a v1.5 commitment, not v1. Reversible by sliding to v2 or later if pilot feedback indicates other priorities.
- The "no duress-profile concealment" decision is intended to hold across the project's lifetime. Reversal would require new architectural mechanism design and is unlikely to be worth revisiting unless target jurisdictions' legal treatment of concealment shifts significantly — for example, if hidden-volume forensic detection becomes provably unreliable, or if the legal regimes around compelled decryption ease.

## References

- [docs/open-questions.md](../open-questions.md) — Q1, original open question, now resolved
- [docs/handoff.md](../handoff.md) — adversarial review finding #7 surfaced the inconsistency; handoff:165 captured it as an open question
- GrapheneOS duress PIN documentation (https://grapheneos.org)
- Cellebrite UFED and equivalent commercial forensic-extraction tooling: see Section 3 footnote `[^forensic-extraction]` in the design brief
- VeraCrypt hidden-volume documentation (https://veracrypt.io) — historical precedent for concealment-style duress features and the detection arms race that followed
- Compelled-decryption legal regimes referenced: UK Regulation of Investigatory Powers Act (RIPA) §49, Australia Telecommunications and Other Legislation Amendment (Assistance and Access) Act 2018, France Penal Code Article 434-15-2
