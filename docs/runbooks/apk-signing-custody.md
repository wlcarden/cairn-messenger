# Multi-party APK signing-key custody runbook

**Status:** Draft v1; v1 commitment per consolidated external-reads triage X4 / M19
**Last reviewed:** 2026-05-29
**Owner:** Maintainer (developer); trustees per arrangement below
**Cadence:** Trustee arrangement renewed annually on the same cycle as Q14 partner advisory authority renewal

---

## Purpose

The long-lived APK signing key is the single most consequential cryptographic credential in Cairn's release-security stack: its compromise or loss is a multi-release recovery process via APK Signature Scheme v3 key rotation, and its inaccessibility under sudden developer unavailability would prevent any patched release from shipping. Earlier brief versions held this credential under developer-only custody with "ideally multi-party access procedures" as aspirational language. The consolidated external-reads triage upgrades this to a **v1 multi-party access commitment** before v1 ship.

This runbook specifies:

- The N-of-M trustee arrangement (2-of-3 at v1; expandable to 3-of-5 at v1.5 if reviewer pool forms)
- Physical custody of the signing token
- Trustee identification and rotation procedures
- Access procedures for routine release and emergency release
- Interaction with D0009 sudden-unavailability
- Interaction with the CVE-response runbook

---

## Trustee arrangement (v1 commitment)

**Threshold: 2-of-3 access** at v1 ship. Routine release proceeds with developer-only access; the 2-of-3 path activates only under sudden-developer-unavailability (per D0009) or under explicit multi-party signing for release-critical events.

**Trustee composition:**

- **Trustee 1: Developer (maintainer).** Default operational signer for routine releases. Primary custody of the signing token under normal operations; physical token in the developer's working possession.
- **Trustee 2: Partner advisory authority partner per D0009.** Holds the share of access material needed to participate in 2-of-3 reconstruction under sudden-developer-unavailability. The same partner that publishes the sudden-unavailability advisory per D0009 holds this role; the rationale is institutional consistency — the partner who declares the developer unavailable is the partner who participates in the technical-execution response.
- **Trustee 3: Independent named individual.** Selected for jurisdictional and operational diversity from the developer's and the partner's jurisdictions. Holds the share of access material needed for the third 2-of-3 path. Candidate criteria: cryptographic literacy sufficient to participate in signing operation; institutional independence from both the developer's primary affiliation and the partner organization; geographic distance from any single seizure scenario covering both developer and partner; willingness to commit to multi-year operational role with annual renewal.

**Trustee identities** are named in the successor-handover documentation per D0009. The names are private to the trustee arrangement; the existence and structure of the arrangement is public (this runbook is public).

**Trustee compensation.** Trustee 2 and Trustee 3 receive token honoraria for the operational commitment (~$200–500/year per trustee, paid through fiscal-sponsor route per §10.4 under D0016 deferral). The honoraria reflect the operational responsibility and renewal-cycle time commitment; trustees are not expected to contribute substantive engineering or operational work beyond the trustee role.

---

## Physical custody of the signing token

**Token hardware.** A hardware security token (YubiKey 5C or equivalent) holds the long-lived APK signing key under PIN-protected access. The token is provisioned at v1 ship with the APK signing key generated on-device (not imported from software) — the private key never exists in software at any point.

**Primary custody location.** Developer holds the physical token under normal operations. Storage: physical safe at the developer's primary residence or secure office equivalent. The developer carries the token only when actively signing a release; routine work does not require the token.

**Trustee 2 and Trustee 3 custody** is not of the token itself but of access material needed for the 2-of-3 reconstruction path:

- **Trustee 2** holds: PIN component 2 (the PIN that unlocks the token is split into three shares using Shamir-2-of-3; the developer holds component 1, Trustee 2 holds component 2, Trustee 3 holds component 3). PIN component is stored on a separate hardware-backed credential (a YubiKey or equivalent at Trustee 2's location).
- **Trustee 3** holds: PIN component 3 under the same scheme. Stored on a separate hardware-backed credential at Trustee 3's location.

**Reconstruction of the PIN** requires 2 of the 3 PIN components. The developer normally has direct access (component 1 + PIN-recovery procedure if the developer's components are inaccessible); under sudden unavailability, Trustee 2 + Trustee 3 jointly reconstruct components 2 + 3 + the developer's published PIN-recovery procedure to obtain the working PIN, then access the token through a developer-pre-arranged physical-token-recovery procedure (the token's physical location is documented in the successor-handover documentation; access requires the partner advisory authority's authorization per D0009).

**Token physical-loss recovery.** If the physical token is lost, destroyed, or seized, the response uses APK Signature Scheme v3 key rotation. The rotation requires the prior key (lost in this scenario), so the response is a multi-release recovery: a new signing identity is provisioned; users on the prior identity must perform a clean reinstall under the new identity. This is the catastrophic case the trustee arrangement is structured to prevent through redundant access paths; if the physical token is genuinely lost (not just inaccessible to one party), the recovery is not avoidable.

---

## Access procedures

### Routine release (developer-only path)

1. Developer schedules a release per the project's release cadence per [D0008](../decisions/D0008-volunteer-baseline-cadence.md).
2. Developer prepares the release artifact (built per the reproducible-build pipeline at v1.5+; built per the developer's build environment at v1).
3. Developer authenticates to the hardware token with PIN component 1 + their PIN-recovery component (which they hold under normal operation).
4. Token signs the APK with APK Signature Scheme v3 signature.
5. Developer signs the Sigstore identity-based attestation on top per §5.5.
6. Witness cosignatures are collected per the witness-pool protocol.
7. Release ships through F-Droid + Accrescent + direct download.

Routine release does not invoke trustees 2 or 3. They are notified of releases through the release-channel notifications but do not participate in signing.

### Emergency release under developer unavailability (2-of-3 path)

This procedure activates when the D0009 sudden-unavailability advisory has been published OR when a CVE requires patch ship and the developer is unreachable for >24 hours during a critical-severity CVE response.

1. Partner advisory authority partner (Trustee 2) contacts Trustee 3 through pre-arranged direct channels.
2. Trustee 2 and Trustee 3 jointly determine whether 2-of-3 signing is warranted. Criteria: (a) the developer is verifiably unavailable for the time-window the response requires (verified through D0009 first-contact protocol); (b) the release-content is verifiable (the release artifact is built reproducibly at v1.5+; at v1, the developer's pre-staged successor documentation per D0009 includes the build environment specification trustees can replicate or a pre-signed pending release ready to ship).
3. Trustee 2 + Trustee 3 + an additional partner-organization legal-counsel observer (if available) physically convene OR coordinate through secure channels to reconstruct the PIN.
4. The physical token is recovered per the documented physical-recovery procedure (location, authorization through partner advisory authority).
5. The reconstructed PIN unlocks the token; the token signs the emergency-release APK.
6. Emergency release follows the same Sigstore + Sigsum + witness flow as routine release.
7. Partner advisory authority publishes a notification clarifying that the release was signed under the 2-of-3 trustee path due to developer unavailability; the notification is part of the broader D0009 sudden-unavailability advisory if that is also in effect.

The 2-of-3 path is intentionally heavyweight. It is not a routine signing path; it activates only when developer-only signing is unavailable AND the release urgency does not allow waiting for developer-availability restoration.

### Voluntary multi-party signing (developer + trustee path)

The developer may optionally invoke 2-of-3 signing for high-consequence releases (major version transitions; releases with significant security implications; releases occurring after extended developer absence where partner verification is operationally appropriate). This is discretionary and does not require formal trigger conditions. The procedure is the same as the emergency-release path above, with the developer participating as Trustee 1.

---

## Trustee onboarding and rotation

### Onboarding (at v1 ship)

1. Trustee candidates are identified per the composition criteria above. Candidates are evaluated for: technical capacity to execute the access procedure; institutional independence; jurisdictional fit; multi-year availability commitment.
2. Trustee arrangement is documented in a private trustee agreement signed by all three parties. The agreement specifies: trustee responsibilities; renewal cycle; honoraria structure; exit procedure; conflict-of-interest protocol; jurisdictional and indemnification framing.
3. PIN components are generated and distributed to each trustee at provisioning. The generation occurs in a verifiably-secure context (e.g., a freshly-installed GrapheneOS-on-Pixel device used only for this provisioning; the device is wiped after provisioning).
4. Each trustee verifies their PIN component is recoverable from their hardware-backed credential.
5. Test reconstruction: trustees 2 + 3 + developer-published recovery component reconstruct the PIN in a test session, verify the token unlocks, and re-secure. Documented in trustee arrangement record.

### Renewal (annual)

Trustee arrangement is renewed annually on the same cycle as Q14 partner advisory authority renewal. The renewal:

- Reconfirms each trustee's commitment to the role
- Re-tests the PIN reconstruction procedure
- Updates trustee contact information if changed
- Re-issues honoraria per the agreement
- Reviews the trustee composition against current jurisdictional/operational fit

### Trustee replacement

If a trustee withdraws or becomes unavailable, the project replaces them within 60 days of notice:

1. New trustee candidate is identified per composition criteria.
2. New trustee's PIN component is generated; the existing PIN components are rotated to incorporate the new trustee (Shamir share rotation: generate a new 3-share split of the same PIN; distribute new components to all three trustees; old components are destroyed by their holders).
3. Test reconstruction confirms the new arrangement.
4. Documentation in successor-handover records updates to reflect the new trustee identity.

**Replacement under sudden trustee unavailability** (analogue of D0009 for trustees): if a trustee becomes unreachable during a 2-of-3 signing event, the response defers to the developer-availability check (if developer becomes available, routine signing proceeds; if developer remains unavailable AND trustee is unreachable, the response escalates to APK Signature Scheme v3 key rotation under partner-published-advisory framing). The arrangement is structured so single-trustee unavailability is recoverable; double unavailability is the catastrophic case.

---

## Interaction with D0009 sudden-unavailability

This runbook is the technical-execution layer the D0009 partner advisory authority can invoke. Specifically:

- **D0009 30-day first-contact** does not invoke this runbook; the partner attempts to reach the developer through pre-arranged direct channels.
- **D0009 60-day public-advisory** may invoke this runbook if the advisory includes a patched-release ship requirement (e.g., concurrent CVE during DMS window per the CVE-runbook scenario).
- **D0009 duress-canary trigger** invokes this runbook for release-critical operations because the developer's cooperation cannot be assumed reliable.

The partner advisory authority's authorization is required for trustee 2 + trustee 3 to convene under emergency-release path. This authorization is recorded in the D0009 advisory record.

---

## Interaction with CVE-response runbook

For Critical or High severity CVEs (per `docs/runbooks/cve-response.md` Severity table):

- If developer is available, routine signing path applies; the CVE-runbook Phase 4 release engineering proceeds normally.
- If developer is unreachable for >24 hours during a Critical CVE, the CVE-runbook escalates to the emergency-release path in this runbook. The partner advisory authority is notified of the parallel CVE + signing-availability issue; trustees convene per the 2-of-3 procedure.
- If developer is unreachable during an extended response window (>72 hours for Critical; >168 hours for High), the partner advisory authority may publish a D0009 sudden-unavailability advisory in parallel with the CVE patch ship.

The two runbooks are designed to operate concurrently; the partner advisory authority is the coordination point for cases requiring both.

---

## Test exercises

The arrangement requires periodic test exercises to verify operational readiness:

**Annual full-reconstruction test.** At the trustee-renewal cycle, the trustees perform a full test reconstruction of the PIN, unlock the token, and re-secure. The test verifies all three trustees remain capable of executing their role; documents any issues for the renewal record.

**Semi-annual partner-side preparedness check.** Trustee 2 (partner advisory authority partner) verifies internally that the partner organization can mount the emergency-release path on short notice: legal counsel availability; staff training; secure-channels operational; partner-side documentation current.

**Post-incident exercise.** After any actual emergency-release path activation, a lessons-learned exercise documents what worked and what did not; updates this runbook accordingly.

---

## What this runbook does not address

- **OIDC identity compromise for Sigstore identity-based signing.** Handled by §5.5 signing-identity compromise plan (Sigstore-identity-specific response); does not involve APK key rotation.
- **Loss of the physical token while developer is available.** Handled by APK Signature Scheme v3 key rotation as a planned operation, not under the emergency-release path.
- **Coordinated compromise of all three trustees.** This is the structural limit of the arrangement; the only response is APK Signature Scheme v3 key rotation under a new signing identity with explicit user notification. The 3-trustee composition is selected to make single-jurisdiction or single-organization compromise insufficient to compromise the arrangement.
- **Trustee disagreement on whether to sign.** If trustees 2 + 3 disagree on whether an emergency-release path is warranted, the release blocks pending developer availability. This is a feature, not a bug — the 2-of-3 threshold is set so that consensus between non-developer parties is required for emergency action.

---

## References

- `docs/reviews/external-reads-consolidated.md` — X4, M19 findings requiring this runbook
- `docs/design-brief.md` §5.5 — multi-party APK signing-key custody commitment
- `docs/decisions/D0009-sudden-unavailability.md` — sudden-unavailability contingency
- `docs/decisions/D0015-v1-release-security-posture.md` — emergency-release path mechanics
- `docs/runbooks/cve-response.md` — CVE response runbook (Sprint 2 companion document)
- APK Signature Scheme v3: <https://source.android.com/docs/security/features/apksigning/v3>
