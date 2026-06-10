# Security disclosure policy

This policy follows Cairn's published Researcher Safe Harbor commitment per
[`docs/decisions/D0012-researcher-safe-harbor.md`](docs/decisions/D0012-researcher-safe-harbor.md)
and the CVE-response runbook per
[`docs/runbooks/cve-response.md`](docs/runbooks/cve-response.md).

**Status:** Cairn is pre-pilot and pre-audit and has not shipped any code to
end users (there are no releases). This policy applies to pre-pilot
implementation work; it becomes operationally load-bearing once v1 ships to
pilot users.

## Reporting a vulnerability

Email `security@cairn-project.org` (placeholder; the operational email and
PGP key will be published before v1 alpha).

Include:

- The version or commit hash affected
- A description of the issue
- Reproduction steps or a proof of concept (if available)
- Your assessment of severity (Critical / High / Medium / Low) per the
  severity table in `docs/runbooks/cve-response.md`

We will acknowledge receipt within **72 hours** and provide a triage
classification within **10 days**.

## Coordinated disclosure preferences

Cairn's published Safe Harbor commits to:

- Acknowledging good-faith researchers in security advisories with their
  preferred handle/affiliation, or pseudonymously, or anonymously per their
  request
- Coordinated disclosure timelines per severity (Critical: 30 days from
  patch ship; High: 60 days; Medium: 120 days; Low: with next regular release)
- Not pursuing legal action against good-faith security research

We prefer to receive disclosures through research-lab partner organizations
whose work model is structured to disclose rather than sell: Citizen Lab,
Amnesty International Security Lab, Access Now Digital Security Helpline,
EFF Threat Lab. These are candidate disclosure-relationship partners;
formal arrangements are negotiated as part of Q5 partner outreach per the
project's open-questions tracker.

## Out of scope (for this policy specifically)

- Vulnerabilities in upstream dependencies (Tor, SimpleX, GrapheneOS,
  Sigstore, the RustCrypto stack, etc.) — please report to the upstream
  project directly. See `docs/runbooks/cve-response.md` §7 for the upstream
  redirect protocol.
- Issues that require physical access to a target's device (the threat model
  explicitly includes these as residual surfaces; see brief §3.5).
- Compromise of GrapheneOS itself or Pixel hardware (these are trust roots
  per `docs/design-brief.md` §3.4; outside Cairn's scope).

## Pre-pilot audit

Per [`docs/decisions/D0011-audit-budget-and-timing.md`](docs/decisions/D0011-audit-budget-and-timing.md),
Cairn commits to a pre-pilot cryptographic-primitives audit before pilot
deployment. The audit scope per Sprint 1 of the consolidated triage covers
the COSE_Sign1 envelope construction, the recovery-flow cryptographic
operations, and (added Sprint 1 C15) Shamir-library timing-safety
verification. The audit firm and report are made public on the
project's transparency log.

## Limitations of Safe Harbor

Per [`docs/decisions/D0016-foundation-incorporation-trigger.md`](docs/decisions/D0016-foundation-incorporation-trigger.md),
Cairn's Safe Harbor commitment is currently a **published-preference**
rather than a legally-enforceable commitment (because the project is not
incorporated as a foundation). Researchers evaluating disclosure to Cairn
should understand:

- The project's stated intent not to pursue legal action against good-faith
  research is unenforceable against future personal action by the
  maintainer, against successors, or under coercion-induced exceptions
- Most of the candidate disclosure-partner organizations named above have
  institutional legal-protection postures that practically substitute for
  project-side Safe Harbor; for some researchers, disclosing through a
  partner organization is a stronger legal posture than direct disclosure
  to Cairn

See `docs/design-brief.md` §8.5 for the honest framing.
