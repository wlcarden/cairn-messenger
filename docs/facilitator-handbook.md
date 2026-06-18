# Facilitator handbook

> [!WARNING]
> **Cairn is alpha and pre-audit. Do not rely on it for safety yet.** This is the
> operational guide for the person running a pilot onboarding. The recovery flows
> are new and partly still being wired; you are the safety net.

A **facilitator** helps a pilot user get Cairn safely onto a device, sets up
their recovery network, and supports them through the pilot. In the v1 pilot the
facilitator is usually the developer. This handbook is what the role involves.

## The role, honestly

You are a **trust root**. The user trusts you to hand them a genuine build, to
generate and split their master key correctly, and to keep no copy. Your own
security, your computer, your accounts, your physical safety, becomes part of
theirs. Take that seriously, and tell the user plainly that this is how v1 works.

In v1 you are also recruiter, facilitator, and (often) the existing social
relationship. Make clear that declining any part of the pilot does not affect
that relationship.

<details>
<summary>🔍 Why the facilitator is a trust root in v1</summary>

v1 concentrates provisioning and human exposure in one person: you generate the
master key, you verify the build, you are the in-person contact. The design
(brief §3.4, §6.3) names this as a v1 limitation, not a permanent property.
v1.5+ distributes it through reproducible builds and a recruited reviewer pool so
no single person is the whole chain. Until then, your counter-surveillance
practice is load-bearing for the people you onboard.

</details>

## Before you meet

- The user needs a **GrapheneOS-on-Pixel** phone, their own or a loaner.
  Installing GrapheneOS is part of onboarding, not covered here.
- Help them choose **recovery peers**: the people who will each hold one piece of
  their backup. Good peers can say no under pressure, sit in different places and
  relationships, and are not all from one circle that a single introduction could
  compromise.

> [!NOTE]
> v1 pilot caveat: the cohort is small and socially connected through you, so the
> geographic and social diversity the recovery design assumes is limited at this
> stage. Name that limitation to the user rather than implying their peer set is
> as resilient as the architecture allows.

## The provisioning ceremony

Do this **in person**, on your computer and their phone.

1. **Verify the build first** (see the next section) before anything is installed.
2. **Generate the master key** on your computer with the project CLI
   (`cairn-cli gen-key`). This is the root of the user's identity. It never lives
   on the phone.
3. **Split the master** into a **3-of-5** recovery set. The split runs on your
   computer, never on the phone, and produces five shares plus a printable
   **recovery card** for each.
4. **Distribute the recovery cards**: paper cards the user stores safely, and
   cards given to their chosen peers. Any three of the five rebuild the identity.
5. **Set a challenge phrase with each peer**: a private phrase the user and that
   peer agree on out-of-band, never stored on the user's phone. The peer uses it
   later to confirm a recovery is really the user (see the
   [peer-recovery handbook](peer-recovery-handbook.md)).
6. **Install the verified build** and do **first-run setup with the user**
   (passphrase, identity). The [user guide](user-guide.md) has the
   screen-by-screen.
7. **Practice once.** Walk the user through a practice recovery and the
   [after-seizure steps](after-seizure.md) so they have done it before they need
   it under stress.

> [!NOTE]
> The split is a deliberate CLI ceremony (it never crosses into the app, so the
> app never handles the whole seed). The exact command sequence lives with the
> facilitator tooling, and some recovery UI is still being completed; treat this
> ceremony as facilitator-run, not self-serve, at v1.

## Verifying the build (do not skip)

Before installing, confirm the APK is the genuine signed build by checking its
published SHA-256 checksum and its signing-certificate fingerprint. The exact
commands and the fingerprint are in the install guide,
[Step 2](install-guide.md#step-2--check-the-download-is-genuine-do-not-skip).
**You run these,** so the user does not have to, and you confirm both pass before
the app touches their phone.

## The recovery network

The user's safety net is **3-of-5** over their chosen peers, plus their paper
shares. Each peer holds one card and shares one challenge phrase with the user.
One card reveals nothing; three rebuild the identity. Give each peer the
[peer-recovery handbook](peer-recovery-handbook.md).

Set expectations about timing: when a recovery happens, each peer waits **48
hours** after confirming the phrase before their share is sent, so a
peer-based recovery takes a couple of days. Paper-share recovery is faster
because there is no peer and no wait.

## Consent and exit

Get **informed consent** at enrollment. Cover:

- what the pilot involves (this ceremony, designating peers, feedback, the pilot
  duration)
- what the project does and does not collect (no message content, no contact
  lists, no telemetry unless the user opts in)
- what is asked of the user, and their right to refuse any part without losing
  the rest
- their right to exit at any time

Be explicit about two things the user deserves to hear from you directly. First,
the concentration above: you are recruiter, facilitator, and friend, and refusal
costs them none of that. Second, the **v1 supply-chain gap**: v1 ships under
developer source review, without the v1.5 reproducible-builds and reviewer pool,
so a compromised build pipeline producing a bad binary from clean source would
not be caught by source review alone (D0013).

For **exit and problem-reporting**, the intended path is a partner organisation
the user can reach without going through you.

> [!NOTE]
> Candidate partner organisations are identified but **not yet established**.
> Until one is in place, exit and reporting run through you, and you commit to
> honouring an exit without follow-up pressure. Say so plainly; do not imply an
> independent channel exists before it does.

## Ongoing support, and after a seizure

You are the user's support line through the pilot. If a device is seized or
suspected compromised, help them:

1. treat the device as **burned** and stop using it,
2. **warn their contacts** on a channel other than the taken phone,
3. **recover onto a fresh device** from their peers or paper shares, and
4. **revoke the old identity**.

At this stage the in-app one-tap "I've been compromised" entry point and the
automatic revoke-during-recovery are still being completed, so **you help the
user revoke the old identity** as part of recovery. The full sequence is in the
[after-seizure guide](after-seizure.md).

## See also

- [`peer-recovery-handbook.md`](peer-recovery-handbook.md) — give this to each peer
- [`after-seizure.md`](after-seizure.md) — the seizure response
- [`user-guide.md`](user-guide.md) — day-to-day use, with screenshots
- [`install-guide.md`](install-guide.md) — install and build verification
- [`../SECURITY.md`](../SECURITY.md) — reporting a security problem
