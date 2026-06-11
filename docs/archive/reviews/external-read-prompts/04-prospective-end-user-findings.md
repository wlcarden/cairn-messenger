# Prospective end-user review findings

**Review date:** 2026-05-28
**Brief version reviewed:** v0.7
**Time spent:** ~3 hours of reading, plus two evenings with my trainer on calls translating the cryptographic sections into plain language
**Who I am (briefly):** Freelance investigative journalist, 34, eight years in this work in a country where independent media is under sustained surveillance pressure. My national language is not English; my English is functional, not native. I carry a Samsung A54 (work) and an iPhone SE (personal). I use Signal for sensitive work, Telegram for source contact, WhatsApp because half my contacts are there. Two of my colleagues were confirmed Pegasus targets last month by Citizen Lab forensics. A source I talked to in March is in detention; I don't know whether my communications with him are in the case file. I have tried and abandoned four "secure" tools that NGOs recommended over the past five years. I am skeptical by default. My security trainer (three-year relationship) asked me to read this and asked the maintainer to want my honesty. I'm giving it.
**Languages I read the brief in:** English, with my trainer mediating §3, §5.1, §5.2, §5.3, §6.1, D0005, D0006, and the trust-graph diagram. Sections I read alone: §1, §2, §3.1, §4, §5.6, §6.2, §6.3, §7.1, D0013, D0014, open-questions.md. Where my trainer translated a technical term, I evaluate the plain-language meaning, not the term.

---

## Summary

I would not participate in the v1 pilot if invited today, but I would not be invited — the brief structurally excludes me. I do not own a GrapheneOS-capable Pixel, I run a Samsung A54 and an iPhone SE, the pilot is restricted to "10–15 users in one or two local groups already known to the developer," and the brief does not say where the developer is. If by coincidence I am near them and could buy a Pixel, four other things would still stop me from saying yes: (1) the 15-minute default push-polling interval makes Cairn unusable for journalism where sources need answers in minutes; (2) v1 ships _no in-app coercion-recovery flow and no duress-wipe_ (both deferred to v1.6 with no calendar) — the brief tells me to read a document under detention stress; (3) recovery from device seizure takes a minimum of 48 hours after I've gathered three peer shares, which is incompatible with sources who are in active danger; (4) the partner-mediated reporting channel that D0013 makes a precondition of pilot enrollment does not yet exist (Q5 outreach has not begun). I would not recommend the brief unchanged to the maintainer as ready for pilot recruitment from journalists at my friction tolerance — the _brief_ is honest, the _engineering_ is not yet at the point where a journalist working with sources can use it. The v1 pilot, as scoped, is a research instrument with named-population validity; recruiting working journalists into it at the current shape would produce a six-month exposure window during which I would route my actually-sensitive traffic through Signal anyway and use Cairn for low-stakes test conversations. I would tell that to my trainer. She would write it down.

What I would say yes to: a v1.6-shape pilot (in-app coercion recovery, duress-wipe, multi-profile, push under explicit informed-consent, localization to my language) if my trainer's organization were confirmed as the partner-mediation channel and I had a colleague already in the cohort. That product I would consider seriously.

---

## Onboarding reality

**The first 30 minutes does not start at the app.** It starts months earlier with me being told I need to acquire a Google Pixel running a custom operating system I have never used. In my country, Pixel devices are not sold through standard retail; I would buy through a reseller or import. That is several hundred dollars I do not have budgeted for a device that will not replace my Samsung. The brief notes a 2–4 device loaner pool — that is global, not per-region; I will not get one of them. The hardware question is itself an abandonment trigger before installation; my trainer will spend an hour talking me back into trying.

**Installing GrapheneOS.** The brief assumes the developer assists with GrapheneOS installation in person if I haven't already done it. So my first 30 minutes is not "with the app" — it is sitting in a room with a stranger (the developer; my trainer is not the developer) watching commands run on my new phone. I have heard of GrapheneOS twice and never installed it. I do not know what verified boot is. The brief says GrapheneOS verified-boot attestation is the operational mitigation for evil-maid scenarios (§5.1); I will not check it post-seizure because I will not remember how.

**Identity provisioning ceremony.** Per §6.3 and §5.3, the developer walks me through:

1. Master Ed25519 seed generation
2. Shamir 3-of-5 split among peers I designate
3. Pre-shared challenge phrase establishment with each of those 5 peers (D0005)
4. Trust-graph seeding
5. First attestations

My trainer translates the master/operational/capability-token tier model. I get it on the surface: "the important key is split among my friends; the day-to-day key lives in my phone." Fine. I do not understand why there are three tiers and not two. The brief explains; I will not retain the explanation. What I will retain: "the master is not on my phone." Good enough.

**Peer designation is the moment I will quietly compromise the design.** §5.3 says the product "does not score contacts, does not recommend specific peers, and does not require any property of the chosen set." The facilitator pushes back on poor choices, but I am the one who decides. The selection guidance asks me to pick 5 peers who are: (a) geographically distributed across jurisdictions, (b) socially distant from each other, (c) demonstrably able to refuse coercion, (d) reachable when I need them, (e) willing to install Cairn on a GrapheneOS-Pixel device themselves so they can hold the share.

The honest answer is I have, at v1 scale, no such peer set. The pilot is 10–15 people total. My peers, to hold Cairn shares per D0005 ("each peer's Cairn application stores their assigned phrase encrypted at rest"), must themselves be Cairn users. So my 5 peers are some subset of the other 9–14 pilot participants — all in the developer's "one or two local groups." This is the recovery-network surface the brief acknowledges in §3.3 and §5.3, made worse by the v1 closed pilot constraint: my entire peer set is geographically correlated, socially correlated through one facilitator, and structurally targeted as a recognizable cohort. If our group is targeted, my peers are targeted. The architecture for which 3-of-5 Shamir is the right answer is not the architecture I will actually deploy.

Under stress I will pick the first 5 contacts I have who agree. They will be other journalists in my city. They will not be in different jurisdictions. The facilitator will push back. I will agree and pick the same 5 anyway.

**Pre-shared challenge phrases.** I have to agree on a unique secret phrase with each of 5 peers. The phrases are stored off-device — paper, hardware-backed password manager, or "another Cairn user's encrypted message archive." I do not have a hardware-backed password manager that is not on the device I just provisioned. I do not have a safe at home. I will write them on paper that I will keep in my notebook that I carry to interviews. If my apartment is raided or my notebook is photographed, the phrases are exposed. The brief's §3.3 forced-peer-designation surface and the §5.3 recovery-network surface together describe the consequence; the operational mitigation (the in-person ceremony is private) does not address what I do with the phrases after I leave the ceremony.

**Where I close the app the first time.** The provisioning ceremony might take 90 minutes including GrapheneOS install. I will leave with a phone that has the app installed, an identity provisioned, 5 paper notes I do not yet trust myself to store, and a single conversation seeded with the developer-as-facilitator. The first 30 minutes of _using_ the app are: opening it, seeing the contact list (the developer plus zero contacts), trying to send a message, getting no notifications back (15-minute poll), trying to figure out where my contacts go (I have to introduce Cairn to each one in person? out-of-band SimpleX-style? — §5.6 says "Signal-familiar surface" but Signal is phone-number-based; Cairn is identifier-less; this is the gap I will fall into). I will probably set Cairn aside for the next day and use Signal.

## Daily-use friction analysis

**The notification problem dominates everything.** I get 30–80 messages a day across Signal, WhatsApp, Telegram, and email. Many of those have time pressure measured in minutes. A source whose contact I am waiting on, a colleague verifying a fact before a deadline, a fixer confirming a meeting that's an hour away. If Cairn polls every 15 minutes by default (§5.4, §6.1, Q12), then a source's message sent at 2:01 PM reaches me at 2:15 PM. If sent at 2:14 PM, also at 2:15 PM. The actual latency distribution from a source's perspective is 0–15 minutes uniform. Half my messages will be 7–15 minutes late.

For Signal that is unworkable. For Cairn, with sources who are in some cases at physical risk, it is _dangerous_. The brief acknowledges this in §9.1: "the polling-default for push notifications proves too costly for routine operation" is named as a pilot-failure mode. Q12 explicitly flags the 15-minute default as possibly "operationally unusable." The brief therefore knows. The architectural justification — "not adding a third-party metadata channel" — I understand. The journalism cost is: I will route time-sensitive traffic through Signal, fall back to Cairn for archival or planning conversations, and the security property of the conversations that actually matter (where my sources are) will be whatever Signal offers, not whatever Cairn offers. _The security of a tool I don't use for the actually-sensitive thing is zero._

The opt-in push path (UnifiedPush distributor at provisioning) trades the polling cost for a metadata cost. My facilitator will walk me through this at the ceremony per §6.1. I will pick whatever is fastest, and the metadata channel will be a U.S. or European push distributor I do not control, in a jurisdiction whose adversariality to my work I cannot evaluate myself. My trainer cannot pre-evaluate every distributor for me. I will get this decision wrong and not know it.

**Trust-graph operations propagating through my normal traffic.** §5.2 says trust-graph operations propagate over the same SimpleX channel as messages. Fine. Most of these — attestations, withdrawals, introductions, key rotations — happen rarely and I won't interact with them. The one that will appear: a stale-flag on a contact whose attestation has not been refreshed in some period. §6.1 confirms the 90-day auto-escalation timer is _not in v1_ — only the stale-flag visibility ships. So I will see "this contact's attestation is stale" but the system will not act on it. I will not act on it either. I will see the badge, learn to ignore it, and the warning-fatigue pattern §5.6 itself warns against will land on the v1 product. By the time the auto-escalation lands in v1.5 (or v1.6 if it slips), I have already trained myself to dismiss the badge.

**Starting a conversation with a new contact.** In Signal I open Signal, type their number, and a thread exists. In Cairn the contact does not exist until I "introduce" them via SimpleX out-of-band link, then they must add me, then we attest each other. If my source contacts me cold (Signal use case: stranger messages my number), Cairn does not work. There is no number for them to find. Each new contact requires an out-of-band exchange of an identifier-less queue address. For me as a journalist where new sources reach me regularly through tips and warm introductions, this is the central friction. The "Signal-familiar surface" claim in §5.6 is true for _conversations that exist_; conversation establishment is a different shape and the brief does not specify the UI.

**Introducing two of my contacts to each other.** This is the trust-graph "introduction" operation. §5.2 says when one contact vouches for another, the relationship is signed and propagates. For my work: I regularly introduce a source to another journalist for verification. In Signal this is a message that says "talk to her." In Cairn this is a signed cryptographic operation that will appear in the trust graph of both parties, and (per the diagram in architecture-diagrams.md §4) be committed to the public Sigsum log as a hash. My trainer assures me the public log only stores the hash, not the names — but the relationship structure becomes part of permanent record. I am, structurally, careful about who I introduce to whom. Adding "signs a permanent cryptographic operation" to that decision will slow me down. Sometimes that is good. Sometimes it will keep me from making an introduction I should make.

**Single-profile UI in v1.** I cover multiple beats — corruption, security forces, environmental. My Signal already uses one identity for all of them (a cost I bear). Cairn at v1 makes this the only option (multi-profile UI is v1.6). When v1.6 lands, multi-profile is invisible if I have only one — fine. But at v1 I would be deploying _one identity_ against three threat models, the highest of which is "security forces sources." All of my contacts see all of my trust-graph activity. A source on the environmental beat learning that I just attested someone connected to a security-services investigation is a leak. Signal has the same problem; the v1 Cairn does not solve it.

**Voice notes and attachments.** §6.1 commits to voice notes, attachments, group chats at v1. Good. Voice/video calling is deferred to v1.x (Q9). I record interviews. I send them. I assume this works for me, but the brief does not commit to size limits, attachment retention policies, or whether attachments are persisted on the SimpleX server or peer-to-peer. I cannot evaluate this from the brief alone.

**Screenshots.** I screenshot constantly — every contact handoff, every source confirmation, every fact-check exchange becomes part of my notebook. The brief does not address screenshots at all (grep for "screenshot" across `docs/` returns zero hits in the design brief). I do not know whether Cairn blocks screenshots (FLAG_SECURE on Android), warns me, or simply allows them. My assumption from §5.6 ("the conventional foreground is what makes the unconventional background tolerable") is that screenshots will just work, but I cannot tell. If they are blocked, my workflow breaks badly. If they are allowed silently, the brief should say so. Either way I want to know before pilot.

**Disappearing messages, archive, search.** Not mentioned anywhere. I use Signal's disappearing messages heavily for source conversations. I search Signal regularly. Archive is how I keep my contact list usable. None of these are committed in §6.1's "Signal-familiar surface." This may be a v1 UI completeness gap or a deliberate omission; I cannot tell which.

**Capability-token renewal.** §5.1 says tokens are short-lived (hours to days) and renewing requires re-entering the device unlock passphrase. So I will be prompted for my passphrase several times a day, every day. Signal does not do this. WhatsApp does not do this. This is daily attention I am spending on Cairn's tier model that produces nothing visible to me. The architectural argument is real (bounded-window exposure of the operational identity); the user-facing experience is "this app keeps asking me for the same password Signal asks me once for at unlock." That is the kind of thing that, on month two, has me rolling my eyes and reaching for Signal.

## Recovery fear

**The scenario the brief is designed for is roughly what I worry about, and the answer is partially adequate.** Let me walk through what happens on the day my Samsung A54 (running Cairn) is taken from me at a border or by police in a roadside stop.

**Day 0.** Phone is held. I am released after some unspecified time. I am told the phone will be returned later, or I am told it will not.

**Day 1, phone returned.** Per §3.3 returned-after-seizure surface, my operational guidance is to treat it as burned and not return it to active use. I have to acquire a new phone. The same hardware barrier: another GrapheneOS-Pixel, several hundred dollars, sourced through whatever channels are available to me. I do not have a spare. While I do not have a phone:

- My sources cannot reach me on Cairn.
- My contact list (per §3.5 "Bounded exposure under compelled unlock") _was decryptable under unlock_. Whoever held the device could read my contacts and recent messages.
- My trust-graph view was decryptable. Whoever held it saw who I had attested and who I had been introduced to.
- The set of _recovery peers_ I designated was visible from the on-device trust-graph view (per §5.6 "what unlock yields is... the user's trust-graph view — which together identify the user's recovery peer set"). So now the adversary knows who to pressure.

This is the recovery-network surface §3.3 explicitly names. The protection is the peer-verification mechanism in D0005: the 5 peers refuse to release shares without the pre-shared phrase, and the 48-hour delay-and-confirm gives me a window to cancel. Both of those mitigations require my phone to no longer be in the adversary's hands and my peers to be reachable and uncompromised.

**Day 2, fresh phone in hand.** Per §5.3, I install Cairn, initiate recovery, reach out to my 5 peers out of band. "Out of band" means I have to contact each peer through a channel that is not the recovery request channel itself. I call them — but my phone is new, my SIM may not be the same SIM, my contacts are not in this new phone yet because they were on the seized device. I have to look up my peers' contact details somewhere. If they were in my Signal account, I can re-register and recover Signal contacts (Signal's PIN-backed registration). If they were only in Cairn, they are gone with the seized device. _My recovery network's contact details are themselves not recoverable except by my memory or by Signal._

I reach three peers. Each peer prompts me for the pre-shared phrase ("What was the answer we agreed on?"). I open my paper notebook. I find the page where I wrote the 5 phrases six months ago. I read them. The peer verifies and starts the 48-hour clock. I do this with three peers.

**Day 4 or 5, master reconstructed.** The cooling-off window has elapsed. Cairn reconstructs the master, generates a new operational identity, revokes the old one through the trust graph, re-splits the master among peers (same set or revised), zeroizes everything. I am back. Total elapsed time from seizure to operational: ~5 days minimum, assuming everything works.

**What goes wrong, in order of likelihood:**

1. **My paper with the 5 phrases is at home and home was searched.** I write the phrases somewhere only I can reach. But the adversary also searched. Fresh-identity path it is.
2. **Two of my peers are not reachable in 48 hours.** They are traveling, deceased, estranged, or themselves seized. I only have 3 reachable. If one of those is suspect, I have 2. Below threshold. Fresh-identity path.
3. **One of my peers has lost their share.** They reinstalled Cairn between provisioning and now and didn't preserve. Below threshold. Fresh-identity path.
4. **The 48-hour wait is incompatible with what I need to do.** I have a source whose situation is escalating. Per the recovery flow, I cannot send signed Cairn traffic for ~5 days. I can use Signal — but Signal also requires re-registration with my new phone, and Signal-side my contacts may not know it is really me. I will rebuild on Signal because that path is faster.
5. **Continuous-control adversary.** Per D0005 alternatives-considered: an adversary who controls me for 48 hours can extract the phrases (with sufficient pressure) and prevent me from cancelling. The 48-hour delay is acknowledged in D0005 as defeatable by exactly the actor I am most afraid of. The honest framing in §4.3 — "layered resistance, not defeat" — is correct, but my fear is the layer that does not hold.

**The fresh-identity path is the actual recovery path for working journalists.** §5.3 names it as the alternative when recovery is not viable, and it requires in-person re-introduction by an existing contact. I lose history and prior attestations; my colleagues have to re-attest me. For me this is what will _actually happen_ in most of the recovery scenarios I would face. It is the lower-latency path explicitly named in D0005. The brief should treat it as the normal recovery path for my threat tier, with peer-recovery as the slow path for users with intact peer networks. Right now the brief treats peer-recovery as default and fresh-identity as fallback — but in my hands, fresh-identity is the realistic path 60–70% of the time.

**The compelled-unlock guidance is a document at v1.** Per §5.6, the v1 in-app post-coercion flow is _deferred to v1.5_ and at v1 lives in documentation only. This is the most operationally damaging deferral in the brief for me. When I am post-detention, alone, possibly in a country that is not my home country, my emotional state is "panic" and my cognitive state is "compromised." The brief assumes I will find a documentation file and read it. I will not. I will open the app and look for an in-app "I think I've been compromised — what do I do?" button. There will not be one. I will either get this wrong (try to keep using the seized device, which is exactly what §3.3 says not to do) or I will give up on Cairn and use Signal.

**No duress-wipe at v1.** Per §3.5 and §6.2, the duress-wipe pattern is deferred to v1.5/v1.6. So at v1, when an officer hands me my phone and tells me to unlock it, I have no choice except to unlock. The bounded-exposure property protects the master, but not the contact list, message history, or trust-graph view. The brief's answer is that the operational identity is revocable after the fact. That is correct _if I survive the encounter and have time to revoke_. The duress-wipe would let me throw the operational identity (and the local message store) away at the unlock moment. It is the single most operationally important UI feature for my work and the v1 ship omits it.

I will not absorb this. My trainer will push back ("you'd be fine; the architecture protects the master"). I will say the master is not what I am afraid of losing. _I am afraid of my contact list being read_.

## Trust UI evaluation

**The badge model in §5.6 is the right idea and the right risk.** "Information on demand, attached to the entity it describes" is correct as a principle. The risk is that I look at the badges, do not understand what they mean, and treat them as meaningless decoration.

**Verification badges.** In Signal I have done safety-number verification with maybe 8 contacts over six years. Three of those I did because the trainer told me to. Five I did because the contact and I were sitting together and it was a curiosity. I have not noticed safety-number changes that fired. The verification model works _as a property_, not as a practice I engage with.

Cairn's model is denser: each contact carries a verification badge that summarizes attestation state. When an attestation is withdrawn (D0006 operation type 2) or a key is revoked (operation type 3), the badge changes. The brief promises "calibrated language" ("verified through chain of attestations" not "secure"). My trainer assures me the badge state will be intelligible. I am not so sure.

The thing I will glaze over on first: _the difference between "withdrawal" and "key-compromise revocation."_ Per D0006 these have different cascade semantics — withdrawal soft-flags downstream; key compromise hard-suspends post-revoked and soft-flags prior. The user-facing question this maps to is roughly: "is this person no longer my friend, or has their phone been hacked?" That is a real and important distinction. I will not retain the distinction. I will not act on the cascade difference. I will see "this contact's attestation is questionable" and decide based on what they say, not what the badge says.

**The trust badge will mislead me in one specific way.** A contact who has not had their attestation refreshed in 90+ days will be stale-flagged (per architecture-diagrams.md §4). At v1 the auto-escalation timer is not present, only the stale-flag visibility. So I will see "stale" indicators on many contacts simply because nobody has refreshed their attestations recently — not because anything has changed. I will learn to ignore stale flags. When v1.5 ships the auto-escalation, the system will start treating my ignored flags as actionable signals. I will not have re-tuned my pattern.

**Attestation withdrawal in practice.** If a journalist colleague who attested me later withdraws that attestation (because we fall out, or because they have decided I am compromised, or because they themselves are coerced into withdrawing), what happens on my screen and what do I do? My trainer translates §5.2: "their badge changes color; you see that contacts who relied on their attestation are now flagged." Then what? Do I unflag them by re-verifying? Do I drop them? Do I get a notification? The brief does not specify the user flow for this; it specifies the data structure. From my position, this is one of the moments where I most need the UI to slow me down — and it is one of the moments where, under stress, I am most likely to take an irreversible action (drop a contact who is fine, or keep a contact who is compromised).

**Introduction propagation.** When I attest a new contact, the operation goes to the trust graph. My existing contacts see the operation. This is the "social-network attestation" property §4.3 highlights. For me, the practical question: when I introduce a new source to a journalist colleague, the colleague sees the introduction and the source sees the colleague. The trust badge on the source's row in the colleague's app is now "introduced by [me]." That is exactly what I want. _And it is also exactly what I do not want_ in some circumstances — there are sources I introduce to one colleague that I would not want another colleague to know about. v1 ships single-profile, so all my introductions are visible to all my contacts who are interested. Multi-profile (v1.6) is the architectural answer. v1's answer is "be careful about who you introduce to whom."

## Compared to Signal: the friction tax

Per-feature comparison, calibrated against what I actually use:

| Feature                       | Signal (today)                                           | Cairn v1                                                         | Cairn v1.5                           | Cairn v1.6             | Friction cost for me                                                 |
| ----------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------ | ---------------------- | -------------------------------------------------------------------- |
| Text messages                 | works                                                    | works                                                            | works                                | works                  | none                                                                 |
| Push notifications            | < 1 sec                                                  | 0–15 min poll (opt-in push trades for metadata)                  | possibly default-on                  | possibly               | **catastrophic**                                                     |
| Voice notes                   | works                                                    | committed §6.1                                                   | works                                | works                  | unknown until trialed                                                |
| Attachments                   | works                                                    | committed §6.1 (limits unspecified)                              | works                                | works                  | unknown                                                              |
| Group chats                   | works                                                    | committed §6.1                                                   | works                                | works                  | none probably                                                        |
| Voice/video calls             | works                                                    | deferred to v1.x (Q9)                                            | possibly                             | possibly               | moderate                                                             |
| Disappearing messages         | I use heavily                                            | **not mentioned**                                                | unknown                              | unknown                | high if absent                                                       |
| Archive                       | works                                                    | not mentioned                                                    | unknown                              | unknown                | medium                                                               |
| Search across messages        | works                                                    | not mentioned                                                    | unknown                              | unknown                | high — I search constantly                                           |
| Screenshots                   | works                                                    | **not addressed**                                                | unknown                              | unknown                | high if blocked                                                      |
| Profile name/photo            | works                                                    | not mentioned (single-profile in v1)                             | unknown                              | multi-profile UX       | medium                                                               |
| Multi-device (laptop)         | works (linked devices)                                   | **no** (v2)                                                      | no                                   | no                     | **catastrophic — I write on a laptop**                               |
| Stable contact handle         | phone number                                             | identifier-less; each contact added out of band                  | same                                 | same                   | high — new sources cannot reach me cold                              |
| Account recovery              | PIN-backed re-registration; preserves contacts           | 48–96 hour peer-share recovery OR fresh identity (loses history) | + offline-tolerant trust graph cache | + in-app coercion flow | high                                                                 |
| Coercion / duress             | I rely on plausible deniability of disappearing messages | **no duress wipe; written-doc coercion recovery**                | duress wipe + in-app                 | same                   | **catastrophic**                                                     |
| Localization                  | available in my language                                 | **English only**                                                 | maybe                                | maybe                  | high — my trainer would have to translate critical UI strings for me |
| iOS interop (my second phone) | available                                                | **no**                                                           | no                                   | no (v3)                | high — I lose my personal/work separation                            |

The brief frames the friction tax as the price of the threat tier (§4.2 "honest about limits"). The friction tax I would actually pay in daily attention and time, normalized to a workweek:

- **15 extra minutes per day** entering passphrases for capability-token renewals
- **5–10 minutes per new contact** for out-of-band exchange (current rate: 2–3 new contacts per week)
- **15-minute median latency** on incoming messages I am not actively polling for
- **No laptop workflow** — I cannot draft on my laptop and verify on my phone, which is how I work
- **2–3 hours per quarter** maintaining peer relationships, refreshing attestations, possibly rotating peers
- **Annual cost: a recovery rehearsal** — I should do this with my trainer to make sure the flow works for me. Realistically I will not do it.

The friction is justified for the security property I get _if_ (a) my adversary is the threat tier the brief is designed against and (b) the deferred features (duress wipe, in-app coercion flow, multi-device, localization, push) all eventually ship and I am still around to receive them. At v1 specifically, the security property I get is bounded by the things v1 does _not_ protect (the contact list and message history under compelled unlock) and the things v1 does _not_ support (push, in-app coercion, duress wipe, multi-device, my language, my iOS). For v1, the friction tax exceeds the security benefit _for my specific work_. For v1.6 or v2 the math might invert.

## Pilot-consent evaluation

**D0013 is the most thoughtful single document in the package.** It correctly identifies the developer-recruiter-facilitator triple-role problem. It correctly identifies that a consent disclaimer does not address the structural cost of honest reporting. It commits to a partner-mediated reporting channel as a precondition. It commits to a mid-pilot exit protocol that preserves device and data. It commits to tool-mediated harm reporting. These are all the right commitments.

**What I would and would not consent to:**

I would consent to:

- The provisioning ceremony, _if_ my trainer is present alongside the developer
- The six-month duration of active use, _if_ I can exit at any time without social cost
- The partner-mediated debrief, _if_ my trainer's organization is the mediating party
- Public acknowledgment in v1.5 release notes, _if_ the acknowledgment is opt-in per user (which D0013 says it is) and I have time to think about whether to opt in _after_ the pilot rather than at enrollment

I would not consent to:

- Enrollment before the partner-mediated reporting channel exists. Per D0013 this is already a precondition — "Pilot enrollment cannot begin until the partner-mediation arrangement is in place." Per Q5 in open-questions.md, the partner outreach has not begun. So in plain terms: _the brief commits to a precondition that the brief itself confirms is not met_. I do not consent to enroll until the partner channel exists _and I know which organization runs it and through what specific instructions_.
- Pilot enrollment without seeing the actual consent document. D0013 specifies the protocol shape; the document I would sign is described but not drafted. I would want to read the document my trainer's org has reviewed.
- Pilot enrollment without a documented support relationship for when something breaks. The brief says "in-app support channel (cross-ref §5.7 acknowledgments)" but §5.7 confirms the project-operated SimpleX crash queue cuts from v1 and feedback flows through the partner channel per D0013. So my support relationship at v1 is: I report through my trainer's org to the developer. There is no service-level commitment on response time. If my phone is acting strangely on day 3 of a sensitive interview week, I do not know who I am calling and when they will respond.
- A pilot whose CVE-response process is not described. The brief mentions disclosure policy (§8.5, §9.4) but does not specify what pilot users are told when a CVE is found, in what language, with what urgency, and what they are asked to do. As a journalist I have lived through "your tool is compromised, do nothing until further notice" advisories from other software; I have to know what Cairn's variant looks like.

**Time commitment during the pilot.** The brief implies but does not specify: how many hours per month am I committing? The provisioning ceremony is one event. Partner debriefs at 3 and 6 months. Mid-pilot feedback collection through an "in-app support channel" that v1 does not have. What is the realistic commitment? 2 hours/month? 5? More? In what form — interviews, structured surveys, written reports? In English? Whoever is recruiting me should be able to tell me this before I say yes.

**Liability framing.** If something goes wrong — a contact is compromised because of something I did or did not do in Cairn, a source is exposed because the trust-graph propagation surfaced something I did not realize was visible, my device gets rooted because of an undisclosed CVE — what is the brief's framing of responsibility? D0013 has the tool-mediated-harm reporting path, which is the _post-hoc_ mechanism. The _pre-event_ framing — who is responsible for me understanding the limits of the tool — is implicitly "the partner-mediation channel + the facilitator + my trainer + me." If a Pegasus zero-click compromises my Cairn the way it would compromise my Signal, none of those parties are at fault. But if the compromise was caused by an issue Cairn could have warned me about and didn't, the brief should say what happens. It does not.

**Exit protocol.** Per D0013, mid-pilot exit is "revoke pilot enrollment via the partner channel; project commits to honor exit without follow-up pressure from the developer; user retains the device and data on it." That is correct in shape. What it does not address: my Cairn-only contacts (other pilot users) can only reach me on Cairn. If I exit, do I keep using Cairn passively to receive their messages until they migrate me to another channel? Do I un-attest them? Do they un-attest me? The mechanical question of leaving the trust graph is unspecified.

## Top 5 abandonment triggers

Each described as a specific event and a specific reaction. Tolerance breach noted; brief reference noted; tolerance-changing condition noted.

**1. Source dies because my Cairn message arrived 14 minutes too late.**

- _Event:_ A source messages me at 2:01 PM about an arrest in progress; I see it at 2:15 PM during the next poll; the situation has changed; I cannot intervene because the actionable window has closed.
- _Tolerance breach:_ Catastrophic. This is the failure mode my work is structured to avoid. A tool that introduces a 0–15 minute uniform delay on incoming messages cannot be the tool I use for the messages that matter.
- _Brief says:_ §5.4 and §6.1 commit to polling-only at 15-min default. §9.1 explicitly names "the polling-default for push notifications proves too costly for routine operation" as a pilot-failure mode. Q12 acknowledges the default may be operationally unusable.
- _Tolerance-changer:_ Push enabled by default (v1.5 might revisit per Q12). Or polling default reduced to ≤2 minutes with explicit battery cost. Either changes my answer from "uninstall within a month" to "use it for non-time-critical work."

**2. I am at a checkpoint and have no way to wipe Cairn before unlocking.**

- _Event:_ Officer demands unlock; I unlock; my contact list is read; sources are identified; arrests follow.
- _Tolerance breach:_ Catastrophic. The duress-wipe is the single most operationally important UI feature for my work, and it is deferred to v1.5/v1.6.
- _Brief says:_ §3.5 names "Bounded exposure under compelled unlock"; §6.2 defers duress-wipe to v1.5; §5.6 says compelled-unlock guidance is documentation-only at v1.
- _Tolerance-changer:_ Duress-wipe shipped at v1, even in a primitive form (delete the message store and revoke the operational identity on a designated passphrase). Or — explicit pilot guidance "do not put sensitive contacts in Cairn at v1; the contact list is exposed under unlock," which would change my deployment pattern from "use Cairn for sources" to "use Cairn for non-sensitive coordination, keep sources in Signal until v1.6."

**3. Recovery takes 5 days and during that time a source goes dark and I cannot tell whether they have been arrested.**

- _Event:_ Phone seized. I get a new phone on day 2. I contact peers, they verify challenges, 48-hour clock starts on day 3, I am operational on day 5. During those 5 days, a source's messages bounce; the source assumes I have been compromised; the source goes dark.
- _Tolerance breach:_ High. This is the recovery latency cost the brief acknowledges in D0005 ("recovery takes a minimum of 48 hours from the time the user has gathered shares ... acceptable for the threat tier") but does not acknowledge in journalism terms. The threat tier may tolerate it; my source relationships do not.
- _Brief says:_ D0005, §5.3 expected timing 48–96 hours; D0005 explicitly says "users in time-critical states have the fresh-identity path as the lower-latency alternative."
- _Tolerance-changer:_ The fresh-identity path made faster and more accessible — perhaps a "I need to re-establish identity quickly; lose history" first-class action that takes minutes, not days. Or: a publishable "I am temporarily offline, route through X" capability that does not require my master key at all.

**4. The partner-mediated reporting channel never materializes and I have nowhere to report when something breaks.**

- _Event:_ Three months into the pilot, my facilitator sends a message asking for an update; I do not reply because the question is sensitive (Cairn surfaced something I do not want to discuss with the developer directly). The partner channel D0013 promised does not exist. I either say something I do not want to say, or I do not say anything, or I exit silently.
- _Tolerance breach:_ High. The trust I am extending to the pilot depends on D0013's mediating channel being real, not aspirational.
- _Brief says:_ D0013 makes the channel a precondition; Q5 confirms the partner outreach has not begun.
- _Tolerance-changer:_ The partner-mediated channel exists, is staffed by a named organization (ideally my trainer's organization or one I trust), and has a documented response time. I want to see the staffing arrangement before I enroll.

**5. The pre-shared peer challenge ritual collapses because two of my peers lost their phones, reinstalled Cairn, and forgot the challenges.**

- _Event:_ I need to recover. Three peers respond. Two of them say "I don't remember the phrase." I am below threshold. Fresh-identity path. I lose my message history and have to re-establish trust with all my contacts. I quietly stop trusting Cairn's recovery model.
- _Tolerance breach:_ High after the second event of this kind in 12 months. The peer-challenge mechanism per D0005 places a maintenance burden on 5 other people that they did not sign up to maintain.
- _Brief says:_ D0005 confirms the per-peer challenge model; §5.3 confirms peers store challenges in their own Cairn app encrypted at rest; v1 has no automated reminder mechanism for refreshing peer relationships.
- _Tolerance-changer:_ A v1.x "peer-relationship maintenance" pattern — periodic reminder to re-verify a peer (and re-establish the challenge if needed), with a UI that does not require my peers to be cryptography hobbyists. Or: a non-peer recovery path per D0014 candidate options (paper shares held by self being the most plausible for me).

**Honorable mention abandonment trigger that does not crack top 5 only because it would not happen to me personally:**

A second journalist in my city — also a pilot user, also one of my recovery peers — has a Citizen Lab confirmed Pegasus event. The trust graph propagates the key-compromise revocation. My copy of the trust-graph view shows a cascade quarantine across all the attestations she made. I do not understand what to do; my trainer is on a flight; I ask the developer through the (non-existent) partner channel. I get conservative advice and over-revoke. I now have 4 peers instead of 5 and need to re-provision. I lose trust in the cascade-quarantine UI and stop using it as a signal — which is precisely what §5.6 says it is for.

## Top 3 erosion patterns

These are not single events but month-over-month decay patterns that push me back to Signal without my noticing.

**1. The passphrase prompt fatigue.**

Capability-token renewal requires me to enter my device unlock credential. Per §5.1, tokens are short-lived (hours to days). Daily I will be prompted to enter my passphrase several times. Signal asks me once at unlock and then is silent. WhatsApp does not ask at all. The architectural justification — bounded-window exposure of the operational identity — is correct but invisible. The user experience is "this app keeps asking me for the same password Signal asks me once for." Over a month, this trains me to skip Cairn for quick replies. After three months I am using Cairn for the conversations where I have set aside time for security ritual, and Signal for everything else. The security property of Cairn applies to a shrinking fraction of my actual communication.

**2. Stale-flag noise without auto-escalation.**

Per §6.1 (F9 partial), v1 ships stale-flag visibility without the 90-day auto-escalation timer. I will see a growing number of contacts whose attestation chains are stale — not because anything is wrong, but because nobody is refreshing attestations on a cadence. The flag will become wallpaper. By the time v1.5 ships the auto-escalation, I will have trained myself to dismiss the flag, and the system will be giving me actionable signals against a habit I have built. The warning-fatigue literature §5.6 itself cites predicts this outcome.

**3. The "Cairn is for the slow stuff" mental model.**

Combine the polling latency, the passphrase prompts, and the slower contact-add flow, and the natural place Cairn ends up in my workflow is "planning conversations and archive." Sources go in Signal because Signal is fast. Coordination goes in Telegram because that is where my colleagues already are. Cairn becomes the place where I write longer messages to one or two people I have onboarded with full ceremony. After six months I will use Cairn 5–10 times a week, not 50–100. The architectural security I am paying for is therefore being applied to my least sensitive 5–10% of communication.

This is the slow death of secure-messaging adoption I have seen with the four tools I previously abandoned. The pattern is not "I uninstall" — it is "I stop reaching for it." The brief does not have a UX mitigation for this pattern that is convincing to me at v1. The Signal-familiar-surface argument addresses the _first_ day; it does not address day 90 when my fingers reach for the blue icon, not the Cairn icon.

## Steps I will skip

Each step, why I will skip it, and what the brief's mitigation looks like:

**Choosing peers carefully per the §5.3 selection guidance.** I will not assess my peers against geographic distribution, social distance, and demonstrated coercion-refusal capability. I will pick 5 people who agree to participate. They will be other journalists in my city. The facilitator will push back; I will agree and pick the same 5. _Brief's mitigation:_ the in-person ceremony with a trained facilitator. _Why I will skip anyway:_ I do not have 5 trustworthy peers across jurisdictions who will install Cairn on a GrapheneOS-Pixel; the pilot's scope makes the requirement structurally impossible to satisfy.

**Recording the pre-shared challenge phrases off-device per D0005.** I will write them on the same notebook I carry to interviews. I will not transfer them to a hardware-backed password manager because I do not own one. _Brief's mitigation:_ documentation; facilitator coaching at provisioning. _Why I will skip anyway:_ the off-device storage problem is not a coaching problem; it is a "I do not have a safe in my apartment" problem.

**Reading the post-coercion recovery documentation before I need it.** I will not. I will read it after the event, on the day I need it, on whatever device I have access to. If the documentation is on the v1 device, the documentation is also on the device I have to abandon. If the documentation is on a web URL, the URL goes through a network I do not control on a fresh device whose Tor config is not yet set up. _Brief's mitigation:_ documentation. _Why I will skip anyway:_ this is the situation a v1.5/v1.6 in-app first-class action is designed to address; v1's deferral assumes a user who reads documentation prophylactically. I am not that user.

**Verifying contact attestation chains by drilling into the contact detail.** I will glance at the badge color and assume. _Brief's mitigation:_ "information on demand" model; the chain is drillable. _Why I will skip anyway:_ drilling into a chain takes 30 seconds; my time budget per conversation is 5 seconds; the badge color will be the load-bearing signal whether the designer intended it to be or not.

**Reviewing the Sigsum log entries to verify trust-graph operation provenance.** I will not. _Brief's mitigation:_ the log is auditable. _Why I will skip anyway:_ I do not know what a log entry looks like, what would be wrong with one, or what I would do if I found a discrepancy.

**Verifying GrapheneOS verified-boot attestation post-seizure per §5.1.** I will not. I do not know how. _Brief's mitigation:_ "platform infrastructure, not a Cairn-layer defense" — i.e., the brief acknowledges this is on the user. _Why I will skip anyway:_ my trainer might do this with me once and I will forget the steps by month 3.

**Updating the app within the recommended window after a release.** I will defer updates because I am on a deadline. After a CVE I will defer updates because I am on a deadline. _Brief's mitigation:_ multi-channel distribution + the v1.5 rebuild attestation. _Why I will skip anyway:_ update fatigue is universal, and the v1 supply-chain gap §5.5 acknowledges makes pre-v1.5 updates particularly worth scrutinizing — which I will not do.

**Re-attesting contacts on a schedule.** I will not maintain attestation freshness for my contact set. Over months, my trust graph will become a record of attestations I made in the first week and nothing since. _Brief's mitigation:_ the stale-flag visibility; v1.5 auto-escalation timer. _Why I will skip anyway:_ there is no maintenance prompt in v1 that escalates; the flag is information, not a forcing function.

## Concepts I will not retain

These are the technical concepts I will not be able to explain in my own words 30 days after onboarding. For each, the operational consequence:

- **The three identity tiers (master / operational / capability token).** I will retain "important key is split among friends; phone has the day-to-day key." The third tier — capability tokens — will collapse for me into "the app." _Operational consequence:_ I will not understand why I am being prompted for my passphrase to renew tokens. I will treat it as friction with no payoff.
- **The five trust-graph operation types and the cascade quarantine.** I will retain "the badge changes when something is wrong." The withdrawal-vs-revocation distinction will not survive. _Operational consequence:_ I will not act differently on a soft-flag versus a hard-suspend; I will treat both as "this contact is questionable."
- **COSE_Sign1 / CBOR / nine-field signed-operation schema.** Nothing. I will not be able to explain what is signed or why. _Operational consequence:_ none directly; the architecture-level concept survives ("things are signed") even if the details do not.
- **Sigsum commitment-only logging.** I will retain "the log is public but does not contain my contact information." I will not retain why. _Operational consequence:_ I may not understand the privacy implications of activities that _are_ visible in the log (release attestations, witness cosignatures, hash chains in aggregate).
- **The 48-hour delay-and-confirm window.** I will retain "recovery takes 48 hours." I will not retain that the window is for me to cancel an adversary-initiated recovery. _Operational consequence:_ under stress I may not notice the "you can cancel" UI element in the fresh device's recovery screen.
- **What StrongBox / TEE / Titan M2 actually does.** I will retain "there's a special chip in the phone." _Operational consequence:_ I will not be able to evaluate whether GrapheneOS's verified-boot attestation post-seizure shows tampering — I will not run the check at all.
- **Why the master is not on the device in routine operation.** I will retain this — it is the central architectural message and my trainer has translated it well. _Operational consequence:_ this is the one concept I will hold across all 30 days, and it is what will reassure me at the worst moments.
- **What the trust badges' specific colors and shapes mean.** Without seeing the actual UI, I cannot evaluate this — but I predict I will retain at most a binary "good / suspect" distinction. The brief's calibrated-language commitment ("verified through chain of attestations" vs "secure") is the right design; whether I retain the calibration is a UI-execution question the brief does not yet answer.

## What I would tell my colleague after three months

After three months in the pilot, here is what I would tell another journalist colleague who is not in the pilot:

_"Cairn is the most carefully thought-through secure tool I have read documentation for. The team is honest about what it cannot do and they wrote down the limitations in a document I could actually find. The pilot has a real consent protocol — not a checkbox._

_And — I am still using Signal for my sources. Cairn has a delay on incoming messages that I cannot work around. It does not have a duress wipe. If my phone is seized my contact list is exposed. My laptop is not connected. I cannot put my source in Cairn and have her message me from her iPhone because Cairn has no iPhone version yet._

_I would tell you to wait for v1.6 — that is when the in-app post-coercion flow, the duress wipe, the multi-profile UX, and maybe localization to our language all land. Right now Cairn is a research tool with the right architecture. The product that fits our work is one or two versions away. I am paying the friction of v1 because I have a relationship with the team and my trainer wants honest feedback at this stage. If you do not have that obligation, your time is better spent improving your Signal practice and getting comfortable with disappearing-message defaults and verified safety numbers."_

That is what I would say. I would not recommend Cairn v1 to a working colleague unless they were specifically interested in being part of the research and could absorb the friction without compromising their work. I would recommend Cairn v1.6 — if it ships and matches what the brief promises — to colleagues whose threat tier matches mine. That is a future recommendation, not a present one.

## What you would change before recruiting me to the pilot

Concrete changes that would change my answer from "I would consider it" to "I would commit to it." Listed in order of how much each would move me.

**1. Ship the in-app post-coercion recovery flow at v1, not v1.6.** This is the single change that would most move me. The architectural pieces exist; the v1 deferral is a UX-engineering deferral, not a cryptographic one. "Tap this button to revoke your operational identity and start fresh-identity recovery" can be a v1 first-class action even without the rest of the v1.6 polish. The current state — "read a document" — does not survive contact with detention stress.

**2. Ship the duress-wipe at v1, even in primitive form.** Per §6.2, the v1.5 pattern is "modeled on GrapheneOS's duress PIN." GrapheneOS already has it. Cairn can borrow the primitive: a designated passphrase, entered at unlock, wipes the local Cairn message store and revokes the operational identity. Without this, the v1 product is operationally unusable for me at checkpoints, which is half my work.

**3. Reduce the polling default to ≤2 minutes or commit to push-on-by-default for users who explicitly consent to the metadata channel.** The 15-minute default is acknowledged in Q12 as possibly unusable; it is unusable for me. A 2-minute polling default has battery cost but does not introduce the per-distributor metadata channel. The brief should treat the polling-vs-push tradeoff as a v1 user choice with a defensible default that is operationally usable, not a deferral to v1.5.

**4. Name the partner-mediated reporting organization and confirm the channel exists before recruiting.** D0013 makes the channel a precondition. The brief should commit to naming the specific organization (Front Line Defenders / Tactical Tech / Access Now / my trainer's org) before pilot recruitment starts. I would consent to enroll if my trainer's organization is the named mediator. I would not consent to "this will be one of these four organizations, to be determined."

**5. Ship at least one non-peer recovery option at v1 — paper shares held by self.** Per D0014, paper shares is "the option closest to v1's architecture and likely to be the v1.x candidate." It is also the option that solves my actual recovery scenario better than peer recovery: I would print the shares, hide them in three different physical locations, and recover from them when my phone is seized. This eliminates the recovery-network surface and the peer-relationship-maintenance burden simultaneously. The brief should not defer this to v1.x; it should ship at v1 alongside peer recovery.

**6. Document the screenshot policy explicitly.** Tell me whether Cairn uses FLAG_SECURE, allows screenshots, warns me, or detects them. This is a 1-paragraph addition to §5.6 or §6.1. Without it, I do not know whether my workflow breaks on day 1.

**7. Specify the SLA on the support relationship during pilot.** What is the expected response time when I report a problem through the partner channel? Within what hours? In what languages? This is a 2-sentence addition to D0013.

**8. Commit to a CVE-disclosure protocol specifically for pilot users.** When a CVE is found, what specific message do pilot users receive, through what channel, in what language, with what asked action? D0013 covers tool-mediated-harm reporting; CVE response is the inverse direction and the brief does not address it.

**9. Localize the critical-UI strings to my language at v1, not v1.5.** Per Q19 / Q6, localization is a v1.5+ commitment dependent on pilot user demographics. The chicken-and-egg problem: if v1 ships English-only, the pilot reaches English-comprehending users, and the demographic data the brief intends to use to prioritize localization is biased toward English speakers. At least the post-coercion guidance, the recovery flow text, the trust-badge labels, and the consent document should be available in my language at v1. The full app can stay English.

**10. Acknowledge the laptop workflow problem and offer a v1 partial answer.** Multi-device is v2. That is a long wait. A v1 answer that lets me at least _receive_ messages on my laptop (a read-only secondary view; even a manually-exported transcript) would let me use Cairn for the kind of long-form research I do on a laptop. The brief currently assumes single-device-per-identity is acceptable for v1; for me it is the workflow-killing constraint.

Items 1, 2, 3, and 5 change my answer from "consider" to "commit." Items 4 and 7 are preconditions I would name in the consent conversation regardless. Items 6, 8, 9, and 10 are quality-of-life issues I would absorb if the others were addressed.

## What works well

Each item below identifies a specific failure mode from my prior experience (with Signal, Telegram, WhatsApp, or one of the four tools I abandoned: PGP-over-Thunderbird, Wire, Wickr Me, Tutanota). Each item names what about Cairn structurally avoids that failure mode.

**1. The audience exclusion honesty in §2.2 and D0014.**

- _Failure mode this addresses:_ In 2020 my trainer recommended a tool whose threat model was good for organizers but wrong for journalists with sources in detention. I tried it, abandoned it within three weeks, and stopped trusting that trainer's recommendations for almost a year. The brief names _who it is not for_ before it names who it is for — sex workers under criminalization, abuse survivors, isolated dissidents, undocumented organizers, queer people in criminalizing jurisdictions, religious minorities, prisoners' families — and commits to a v1.x/v2 candidate path (D0014). For my case, the brief tells me clearly: "v1 is appropriate for users whose primary adversary is remote" and "users without an available peer-recovery network are out of scope." If I am not in the audience, I find out before I install. The trust this builds is the inverse of the abandonment-trust-loss pattern from 2020.

**2. The threat model addressed to facilitators, not users (§3.1).**

- _Failure mode this addresses:_ PGP-over-Thunderbird (2018) assumed I would understand its threat model and operate accordingly. I did not. I generated a weak key. I shared my private key with myself across devices in an insecure way. I abandoned it because I knew I was getting it wrong. The Cairn brief explicitly says the threat model is "written for the people who deploy and support the product on behalf of users — pilot administrators, NGO security trainers, journalists' digital-security staff — and not, in most cases, for the end users themselves." This matches how I actually work. My trainer interprets; I act on her interpretation. The architecture is _designed for_ this support relationship, not despite it.

**3. The fresh-identity path as a recovery alternative (§5.3 last paragraph; D0005 acknowledgment).**

- _Failure mode this addresses:_ Wickr Me, before AWS sunset it, had a single recovery path — your recovery key or nothing. I lost access to an account once and lost the conversation history. The brief commits to two recovery paths and is explicit that the fresh-identity path is the lower-latency alternative for users in time-critical states. For me as a journalist, the fresh-identity path is the realistic recovery path 60-70% of the time, and the brief surfaces it rather than hiding it. The cost (loss of message history and prior attestations) is named in plain language, not buried.

**4. The withdrawal-vs-revocation distinction in the trust graph (D0006, architecture-diagrams.md §4).**

- _Failure mode this addresses:_ In Signal, when a contact's safety number changes, I do not know whether it is a legitimate device-change (new phone) or a compromise. I treat all changes the same way: a brief moment of unease, no action. The cascade-laundering attack the D0006 split closes is a real attack pattern that matches what I worry about with journalist colleagues: their phone gets compromised, the adversary uses their key to introduce me to a "source" who is actually an informant, and the trail leads back to me through the introduction. The withdrawal-vs-revocation distinction tells me what _kind_ of trust change I am looking at. I will not retain the distinction, but my trainer will, and when she tells me "this revocation is the bad kind," I will treat it differently than when she says "this is just a withdrawal."

**5. The commitment-only Sigsum logging (§5.2).**

- _Failure mode this addresses:_ I tried Keybase in 2019. Keybase made all my attestations public — including the connection between my journalist identity and my personal identity. I could not undo it. I deleted the account. The Cairn architecture explicitly avoids this: the public Sigsum log stores only hashes of trust-graph operations, not the content. The trust-graph operations themselves propagate over SimpleX between the parties who need to see them. My source map does not become a public artifact. This is the single architectural decision that makes me willing to consider participating at all.

**6. The honest naming of the recovery-network surface (§3.3) and the recovery-network-as-target framing (§5.3).**

- _Failure mode this addresses:_ Many secure tools imply that social recovery is more secure than centralized recovery; Cairn says "the peer network is itself a high-value target" and names the architectural cost honestly. This means I am not being marketed a property the tool does not have. I make my deployment decisions against an accurate model.

**7. The pilot consent and exit protocol (D0013) treating the developer-as-recruiter problem structurally.**

- _Failure mode this addresses:_ I once participated in a small academic security-tool study where the researcher was also my point of contact. When the tool caused friction I did not report it because the researcher and I had become friends. The data the study collected was biased. D0013 names this dynamic explicitly and commits to a partner-mediated channel as a precondition. Whether the precondition actually closes (Q5) is a separate question, but the architectural commitment to addressing it is real.

**8. The phase-gate framing for v1 ship conditions (§7.1).**

- _Failure mode this addresses:_ I have been recruited to "early access" releases of tools that shipped before they were ready and broke during use. The four conditions for v1 — engineering scope completion, pre-pilot audit, partner-mediated consent protocol in place, developer source review completes — are real gates, not calendar dates. If the audit does not close, the pilot does not start. This is the inverse of "we are shipping by Q3 because we promised investors."

**9. The naming of the v1 supply-chain gap (§5.5, D0013) in the consent material itself.**

- _Failure mode this addresses:_ I have used tools whose update channel was compromised. I learned about it from press coverage, not from the tool. Cairn commits in the pilot consent to disclosing the v1 source-vs-binary supply-chain gap — "a compromised build pipeline producing a malicious binary from clean source would not be detected by developer source review alone." I am being told the specific thing the tool does not yet protect against, before I install. This is not marketing language; this is what a serious tool sounds like.

These nine items are the architectural and operational decisions that make me willing to read this brief seriously and consider the product on its own terms. None of them changes my abandonment-trigger list. They change my willingness to engage at all.

## Open questions

Where the brief does not tell me enough to answer my own questions:

- _Where is the developer geographically?_ The brief says "10–15 users in one or two local groups already known to the developer" but does not say where the developer is. I cannot evaluate whether I am even geographically possible for v1.
- _What is the actual UI for the trust badges?_ The brief commits to the data model (D0006, §5.2) and the principle (§5.6 "subtle trust signals"), but does not show what a badge looks like. I cannot evaluate whether I will understand it.
- _What does the in-app recovery screen show during the 48-hour cooling-off window?_ §5.3 says the fresh device "shows the user the current state at each step (peers contacted, peers verified, time remaining in cooling-off, cancel options available)." What specifically? In what language? With what visual prominence on the cancel option?
- _What does Cairn do with screenshots?_ Not addressed.
- _What happens to my Cairn-only contacts when I exit the pilot mid-way?_ D0013 covers my data; it does not cover the trust graph mechanics on the other side.
- _What is the support relationship during the pilot — who do I contact, on what channel, within what time frame?_ D0013 establishes the partner-mediation channel as a precondition but does not specify SLA.
- _What language will the consent document be in?_ I need to read it to consent. If it is English-only and my English is functional but not native, my trainer translates. Is my trainer's translation binding?
- _What is the developer's identity in the v1 pilot — single person, named, with what professional reputation?_ §3.4 trusts the in-person facilitator. I trust people I can name. The brief does not name the developer.
- _What is the file-size limit on attachments? What is the message-history retention default?_ Routine product questions the brief does not address.
- _Disappearing-message support and defaults?_ Not addressed.
- _Is there a fingerprint or PIN to unlock Cairn on top of the device unlock?_ §5.1 implies the device unlock credential gates operational signing; a separate Cairn app lock is not specified.
- _What is the realistic time commitment per month for pilot users?_ Not specified.

## Reading gaps

Honest accounting of what I did not read carefully and what required so much trainer mediation that my evaluation is uncertain.

- **§5.2 (trust graph) detailed mechanics.** My trainer translated the operation envelope and prior-hash chain into plain language. I trust her translation; I did not verify it against the original text in detail. If the cascade semantics in the architecture-diagrams.md §4 differ from my impression, my evaluation of the trust-graph UX is built on the diagram rather than on §5.2 itself.
- **§5.4 (communications protocols) detailed protocol comparison.** I skimmed the comparison of SimpleX vs Briar vs Matrix vs others. The cryptographic-protocol-selection arguments did not register; my evaluation is at the product-comparison level (§2.3), not at the protocol level (§5.4).
- **§5.5 (release security) detailed pipeline.** My trainer summarized: "the app updates are checked through multiple parties so a single compromised developer cannot push a malicious version." I did not engage with the Sigstore/Rekor/Sigsum specifics. My evaluation of the supply-chain risk is at the named-gap level (the v1 source-vs-binary gap), not at the construction level.
- **§8 (operational and governance plan) detailed funding model.** I skimmed §8 and §10. The cadence framing, the foundation-incorporation deferral, the fiscal-sponsor selection — these affect me only insofar as they bear on the project's continued existence over a multi-year horizon. My evaluation is "the project's runway is conditional and the brief acknowledges that," not a detailed assessment.
- **Appendix A (technical decisions and rationale).** Did not read.
- **Appendix B (glossary).** Used as a reference for unfamiliar terms; did not read end-to-end.
- **Decision documents D0001 (project name), D0003 (implementation language), D0004 (v1 scope cuts), D0006 (cryptographic envelope), D0007 (multi-device), D0009 (sudden unavailability), D0010 (foundation jurisdiction), D0011 (audit budget), D0015 (v1 release security), D0016 (foundation incorporation trigger).** Did not read in full. Surfaced through cross-references from the sections I did read.

My evaluation is most confident on the §1, §2, §3.1–§3.5, §5.1, §5.3, §5.6, §6.1, §6.2, §6.3, §7.1, D0005, D0013, D0014, and open-questions.md surfaces. My evaluation of the protocol-level and release-security-level surfaces is mediated by my trainer and weaker. If the maintainer wants my response to a specific section I did not read carefully, I will read it with my trainer and produce a separate note.

---

_If my trainer reviewed this document, she would nod at almost all of it and push back at one place: the abandonment-trigger framing on the 48-hour recovery delay. She would say "five days is actually fast; you can survive five days." She is right that I can survive five days. She is also right that I would re-route my actually-sensitive traffic to Signal during those five days, which is the failure mode this evaluation is about. Both can be true._
