# If your device is taken (after-seizure guide)

> [!WARNING]
> **Cairn is alpha and pre-audit. Do not rely on it for safety yet.** If your
> device has been taken, work through this **with your facilitator**, and treat
> their guidance and your own judgement as primary.

If your phone is taken from you, even briefly, a detention, a border stop, or
any time it leaves your control under pressure, this is what to do.

## 1. Treat the device as burned

Once a phone has been out of your hands in a hostile situation, you cannot be
sure it is still safe, even if it was handed back and looks completely normal.
Assume it may be compromised. Do not go back to using it for anything sensitive,
and do not unlock Cairn on it to "check."

<details>
<summary>🔍 Why "burned" and not "probably fine"</summary>

Someone with physical access and the right tools can install surveillance that
survives a restart and hides from view, or copy data for offline attack. None of
that is visible to you afterward. The only safe assumption is that a device which
left your control is compromised, so the response is to retire it, not inspect
it.

</details>

## 2. Warn your contacts, on a different channel

Do not use the taken phone to warn anyone. Reach your contacts another way, a
different device, in person, or a call from someone else's phone, and tell them
that your old identity may be compromised and they should not trust messages
from it until you have recovered. Messages from a compromised device can be sent
by whoever holds it.

## 3. Recover onto a fresh device

Get a clean phone, a new GrapheneOS Pixel or one from your facilitator, and
recover your identity onto it from your **recovery network**:

- Collect **three of your five recovery cards**, returned by your peers or read
  from your paper shares.
- Cairn rebuilds your identity on the new phone, and you can reach the people you
  were already talking to.

The peer side of this has a built-in delay: each peer confirms a phrase with you
and then waits 48 hours before their share is sent, so plan for a recovery to
take a couple of days. Your peers' side is in the
[peer-recovery handbook](peer-recovery-handbook.md), and your facilitator walks
you through the recovery on the new device.

## 4. Retire the old identity

Recovering on a fresh device re-establishes you under your master key with a new
device key. As part of coming back, your old (seized) identity is **revoked**, so
your contacts' apps mark it as compromised and stop trusting it.

> [!NOTE]
> At this pilot stage, the one-tap "I've been compromised" button and the
> automatic revoke-during-recovery are still being completed. For now, **your
> facilitator helps you revoke the old identity** as part of recovery. Do this
> step with them rather than assuming the app has done it.

## What Cairn deliberately does not have

Cairn has no hidden or decoy "duress" account that shows fake data when you are
forced to unlock. That approach was rejected on purpose: it tends to fail
against an adversary who knows the feature might exist, and its mere possibility
can raise suspicion and risk. Plan around the real measures here, treat the
device as burned and recover, not around a trapdoor that is not there.

## See also

- [`facilitator-handbook.md`](facilitator-handbook.md) — for the person helping you recover
- [`peer-recovery-handbook.md`](peer-recovery-handbook.md) — what your peers do
- [`user-guide.md`](user-guide.md) — using Cairn day to day
- [`../SECURITY.md`](../SECURITY.md) — reporting a security problem
