# Holding a recovery share (peer handbook)

> [!WARNING]
> **Cairn is alpha and pre-audit. Do not rely on it for safety yet.** These
> recovery flows are new. Set up your role, and walk through a practice
> recovery, **with the facilitator** who onboarded you. If a step here does not
> match what the app shows, trust the app and ask your facilitator.

Someone you know has chosen you as one of their **recovery peers**. This guide
explains what you are holding and, more importantly, what to do (and what not to
do) if they ever ask for it back.

## What you are holding

A **recovery share** for your contact. It lives encrypted inside your Cairn app.
Day to day there is nothing to manage and nothing to check.

One share on its own is useless to anyone, including you. Your contact's backup
is split across several people, and it takes **three of them together** to
rebuild anything. Your single piece reveals nothing at all about your contact's
identity.

<details>
<summary>🔍 Why one share reveals nothing</summary>

The backup is a Shamir secret-sharing split: the master key is divided into five
shares, any three of which reconstruct it, while any two reconstruct nothing.
This is not "hard to crack" but mathematically empty below the threshold: one or
two shares contain no recoverable information about the key. So a share sitting
in your app is not a secret an attacker can use, and losing access to it does not
expose your contact.

</details>

## Why you hold it

Cairn has no account server, so if your contact loses their phone or has it
taken, they cannot click "reset" to get their identity back. They get it back
from people they trust: you and a few others. When three of you return your
shares, your contact can rebuild their identity on a new phone and keep talking
to the people they were already talking to.

## Keeping it safe

There is nothing to do. The share is stored encrypted in your Cairn app, behind
your passphrase. Keep your own Cairn install healthy and your passphrase
private. That is the whole job until, and unless, a recovery happens.

## When your contact asks for it back

A **recovery request** arrives inside Cairn. Before any share is sent, two
checks stand between the request and your contact's safety. Do not skip either.

### 1. Confirm it is really them: the phrase

When you set this up, you and your contact agreed on a private **phrase** known
only to the two of you. It was never stored on their phone.

When a request arrives, **you** reach out to your contact on a channel you
trust, a phone call or in person, and ask them to tell you the phrase. You ask;
they answer. Do not send it to them.

Enter the phrase in Cairn. If it matches, the request is genuine. **If it does
not match, or they cannot tell it to you, stop. Do not release your share.**

<details>
<summary>🔍 Why a phrase and not their key</summary>

A fresh phone has a brand-new key, so the key cannot prove who is asking. The
phrase can, because only the real owner knows it, and because it was never on
the phone an attacker may have seized. The phrase also picks out which share is
being recovered, so it does double duty: it proves identity and selects the
right backup.

</details>

### 2. The 48-hour wait

After the phrase checks out, Cairn does **not** send your share right away. It
schedules the share to send **48 hours later**.

This delay is deliberate, and it protects your contact. If a recovery were ever
forced or faked, the wait gives the real owner time to reach you and stop it.
The countdown runs on **your** phone's clock. After 48 hours, if nothing has
cancelled it, Cairn sends the share on its own.

<details>
<summary>🔍 Why the wait runs on your clock</summary>

The phone requesting recovery might be a fresh device, or one an attacker
controls, so its clock cannot be trusted to enforce a delay. Measuring the wait
on your own device keeps the delay real. The requesting phone shows a countdown
too, but only for information; the enforced timer is yours.

</details>

## Stopping a release

During the 48 hours, your **pending releases** screen has a **Cancel** button.
Your contact can also reach you out-of-band and ask you to cancel.

Cancel if any of these is true:

- they cannot give you the phrase
- they seem to be under pressure, or watched, or not speaking freely
- you did not expect a recovery and cannot confirm it with them independently
- something simply feels wrong

A delayed recovery can always be restarted. A share released to the wrong person
cannot be taken back. When unsure, cancel and confirm.

## If you are the one being pressured

If someone pressures **you** to hand over a share, two facts are on your side.
Your single share reveals nothing, so handing it over (or not) does not by
itself expose your contact; an attacker would need three peers at once. And you
can refuse to enter the phrase, which releases nothing, or cancel during the
48-hour window.

If you cannot safely refuse, the 48-hour delay still buys time, and if your
contact goes unreachable for two days the other peers may notice. The honest
limit: an attacker who compromises three peers at the same time can rebuild the
identity. The protection is that your contact chose peers who are different
people, in different places and relationships, who can each say no.

## See also

- [`facilitator-handbook.md`](facilitator-handbook.md) — for the person who set up your role
- [`user-guide.md`](user-guide.md) — using Cairn day to day
- [`after-seizure.md`](after-seizure.md) — what your contact does if their device is taken
