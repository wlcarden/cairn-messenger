# Installing Cairn (closed-pilot guide)

> [!WARNING]
> **Cairn is alpha and pre-audit. Do not rely on it for safety yet.** This guide
> is for the **facilitator-supported closed pilot** — not a public release. If
> you are a pilot participant, do this **with your facilitator**, not alone.

This guide takes you from "nothing installed" to "Cairn open on your phone." It
is written for a non-technical reader; the few security-critical steps are
called out, and your facilitator handles the parts that need a technical helper.

**Time:** ~15 minutes with your facilitator.

---

## What you need before you start

- **A GrapheneOS-on-Pixel phone.** Cairn runs only on
  [GrapheneOS](https://grapheneos.org) (a hardened Android) on a supported Pixel.
  Your facilitator provisions this device with you — installing GrapheneOS is
  itself part of onboarding and is **not** covered here.
- **Your facilitator.** They help you verify the download is genuine (below) and
  set up your recovery network. This is precondition four of the v1 pilot — see
  [Who it's for](../README.md#who-its-for-stated-honestly).
- **The release file**, `cairn-<version>.apk`, from the project's
  [Releases page](https://github.com/wlcarden/cairn-messenger/releases).

<details>
<summary>🔍 Why GrapheneOS, and not regular Android?</summary>

Cairn's threat model assumes an adversary who will spend real money on forensic
extraction and exploit tooling. GrapheneOS removes Google services, hardens the
OS against those attacks, and gives Cairn the hardware-backed key storage it
relies on. On stock Android many of Cairn's protections cannot hold. See the
[design brief](design-brief.md) for the full rationale.

</details>

---

## Step 1 — Get the app

On the GrapheneOS phone, open the **Vanadium** browser and go to the
[Releases page](https://github.com/wlcarden/cairn-messenger/releases). Download
two files from the latest release:

- `cairn-<version>.apk` — the app
- `cairn-<version>.apk.sha256` — its checksum (used in Step 2)

> [!NOTE]
> You can also download on a computer and transfer the files, but downloading
> directly on the phone is simplest.

---

## Step 2 — Check the download is genuine (do not skip)

This is the step that makes Cairn trustworthy: it proves the file you got is the
exact one the maintainers built and signed, not a tampered copy.

**Most pilot users:** your **facilitator verifies the build with you.** They run
the two checks below and confirm both pass before you install. If you are not
comfortable with a terminal, this is the intended path — do not improvise.

**Facilitators / technically comfortable users**, run both checks:

```sh
# 1. The file matches its published checksum:
sha256sum -c cairn-<version>.apk.sha256          # must print: OK

# 2. The app is signed by the Cairn signing key — the printed
#    "certificate SHA-256 digest" must equal the fingerprint below:
apksigner verify --print-certs cairn-<version>.apk
```

**Cairn release signing-key SHA-256:**

```
4E:5B:C1:FE:13:17:92:23:E7:36:10:5B:E6:52:AF:D7:EB:0C:97:C8:6B:20:60:A4:A8:58:04:1C:7A:7C:BB:8E
```

If either check fails — the checksum doesn't say `OK`, or the fingerprint
doesn't match — **stop and contact your facilitator.** Do not install it.

<details>
<summary>🔍 Why does this matter so much?</summary>

A signature/checksum check is how you detect a substituted or backdoored build —
the exact attack a well-resourced adversary would attempt against a tool like
this. The fingerprint above is the public identity of the one key that signs
real Cairn releases; it never changes between releases, so it is the anchor you
compare every future download against. (Cairn also ships an on-device verifier
built on Sigstore/Sigsum transparency logs; it is not yet wired into the install
flow, so for now this manual check — or your facilitator — is the verification
path. See [Releases & verification](../README.md#releases--verification).)

</details>

---

## Step 3 — Install it

1. Open the downloaded `cairn-<version>.apk` (tap the download notification, or
   find it in the **Files** app).
2. GrapheneOS asks whether to allow the app you downloaded _from_ (e.g.
   Vanadium or Files) to install apps. Allow it, then return to the installer.
3. Tap **Install**, then **Open**.

> [!NOTE]
> **No app store.** Cairn is installed directly (sideloaded), by design — it is
> not on Google Play, and at v1 not yet on F-Droid or Accrescent (those are
> planned). Direct install is why Step 2's verification matters.

---

## Step 4 — First launch

When Cairn opens for the first time it guides you through creating your identity
and setting up recovery with your peers. A full screen-by-screen walkthrough is
in the [User Guide](user-guide.md) — go through first-run setup **with your
facilitator**, who ensures your recovery network is configured correctly.

---

## Updating to a later release

When a new version is published, download and verify it (Steps 1–2) and install
it **over the top** — do **not** uninstall first. Because every real release is
signed by the same key, the update installs cleanly and keeps your data. (If an
install is _rejected_ for a signature mismatch, the new file is **not** a genuine
Cairn release — treat that as a Step 2 failure and contact your facilitator.)

---

## Trouble?

| Symptom                                                    | What it means / what to do                                                                                                          |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `sha256sum` didn't print `OK`, or the fingerprint differs  | The file is corrupted or not genuine. Delete it; contact your facilitator.                                                          |
| Install rejected: "App not installed" / signature conflict | A different-keyed build is already installed. Contact your facilitator (do not blindly uninstall a build that holds your identity). |
| "Can't install unknown apps"                               | You skipped the allow-this-source prompt in Step 3.2.                                                                               |

For a **suspected security problem**, follow [`SECURITY.md`](../SECURITY.md) —
report privately, not in public issues.
