# D0029 — biometric / device-credential quick-unlock (opt-in passphrase wrap)

**Status:** Accepted
**Date:** 2026-06-03

> **Fork resolved (2026-06-03):** the §5 authenticator choice is
> **`BIOMETRIC_STRONG ∥ DEVICE_CREDENTIAL`** (biometric _or_ the lockscreen
> credential) — the recommended option. Validation proceeds per §7: the
> automatable parts (default-OFF regression, the enroll affordance, the prompt
> presenting) run in the harness; the biometric/credential auth _completion_
> (success → decrypt → session, and the cancel → passphrase fallback) is
> confirmed by hand on the device, since adb cannot satisfy the authenticator on
> physical hardware.

## Context

The at-rest model (D0022 §2.2, realized in `CairnSession.bootstrap`) keys
everything on a single user secret: the unlock **passphrase** derives the
Argon2id storage KEK, the domain-separated SQLCipher DB key, and validates
against an encrypted canary. The security property this buys is strong and
simple: **no key material for the encrypted data lives on the device** — a
seized, powered-off phone yields only ciphertext whose key is in the user's
head. The cost is ergonomic: the full passphrase must be retyped on every
launch (the app holds no session across process death — D0026 §12 foreground
note).

The user asked whether unlock can be tied to a biometric / device credential
(or a PIN) instead of retyping the phrase each time. This document decides how,
and — because it **changes the at-rest threat posture** — fixes the boundary
explicitly.

This is downstream of D0022 §2.2 (storage at-rest model) and D0020 §3.4
(StrongBox/TEE posture). It does not change the Rust storage layer or the FFI;
it is an additive Kotlin-side unlock path.

## Decision summary

| Concern                    | Decision                                                                                                                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **What quick-unlock does** | Supplies the **passphrase** to the existing `unlock()` path via a hardware-gated key — it is an _alternate gate_, not a new key hierarchy                                                         |
| **What is wrapped**        | The passphrase bytes, AES-GCM-encrypted under an AndroidKeyStore key. The **KEK is never touched** (stays `NeverExport`, derived in Rust)                                                         |
| **Auth binding**           | `setUserAuthenticationRequired(true)`, per-use (`timeout 0`), `setUnlockedDeviceRequired(true)`, `setInvalidatedByBiometricEnrollment(true)`, StrongBox-backed when available (graceful fallback) |
| **Allowed authenticators** | `BIOMETRIC_STRONG ∥ DEVICE_CREDENTIAL` (Class-3 biometric **or** the lockscreen PIN/pattern/password) — see §5 fork                                                                               |
| **Default**                | **OFF.** Opt-in only, enrolled _after_ a successful passphrase unlock, behind an explicit trade-off explainer                                                                                     |
| **Recovery / root**        | The passphrase **always** works and is the only recovery; quick-unlock never replaces it                                                                                                          |
| **"App PIN"**              | NOT a bespoke app-PIN (security theater, §6). The secure "PIN" is the OS **device credential**, rate-limited by the TEE                                                                           |
| **Blast radius**           | Kotlin-only, additive. When OFF, the posture is **byte-identical to today** (no wrapped secret on disk)                                                                                           |

---

## 1. Why wrap the passphrase, not the KEK

Three candidates could be stored-and-released by a biometric: (a) the
passphrase, (b) the derived Argon2id KEK, (c) a fresh random secret mixed into
the KEK.

We wrap **(a) the passphrase**, because:

- **It respects `NeverExport`.** D0022 §2.4 / §4.1 make the KEK and DEKs
  non-exportable; the KEK is derived inside Rust (`StorageHandle.open` runs
  Argon2id). Wrapping the KEK would require exporting its bytes across the FFI —
  a direct violation. The passphrase, by contrast, is already a Kotlin-side
  `ByteArray` that crosses _into_ Rust; storing a hardware-wrapped copy of it
  exports nothing new.
- **It is purely additive.** The entire existing derivation (KEK + canary + DB
  key) is unchanged; quick-unlock is just a second way to _produce the
  passphrase string_ that `unlock()` already consumes. Smallest possible blast
  radius, no new crypto to audit beyond a standard Keystore AES-GCM wrap.
- **The Argon2id cost is paid once per launch regardless** (we unlock once), so
  skipping it on a "fast path" (the only efficiency argument for wrapping the
  KEK) buys nothing here.

## 2. The wrap

On **enrollment** (user opts in, immediately after a successful passphrase
unlock, so we hold the validated passphrase in memory):

1. Generate an AndroidKeyStore AES-256-GCM key `cairn-quick-unlock-v1` with the
   parameters in §3.
2. `cipher = Cipher.getInstance("AES/GCM/NoPadding")`, `init(ENCRYPT, key)` —
   this requires a fresh user authentication (BiometricPrompt with a
   `CryptoObject(cipher)`), proving the user is present at enrollment.
3. `blob = iv ‖ cipher.doFinal(passphraseBytes)`, written to
   `filesDir/quick-unlock.bin` (a standalone file — it **cannot** live in the
   encrypted store, which needs the passphrase to open: chicken-and-egg).

On **unlock** (launch, if `quick-unlock.bin` exists and the device reports an
enrolled authenticator):

1. Read `iv ‖ ct`; `cipher.init(DECRYPT, key, GCMParameterSpec(128, iv))`.
2. `BiometricPrompt.authenticate(promptInfo, CryptoObject(cipher))` — the TEE
   releases the key only on a successful auth while the device is unlocked.
3. On success: `passphrase = cipher.doFinal(ct)` → call the existing
   `unlock(passphrase)`. On cancel / error / `KeyPermanentlyInvalidated`: fall
   back to the passphrase field (and, on invalidation, offer to re-enroll).

On **disable**: delete the Keystore key + the blob. The posture reverts exactly
to passphrase-only.

## 3. Keystore key parameters (and why each)

```
KeyGenParameterSpec.Builder("cairn-quick-unlock-v1", ENCRYPT | DECRYPT)
  .setBlockModes(GCM).setEncryptionPaddings(NONE).setKeySize(256)
  .setUserAuthenticationRequired(true)                         // (i)
  .setUserAuthenticationParameters(0, BIOMETRIC_STRONG | DEVICE_CREDENTIAL) // (ii)
  .setUnlockedDeviceRequired(true)                             // (iii)
  .setInvalidatedByBiometricEnrollment(true)                  // (iv)
  .setIsStrongBoxBacked(true)  // try; catch StrongBoxUnavailable → retry false (v)
```

- **(i) user-auth-required** — the key is unusable without a successful
  biometric/credential auth. This is the whole mechanism.
- **(ii) per-use (timeout 0)** — every use needs a fresh auth (no validity
  window). We only use it once per launch, so a window buys nothing and a
  non-zero window is strictly weaker. `BIOMETRIC_STRONG` excludes Class-2
  (weak) biometrics from gating real key material.
- **(iii) unlocked-device-required** — the key won't release while the device
  is locked, even if some path could otherwise satisfy auth. Defends the
  "grabbed at a locked screen" case.
- **(iv) invalidated-by-new-biometric-enrollment** — enrolling a _new_
  fingerprint/face invalidates the key, forcing a fall-back to the passphrase
  (and re-enroll). This blocks the "coerce victim to add the attacker's
  fingerprint, then quick-unlock" path.
- **(v) StrongBox when present** — a Pixel 6 has a Titan M2; key material and
  the auth check live in dedicated secure hardware. Fall back to TEE if
  `StrongBoxUnavailableException`, so the app never bricks on a hardware gap.

## 4. Threat-model delta (the honest part)

Quick-unlock **trades a security property for convenience**, and it must be
named, not buried:

- **Passphrase-only (default, unchanged):** _no_ decryptable-data key material
  on the device. Seized powered-off → pure ciphertext. The strongest posture.
- **Quick-unlock ON:** a passphrase ciphertext now sits on disk
  (`quick-unlock.bin`), releasable only by the TEE/StrongBox after a successful
  strong-biometric/credential auth **while the device is unlocked**. This is:
  - **Strictly weaker** than passphrase-only against an attacker who can defeat
    the TEE/StrongBox or who compels a biometric on an unlocked device; and
  - **Far stronger** than the common alternatives users actually pick when
    retyping is painful (a short reused PIN, no lock at all, writing the phrase
    on a sticky note); and
  - **Equal to passphrase-only when OFF** — which is the default, so users who
    want the maximum posture lose nothing.

Therefore: **opt-in, default-off, with an in-product explainer** ("Your
passphrase still works and is the only recovery. Quick unlock stores it
encrypted in this device's secure hardware, released by your fingerprint or
screen lock. Anyone who can pass your screen lock can then open Cairn."). This
is the same bargain Signal's optional screen-lock, and every banking app's
biometric login, already strike.

## 5. Fork — allowed authenticators

The one genuine posture choice is **which authenticators** gate the key:

- **`BIOMETRIC_STRONG ∥ DEVICE_CREDENTIAL` (recommended).** Covers users with
  no enrolled biometric (they use the lockscreen PIN/pattern/password), and
  directly answers the user's "device passkey / PIN" ask **without** a bespoke
  app-PIN (§6). The credential is TEE-rate-limited, so it is a _real_ second
  factor, not a guessable app secret.
- **`BIOMETRIC_STRONG` only.** Slightly higher bar (a shoulder-surfed PIN can't
  open it; it needs the enrolled biometric), but unusable for anyone without a
  registered fingerprint/face, and offers no answer to the "PIN" request.

Recommendation: **both**, since the device credential is hardware-rate-limited
and the convenience win is the entire point. (Confirmed with the user before
implementation.)

## 6. Why not a bespoke in-app PIN

A separate short app-PIN that _directly_ keys the at-rest encryption would be
**security theater**: a 4–6 digit PIN has ~10⁴–10⁶ entropy, so an attacker who
has imaged the device can brute-force it offline against the ciphertext in
moments — it would _lower_ the at-rest bar below the passphrase it replaces.

A PIN is only safe if a tamper-resistant element **rate-limits** guesses. On
Android that element is the lockscreen credential via `DEVICE_CREDENTIAL` (the
TEE enforces backoff/lockout). So "let me use a PIN" is correctly implemented as
"gate the wrapped passphrase behind the OS device credential," **not** as a new
Cairn-managed PIN. If a future product reason demands an _app-specific_ PIN
(distinct from the lockscreen), it must be wrapped by a user-auth-bound Keystore
key the same way — never used as raw key material. Recorded so the theater
option is not revisited.

## 7. Validation plan (and its honest limit)

- **Automatable (adb harness):** default-OFF launch still shows the passphrase
  screen (regression: posture unchanged when disabled); the enrollment toggle
  is reachable only after unlock; `quick-unlock.bin` is written on enable and
  removed on disable; a launch _with_ the blob present surfaces the
  BiometricPrompt (screenshot).
- **Manual (cannot be driven by adb on a physical Pixel):** the actual
  biometric/credential _authentication_ — there is no reliable way to inject a
  fingerprint or satisfy `DEVICE_CREDENTIAL` over adb on hardware (unlike an
  emulator's `emu finger`). So the success path (auth → decrypt → session up)
  and the wrong-finger/cancel fallback are validated **by hand on the device**,
  screenshot-documented — the same honest boundary the camera-scan pairing path
  carries (D0026 §12).
- **Unit-testable:** the bit-level blob format (`iv ‖ ct`) framing helper, host
  JVM. The Keystore itself is not available off-device, so the wrap round-trip
  is an on-device/manual check, not a host unit test.

### Realized (2026-06-03)

Landed as `QuickUnlock.kt` + lock-screen/identity wiring; `MainActivity` became a
`FragmentActivity`; `androidx.biometric:1.1.0` added. On a Pixel 6 with a secure
lockscreen, the automatable checks passed: the default-OFF lock screen is
unchanged with the enroll checkbox present (`isAvailable()==true`); `quickenroll`
generated the hardware key and presented the system prompt — proven via
`dumpsys window` (`Window{… BiometricPrompt}`, `Surface(name=BiometricPrompt#…)`)
and `BiometricService: handleOnDialogAnimatedIn`; the prompt is `FLAG_SECURE`, so
`screencap` is black (a desirable property, not a failure). The enrolled lock
screen offered "Unlock with fingerprint or screen lock", My-Identity offered
"Turn off quick unlock", and disable purged the blob + Keystore key
(`enrolled=false`), reverting to default-OFF. The auth **completion** is the
documented manual step (adb cannot satisfy an authenticator on hardware).

## 8. Cross-references

- [D0022 — storage layer](D0022-storage-layer.md) — §2.2 the at-rest KEK model
  this gates; the passphrase remains the root secret
- [D0020 — integration architecture](D0020-integration-architecture.md) — §3.4
  StrongBox/TEE posture the wrap key uses
- [D0028 — android shell build pipeline](D0028-android-shell-build-pipeline.md)
  — the Kotlin shell this lands in
- D0006 §3.5 — domain separation discipline (the DB key vs KEK precedent the
  passphrase-wrap keeps intact by touching neither)
