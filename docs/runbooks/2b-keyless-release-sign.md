# Runbook: 2b — real keyless release-sign proof

**What this proves (D0042 §7, proof target "2b"):** the full producer→verifier
loop against **real Sigstore keyless signing**. GitHub Actions ambient OIDC →
`cosign sign-blob` → `cairn-release ingest-cosign` → `cairn-release verify`.
A green run means a real Fulcio-issued cert, a real detached signature, and a
real Rekor inclusion proof were assembled into a `ReleaseBundle` that the
**real** `verify_release` accepts.

This is the last milestone that needed something only you can provide. The
verifier, the producer ingest path, and the workflow are all in-tree
(`.github/workflows/release-sign.yml`).

## What you need (the whole list)

1. **This repository on GitHub, with Actions enabled.** That's it.

Everything else is ambient / free / public, no accounts or keys:

- **OIDC** is GitHub's, issued automatically to the workflow
  (`permissions: id-token: write`). No OAuth, no secret, no setup.
- **Fulcio / Rekor / CT** (staging _and_ production) are free public Sigstore
  services. `cosign` hits them over HTTPS.
- **cosign** is auto-installed in the runner (`sigstore/cosign-installer`).

There is **nothing to register, no API key, and no cost.**

## How to run

1. Push this repo to GitHub (if it is not already there) and confirm Actions
   is enabled (Settings → Actions).
2. Actions tab → **release-sign (2b proof)** → **Run workflow**.
3. Leave `environment` = `staging` (the D0042 §1 default) and run.
4. Watch the **verify** step. Success looks like:

   ```
   verify_release: OK
     version:  2b-2026...
     artifacts: ...
   ```

5. The assembled `release-bundle.cbor` + `release-roots.json` are uploaded as
   a run artifact.

## The identity it pins

cosign's cert carries a SAN **URI** of the form
`https://github.com/<org>/<repo>/.github/workflows/release-sign.yml@<ref>`.
The workflow passes exactly that to `ingest-cosign --oidc-san-uri`, and the
verifier pins + matches it (D0042 §6.4). **The repo name is load-bearing** —
it _is_ the cryptographic identity. For a throwaway mechanism proof any repo
works; to carry the proven identity toward production, run it from the real
Cairn repo.

## What is and isn't proven

- ✅ **Sigstore half — real, end-to-end:** Fulcio cert chain + OIDC/URI
  identity, the detached ECDSA-P256 signature, Rekor inclusion + checkpoint,
  and the embedded SCT (checked against the live CT-log key).
- ⚠️ **Sigsum half — synthetic.** `ingest-cosign` mints a synthetic Sigsum
  proof over the real `release_leaf_hash` and pins that synthetic key in
  `release-roots.json`. The recruited Sigsum log + 2-of-3 witness pool is
  funding/people-gated (D0042 §8) — a repo does not substitute for it.
- ⚠️ **Production identity / roots — phase 3.** Staging is best-effort and
  may reset. `environment: production` runs the identical flow against the
  durable production logs (zero extra config), but writes a permanent public
  Rekor entry under the repo identity — defer until the production-identity
  governance decision (D0024 §1.1).

## Caveats / troubleshooting

- **Staging reset / flake:** Sigstore staging has no SLA. Re-run, or switch
  `environment` to `production`.
- **cosign staging config:** the sign step uses `--fulcio-url` / `--rekor-url`
  - `--insecure-ignore-sct=true`. The `--insecure-ignore-sct` only skips
    _cosign's own_ SCT check (which would need the env's CT key configured) —
    the SCT is still **embedded** in the issued cert, and `cairn-release verify`
    checks it against the pinned CT key. If a future cosign version changes the
    staging incantation, this step is the one to adjust.
- **CT-key mismatch:** the workflow pins the _active_ CT log from the live
  `trusted_root.json`. If the leaf's SCT references a different (retired) log,
  drop `--ctlog-key` from the `ingest-cosign` step to skip SCT enforcement
  for that run (the rest of the Sigstore proof is unaffected).

## After 2b

A green 2b retires the OIDC-gated milestone in D0042 §7. The remaining
phase-2/3 work is then purely external: recruit the Sigsum log + witnesses
(§8), decide the production signing identity (D0024 §1.1), and re-run with
`environment: production` to pin production roots.
