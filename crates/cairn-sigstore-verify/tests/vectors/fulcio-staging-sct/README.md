# Fulcio staging SCT test vectors (D0042 §5 / §6.5)

A real Sigstore **staging** Fulcio leaf that **embeds a Signed Certificate
Timestamp**, plus the matching **staging** CT-log key — used by
`tests/staging_sct_vector.rs` to prove embedded-SCT verification
(`sct::verify_embedded_sct`, RFC 6962 §3.2) in the **staging** environment,
the same-environment counterpart to `fulcio-gha/`'s production proof.

This closes the "no staging CT-log key" gap: the 2022 `fulcio-staging/` leaf
predates staging SCT embedding (it carries none — see `sct_vector.rs`'s
`reports_sct_missing_on_a_cert_without_one`), so a staging SCT proof needed a
**recent** staging leaf captured fresh.

## Provenance

Captured 2026-06-09 from public staging Rekor (`rekor.sigstage.dev`) at
global `logIndex = 54783963` — a `hashedrekord` whose certificate is a
genuine staging Fulcio signing leaf. The CT-log key is from the staging
`trusted_root.json` (sigstore/root-signing-staging TUF target).

## Files

- **`leaf-cert.pem`** — a real staging Fulcio **leaf**:
  - Public key: **ECDSA P-256**.
  - SAN: `email:sigstore-staging-prometheus-sa@projectsigstore-staging.iam.gserviceaccount.com`
    (critical); OIDC issuer `https://accounts.google.com` (a Google
    service-account identity).
  - An **embedded SCT** (`1.3.6.1.4.1.11129.2.4.2`, one SCT, CT-log id
    `3e607153…a6b6`, ECDSA-P256) — verified against `ctlog-pubkey.pem`.
  - Validity: `2026-06-09 20:09:12Z .. 20:19:12Z` — a real ~10-minute
    Fulcio ephemeral window.
  - Issuer: the staging Fulcio `sigstore-intermediate`; its AKI equals the
    intermediate's SKI in `../fulcio-staging/root-chain.pem` (staging Fulcio
    has not rotated its intermediate since 2022), so the test **reuses** that
    chain rather than duplicating it.
- **`ctlog-pubkey.pem`** — the staging CT-log public key (ECDSA P-256 SPKI,
  the log active from 2026-01-14) whose `SHA-256(SPKI)` equals the SCT's
  CT-log id `3e607153…a6b6` (verified at capture). Used to verify the
  embedded SCT signature.

## Why this is safe to commit

These are **public** X.509 / CT-log key material (no private keys), already
published in the Sigstore staging CT + Rekor transparency logs, and the leaf
is an already-**expired** 10-minute ephemeral. The SCT proof is a frozen
cryptographic fact, so the test needs no network and no live clock.

These vectors are **staging**, never production.
