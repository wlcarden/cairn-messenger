# Fulcio GitHub Actions test vectors

Real certificates captured from the **production** Sigstore transparency
log, used to prove the verifier against a genuine GitHub Actions keyless
certificate — the CI signing identity Cairn's own releases will use (D0042
§2). This is the production counterpart to `fulcio-staging/` and the
identity counterpart to the developer-email staging leaf.

## Provenance

Captured from production Rekor (`rekor.sigstore.dev`) at global
`logIndex = 1767842880` — a `hashedrekord` entry whose certificate is a
GitHub Actions keyless signing leaf. The Fulcio chain + CT-log key are from
the Sigstore production `trusted_root.json` (the sigstore/root-signing
TUF target).

## Files

- **`leaf-cert.pem`** — a real GitHub Actions keyless **leaf** signing
  certificate:
  - Public key: **ECDSA P-256**.
  - SAN: a `uniformResourceIdentifier` (NO email) — the workflow identity
    `https://github.com/chainguard-dev/mono/.github/workflows/.terraform.yaml@refs/tags/v0.2.278`.
  - OIDC issuer extension `1.3.6.1.4.1.57264.1.1` =
    `https://token.actions.githubusercontent.com` (the GitHub Actions OIDC
    issuer), plus the full GitHub claim set (`57264.1.2`–`1.15`).
  - `KeyUsage: digitalSignature`, `ExtendedKeyUsage: codeSigning`,
    `CA:FALSE`.
  - An **embedded Signed Certificate Timestamp** (`1.3.6.1.4.1.11129.2.4.2`,
    one SCT, CT-log ID `dd3d306a…`, ECDSA-P256) — the proof that the cert
    was published to the CT log. The SCT-verification path (D0042 §6.5)
    checks it against `ctlog-pubkey.pem`.
  - Validity: `2026-06-09 15:49:05Z .. 15:59:05Z` — a real ~10-minute
    Fulcio ephemeral window; the tests pin the signing time inside it.
- **`fulcio-chain.pem`** — the production Fulcio CA chain the leaf is
  issued under: the `sigstore-intermediate` intermediate + the `sigstore`
  self-signed root, so the leaf exercises the **3-level** chain walk
  (leaf → intermediate → root).
- **`ctlog-pubkey.pem`** — the production CT-log public key (ECDSA P-256
  SPKI) whose `SHA-256(SPKI)` equals the SCT's CT-log ID `dd3d306a…`. Used
  to verify the embedded SCT signature.

## Why this is safe to commit

These are **public** X.509 certificates + a public CT-log key (no private
key material), already published in the Sigstore CT + Rekor transparency
logs, and the leaf is an already-**expired** 10-minute ephemeral. The
proof is a frozen cryptographic fact, so the tests need no network and no
live clock.
