# Fulcio staging test vectors

Real certificates captured from the Sigstore **staging** Fulcio CA
(`fulcio.sigstage.dev`), used by `tests/fulcio_staging_vector.rs` to prove
the Fulcio path-validator + B-model P-256 key extraction (D0042 §3) accept
a genuine, attacker-unforgeable keyless certificate — not just synthetic
rcgen fixtures.

## Files

- **`leaf-cert.pem`** — a genuine Fulcio keyless **leaf** (signing)
  certificate. Properties the test pins against:
  - Public key: **ECDSA P-256** (`id-ecPublicKey`, `prime256v1`) — the
    empirical basis for the B-model's P-256 verifier (D0042 §3).
  - SAN: `email:kleung@chainguard.dev` (critical).
  - OIDC issuer extension `1.3.6.1.4.1.57264.1.1` = `google-sigstore-prod`.
  - `KeyUsage: digitalSignature` (critical), `ExtendedKeyUsage:
codeSigning`, `BasicConstraints: CA:FALSE` — the RFC 5280 leaf
    constraints the validator enforces (D0041 §6.1).
  - Validity: `2022-04-21 18:43:37Z .. 18:53:36Z` — a real ~10-minute
    Fulcio ephemeral window. The test pins the signing time inside it.
- **`root-chain.pem`** — the staging Fulcio trust bundle the leaf chains
  to (the self-signed `O=sigstore.dev, CN=sigstore` root plus the
  `sigstore-intermediate`). Passed to `validate_cert_chain` as the pinned
  root PEM.

## Why this is safe to commit

These are **public** X.509 certificates (no private key material), and the
leaf is already **expired** (2022). Nothing here is a secret, and the
proof is a frozen cryptographic fact: the chain signature, OIDC pins, and
P-256 SPKI are fixed, so the test needs no network and no live clock.

These vectors are **staging**, never production. Phase 3 (D0042) swaps the
pinned roots + OIDC identity for the project's real production values via
configuration, not a code change.
