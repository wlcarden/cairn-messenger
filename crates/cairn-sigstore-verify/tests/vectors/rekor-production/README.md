# Rekor production verification vectors (D0042 §5 / §7)

Real, attacker-**unforgeable** data captured from the public Sigstore
**production** transparency log — the production counterpart to
`rekor-staging/`, completing the production Fulcio + CT + Rekor anchor
triple. Verified **offline** by `tests/rekor_production_vector.rs`.

| File                            | Provenance                                                                                                                                                                                                                                                                                                            |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `log-publickey.pem`             | `GET https://rekor.sigstore.dev/api/v1/log/publicKey` (2026-06-09). ECDSA **P-256** SPKI — the key that signs each production shard's C2SP checkpoint.                                                                                                                                                                |
| `entry-logindex1767842880.json` | `GET https://rekor.sigstore.dev/api/v1/log/entries?logIndex=1767842880` (2026-06-09). The same GHA signing event whose cert is `fulcio-gha/leaf-cert.pem` — a `hashedrekord` with its RFC 6962 inclusion proof (a **25-node** audit path) + the signed checkpoint. `treeSize=1648242788`, `rootHash=9469bb46…181d1c`. |

Unlike the staging vector (a frozen _inactive_ shard), this entry is in an
**active** shard — but an inclusion proof against the captured `treeSize`
is a frozen cryptographic fact (the Merkle root at that size is immutable),
so the proof remains verifiable permanently with no network at test time.

## Why this is safe to commit

These are **public** transparency-log artifacts (a public log key + a
public inclusion proof for an already-logged entry) — no private key
material, no secrets. The proof is a permanent cryptographic fact.

To re-capture, refetch both files for any production entry and update the
expected `treeSize` in the test.
