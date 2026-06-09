# Rekor staging verification vectors (D0042 §7 / phase-2 "2a")

Real, attacker-**unforgeable** data captured once from the public Sigstore
**staging** transparency log, used to prove `cairn-sigstore-verify`'s Rekor
verifier against genuine log data (not synthetic fixtures). Verified
**offline** — the inclusion proof + signed checkpoint are a frozen
cryptographic fact ("at tree size 461, this leaf was included, signed by the
Rekor staging key"), so the vectors need no network at test time and remain
verifiable permanently.

| File                   | Provenance                                                                                                                                                                                                                                                                         |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `log-publickey.pem`    | `GET https://rekor.sigstage.dev/api/v1/log/publicKey` (2026-06-09). ECDSA **P-256** SPKI — the key that signs every shard's checkpoint.                                                                                                                                            |
| `entry-logindex1.json` | `GET https://rekor.sigstage.dev/api/v1/log/entries/7c578cc0…f103eb5762530e49c0354` (2026-06-09). A `hashedrekord` entry in the **inactive** (frozen) shard `8959784741570461564`, in-shard `logIndex=1`, `treeSize=461`, `rootHash=ed4cb79f…53221ba`, `integratedTime=1650566621`. |

The inactive shard is permanently frozen, so the proof against size 461 is
stable. Consumed by `tests/rekor_staging_vector.rs`.

To re-capture (e.g. after a staging reset), pick any entry and refetch both
files; update the expected `treeSize` / `rootHash` in the test.
