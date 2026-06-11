# Changelog

Notable changes to Cairn are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Cairn uses semantic
versioning; the release procedure (build, out-of-band signing, publish) is in
[`docs/runbooks/release.md`](docs/runbooks/release.md).

## [Unreleased]

_No changes yet since 0.1.0._

## [0.1.0] - 2026-06-11

The first **pilot pre-release** — alpha and pre-audit, built for a closed
10–15 user pilot on GrapheneOS-on-Pixel. **Do not rely on it for safety yet**;
see the [README](README.md) status banner and
[`docs/implementation-status.md`](docs/implementation-status.md) for the honest
per-feature reconciliation.

### Added

- First signed APK (arm64-v8a; GrapheneOS-on-Pixel target), built and signed
  out-of-band per [`docs/runbooks/release.md`](docs/runbooks/release.md).
- Rust cryptographic + protocol core (15-crate workspace): three-tier identity,
  a trust graph with cascade-quarantine, Shamir-among-peers social recovery,
  canonical-CBOR / COSE envelopes, Tor transport, the SimpleX adapter, and the
  release-verification stack (partial; see Known limitations).
- Kotlin/Compose Android shell over the core via UniFFI, bundling Tor and the
  SimpleX runtime. An end-to-end message round-trip has been demonstrated on two
  physical GrapheneOS Pixels over bundled Tor.

### Known limitations

- Several individual defenses are PARTIAL; the pre-pilot audit (D0011) has not
  been performed.
- The on-device release verifier is not yet wired into the install / update
  path. Until it is, the installer must verify a downloaded APK MANUALLY: check
  the published SHA-256 checksum and compare the signing-certificate fingerprint
  against the value distributed out-of-band (see Installing in the README).
- Sigsum transparency anchoring runs against synthetic roots; the production log
  and witness pool are funding-gated.

[Unreleased]: https://github.com/wlcarden/cairn-messenger/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/wlcarden/cairn-messenger/releases/tag/v0.1.0
