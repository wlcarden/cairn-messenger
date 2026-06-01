// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// CLI exceptions to workspace lints (which target library discipline):
// - `disallowed_macros`: the workspace forbids `println!` / `eprintln!`
//   in library code per D0018 §4.3 logging discipline. cairn-cli IS the
//   user-facing surface; stdout/stderr ARE the output channels.
// - `print_stdout` / `print_stderr`: same rationale — CLI output is
//   intentional, not accidental leak.
// - `unwrap_used`: the binary uses `expect` / `?` for error propagation
//   through anyhow.
#![allow(
    clippy::disallowed_macros,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used
)]

//! # cairn-cli
//!
//! Minimum-demoable-capability CLI composing `cairn-crypto` +
//! `cairn-identity` into a runnable binary that exercises the v1
//! capability-token flow end-to-end per D0006 §9.
//!
//! ## Subcommands
//!
//! ### Key + token management
//!
//! - `gen-key` — generate a fresh Ed25519 seed (32 bytes), write to a
//!   file. The seed is the operational-identity OR device-key
//!   secret material.
//! - `pubkey` — read a seed file, derive the 32-byte Ed25519 public
//!   key, print it in hex.
//! - `issue-token` — build a `CapabilityToken` from an issuer seed
//!   (operational identity), a subject public key (device key), a
//!   comma-separated scope list, and an expiry timestamp. Signs the
//!   token via `Sign1Builder` and writes the bytes to a file.
//! - `verify-token` — read a token envelope file + expected-issuer
//!   pubkey file, decode + verify via
//!   `SignedCapabilityToken::from_bytes`. Prints scope + expiry +
//!   subject pubkey on success.
//!
//! ### Message signing (hops #1 + #2 of D0006 §9)
//!
//! - `sign-message` — sign an arbitrary payload (text or file) with
//!   a device key, producing a `COSE_Sign1` envelope. Supports
//!   `--external-aad` for protocol binding per RFC 9052 §4.4.
//! - `verify-message` — verify a message envelope against a
//!   capability token + expected issuer pubkey. Order of checks
//!   defends against subject-substitution: verify the token first
//!   so the embedded subject pubkey is trusted, THEN verify the
//!   message against that subject. Optionally checks that the
//!   token's scope contains a `--required-capability`.
//!
//! ## Discipline notes
//!
//! - Seed I/O routes through `Zeroizing` buffers — seed bytes never
//!   sit in unwrapped `Vec<u8>` longer than the read syscall.
//! - The CLI exits with non-zero status on verification failure so
//!   shell pipelines can detect rejection without parsing stdout.
//! - Pubkey files contain raw 32-byte Ed25519 public-key bytes (no
//!   header / no encoding); same for seed files. This keeps the
//!   on-disk format trivially auditable in `xxd`-style hex dumps.
//! - Token envelope files contain raw `COSE_Sign1` CBOR bytes
//!   (untagged 4-tuple, per `cairn-envelope::cose_sign1`'s default).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, SEED_LEN, SigningKey, VerifyingKey};
use cairn_envelope::cose_sign1::{CoseSign1, Sign1Builder};
use cairn_identity::{CapabilityToken, SignedCapabilityToken};
use cairn_recovery::{SignedMasterAttestation, reconstruct_and_attest};
use cairn_shamir::{COMMITMENT_LEN, Commitment, SECRET_LEN, Share, reconstruct, split};
use cairn_simplex_adapter::{
    ConnectionId, Invitation, LocalIdentity, RetryBudget, SidecarTransport, SimplexAdapter,
    SimplexAdapterConfig, SimplexAdapterError,
};
use cairn_storage::Storage;
use cairn_storage::key_provider::testing::InMemoryKeyProvider;
use cairn_trust_graph::{
    OpType, QuarantineStatus, SignedTrustGraphOp, TrustGraphOp, compute_quarantine_state,
    verify_chain_links,
};
use clap::{Parser, Subcommand, ValueEnum};
use rand_core::OsRng;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(name = "cairn", version, about = "Cairn capability-token CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a fresh Ed25519 seed (32 bytes) and write to a file.
    GenKey {
        /// Output path for the 32-byte seed file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the public key for a seed file (hex on stdout).
    Pubkey {
        /// Path to the 32-byte seed file.
        #[arg(long)]
        key: PathBuf,
    },
    /// Issue a capability token authorizing the subject pubkey within
    /// the named scope until the expiry timestamp.
    IssueToken {
        /// Path to the issuer's 32-byte seed file (operational
        /// identity).
        #[arg(long)]
        issuer_key: PathBuf,
        /// Path to the subject's 32-byte public-key file (device
        /// key).
        #[arg(long)]
        subject_pubkey: PathBuf,
        /// Comma-separated capability strings (e.g.
        /// `messaging:send,trust-graph:attest`).
        #[arg(long)]
        scope: String,
        /// Unix-seconds expiry timestamp.
        #[arg(long)]
        expiry: u64,
        /// Output path for the `COSE_Sign1` envelope bytes.
        #[arg(long)]
        out: PathBuf,
    },
    /// Decode and verify a token envelope against an expected issuer
    /// pubkey. Prints scope + expiry + subject pubkey on success.
    VerifyToken {
        /// Path to the `COSE_Sign1` envelope bytes.
        #[arg(long)]
        envelope: PathBuf,
        /// Path to the expected issuer's 32-byte pubkey file.
        #[arg(long)]
        expected_issuer_pubkey: PathBuf,
    },
    /// Sign a message payload with a device key, producing a
    /// `COSE_Sign1` envelope. This is hop #1 of the D0006 §9 chain;
    /// pair with a capability token (from `issue-token`) at verify
    /// time.
    SignMessage {
        /// Path to the device key's 32-byte seed file.
        #[arg(long)]
        device_key: PathBuf,
        /// Message payload (UTF-8 text). For binary payloads use
        /// `--payload-file`.
        #[arg(long, conflicts_with = "payload_file")]
        payload: Option<String>,
        /// Path to a file containing the raw message payload bytes.
        #[arg(long, conflicts_with = "payload")]
        payload_file: Option<PathBuf>,
        /// External AAD (text) bound into the signature input per
        /// RFC 9052 §4.4. Both signer and verifier must supply the
        /// same value out-of-band; default is empty.
        #[arg(long, default_value = "")]
        external_aad: String,
        /// Output path for the message envelope bytes.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a message envelope against a capability token (per
    /// D0006 §9 hops #1 + #2). Order: verify the token first so the
    /// embedded subject pubkey is trusted, then verify the message
    /// against that subject pubkey. Optionally checks that the
    /// token's scope authorizes a named capability.
    VerifyMessage {
        /// Path to the message `COSE_Sign1` envelope.
        #[arg(long)]
        message: PathBuf,
        /// Path to the capability-token envelope (from
        /// `issue-token`).
        #[arg(long)]
        token: PathBuf,
        /// Path to the expected token-issuer's pubkey (operational
        /// identity).
        #[arg(long)]
        expected_issuer_pubkey: PathBuf,
        /// External AAD (text) supplied at sign time. Must match.
        #[arg(long, default_value = "")]
        external_aad: String,
        /// Optional capability string the token must authorize.
        #[arg(long)]
        required_capability: Option<String>,
    },
    /// Send a Cairn message envelope over a local file "wire" (D0026 §12
    /// step 6 demo — no `SimpleX` sidecar). Builds → signs → pads →
    /// persists, and writes the `COSE_Sign1` envelope bytes to the wire
    /// file. For the demo the sender's seed doubles as device key +
    /// operational identity.
    SimplexSend {
        /// 32-byte seed file: the sender's device key (also the
        /// operational identity for this demo).
        #[arg(long)]
        sender_seed: PathBuf,
        /// 32-byte pubkey file: the recipient's operational identity.
        #[arg(long)]
        recipient_pubkey: PathBuf,
        /// The message text to send (UTF-8).
        #[arg(long)]
        message: String,
        /// Output path for the wire envelope bytes.
        #[arg(long)]
        out: PathBuf,
    },
    /// Receive + verify a Cairn message envelope from a local file "wire"
    /// (the `simplex-send` counterpart). Verifies the `COSE_Sign1`
    /// signature + AAD domain tag, binds the sender to the expected
    /// operational identity, checks the prior-envelope-hash chain, and
    /// strips padding.
    SimplexRecv {
        /// 32-byte seed file: the recipient's device key (== operational
        /// identity for the demo).
        #[arg(long)]
        recipient_seed: PathBuf,
        /// 32-byte pubkey file: the expected sender (its operational
        /// identity, also used as the device verifying key for the demo).
        #[arg(long)]
        sender_pubkey: PathBuf,
        /// The wire envelope file written by `simplex-send`.
        #[arg(long)]
        wire: PathBuf,
    },
    /// Split a 32-byte seed into Shamir shares per D0006 §9. Writes
    /// N share files (`<prefix>-share-NN.bin`, each 33 bytes:
    /// 1 id byte + 32 share-value bytes) plus a commitment file
    /// (`<prefix>-commitment.bin`, 32 bytes BLAKE3).
    SplitSeed {
        /// Path to the 32-byte seed file to split.
        #[arg(long)]
        seed: PathBuf,
        /// Recovery threshold (`k` in k-of-n). Must be `>= 2`.
        #[arg(long)]
        threshold: u8,
        /// Total number of shares (`n` in k-of-n). Must be
        /// `>= threshold` and `<= 255`.
        #[arg(long)]
        num_shares: u8,
        /// Output filename prefix. Files written:
        /// `<prefix>-share-01.bin`, ..., `<prefix>-share-NN.bin`,
        /// `<prefix>-commitment.bin`.
        #[arg(long)]
        out_prefix: PathBuf,
    },
    /// Reconstruct a 32-byte seed from threshold-many Shamir share
    /// files + a commitment file. The BLAKE3 commitment check
    /// rejects corrupted / malicious / insufficient shares
    /// uniformly per D0018 §3.4.
    ReconstructSeed {
        /// Path to a share file (33 bytes). May be supplied
        /// multiple times.
        #[arg(long = "share", action = clap::ArgAction::Append)]
        shares: Vec<PathBuf>,
        /// Path to the commitment file (32 bytes BLAKE3) emitted
        /// alongside the shares at split time.
        #[arg(long)]
        commitment: PathBuf,
        /// Output path for the recovered 32-byte seed.
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a trust-graph operation (`attest` / `revoke-withdraw` /
    /// `revoke-compromise` / `re-attest`) per D0006 §2. Signed by
    /// the device key under a capability token authorizing the
    /// required scope.
    TrustOp {
        /// Operation kind.
        #[arg(long, value_enum)]
        kind: TrustOpKind,
        /// Path to the device's 32-byte seed file.
        #[arg(long)]
        device_key: PathBuf,
        /// Path to the operational identity's 32-byte pubkey
        /// (becomes the op's `issuer` field).
        #[arg(long)]
        issuer_pubkey: PathBuf,
        /// Path to the subject peer's 32-byte pubkey.
        #[arg(long)]
        subject_pubkey: PathBuf,
        /// Unix-seconds when the op is issued.
        #[arg(long)]
        timestamp: u64,
        /// Path to a file containing the prior-hash bytes (zero
        /// length for genesis ops).
        #[arg(long)]
        prior_hash: PathBuf,
        /// Path to a file containing the issuer-cert-hash bytes
        /// (typically the BLAKE3 of the capability token envelope).
        #[arg(long)]
        cert_hash: PathBuf,
        /// `revoked_as_of` Unix-seconds (`revoke-compromise` only).
        #[arg(long)]
        revoked_as_of: Option<u64>,
        /// Path to the `prior_revocation_ref` bytes (`re-attest`
        /// only).
        #[arg(long)]
        prior_revocation_ref: Option<PathBuf>,
        /// Output path for the trust-graph op envelope.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a trust-graph operation envelope against a capability
    /// token + expected operational identity pubkey. Demonstrates
    /// the D0006 §9 hops #1 + #2 chain for trust-graph ops.
    VerifyTrustOp {
        /// Path to the trust-graph op envelope.
        #[arg(long)]
        op: PathBuf,
        /// Path to the capability-token envelope.
        #[arg(long)]
        token: PathBuf,
        /// Path to the expected operational identity pubkey.
        #[arg(long)]
        expected_issuer_pubkey: PathBuf,
    },
    /// Reconstruct master from shares + sign an attestation of a new
    /// operational identity. The master seed is held in `Zeroizing`
    /// throughout and wiped on exit per D0006 §6.
    AttestOperationalIdentity {
        /// Path to a master share file (33 bytes). May be supplied
        /// multiple times.
        #[arg(long = "share", action = clap::ArgAction::Append)]
        shares: Vec<PathBuf>,
        /// Path to the master commitment file (32 bytes).
        #[arg(long)]
        commitment: PathBuf,
        /// Path to the new operational identity's 32-byte pubkey.
        #[arg(long)]
        new_op_identity_pubkey: PathBuf,
        /// Unix-seconds attestation timestamp.
        #[arg(long)]
        timestamp: u64,
        /// Output path for the master attestation envelope.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a master attestation envelope against an expected
    /// master pubkey (typically the one printed on the user's paper
    /// backup card).
    VerifyMasterAttestation {
        /// Path to the master attestation envelope.
        #[arg(long)]
        attestation: PathBuf,
        /// Path to the expected master pubkey (32 bytes).
        #[arg(long)]
        expected_master_pubkey: PathBuf,
    },
    /// Compute the canonical D0006 §5 `prior_hash` for a trust-graph op
    /// envelope: `SHA-256( COSE_Sign1.signature_bytes( op ) )`. Writes
    /// 32 raw bytes to the output file (suitable for direct use as
    /// `--prior-hash` on the next op in the chain). Also prints the
    /// hex form to stdout for inspection.
    ComputePriorHash {
        /// Path to the trust-graph op envelope.
        #[arg(long)]
        op: PathBuf,
        /// Output path for the 32-byte SHA-256 hash.
        #[arg(long)]
        out: PathBuf,
    },
    /// Compute the canonical D0006 §7 `issuer_cert_hash` for a master
    /// attestation envelope:
    /// `SHA-256( deterministic_cbor_encode( Sig_structure ) )`. Writes
    /// 32 raw bytes to the output file (suitable for direct use as
    /// `--cert-hash` on a trust-graph op or as the chain reference
    /// on a capability token). Prints the hex form to stdout.
    ComputeIssuerCertHash {
        /// Path to the master attestation envelope.
        #[arg(long)]
        attestation: PathBuf,
        /// Output path for the 32-byte SHA-256 hash.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a sequence of trust-graph op envelopes as a single
    /// chain per D0006 §2 + §5. Each op is verified individually via
    /// `verify-trust-op` semantics (hops #1 + #2), plus the chain
    /// structure is checked: genesis op has empty `prior_hash`; each
    /// non-genesis op's `prior_hash` equals `SHA-256(prior op
    /// signature)`; all ops share the same `(issuer, subject)` pair;
    /// timestamps are non-decreasing.
    VerifyTrustChain {
        /// Path to a trust-graph op envelope. Supply once per op in
        /// chain order (`ops[0]` = genesis, `ops[N-1]` = chain head).
        #[arg(long = "op", action = clap::ArgAction::Append)]
        ops: Vec<PathBuf>,
        /// Path to the capability-token envelope authorizing the
        /// device that signed the ops.
        #[arg(long)]
        token: PathBuf,
        /// Path to the expected operational identity pubkey.
        #[arg(long)]
        expected_issuer_pubkey: PathBuf,
    },
    /// Decode a heterogeneous set of trust-graph op envelopes (across
    /// multiple operational identities) and print the D0006 §2
    /// cascade-quarantine status of each. The classifier is stateless:
    /// `CompromiseRevoke` cascades hard-suspend post-revocation
    /// attestations + soft-flag pre-revocation attestations of the
    /// revoked subject; `WithdrawRevoke` soft-flags post-withdrawal
    /// attestations.
    ///
    /// IMPORTANT: this command DECODES without verifying per-op
    /// signatures (the op set spans multiple operational identities so
    /// no single token suffices for verification). Callers should
    /// verify each chain via `verify-trust-chain` before trusting the
    /// classification output here.
    InspectTrustState {
        /// Path to a trust-graph op envelope. Supply once per op in
        /// the set being inspected.
        #[arg(long = "op", action = clap::ArgAction::Append)]
        ops: Vec<PathBuf>,
    },
}

/// Variant flag for the `trust-op` subcommand.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum TrustOpKind {
    /// Issuer claims a trust relationship with the subject peer.
    Attest,
    /// Issuer cleanly withdraws their previous attestation; no
    /// cascade.
    RevokeWithdraw,
    /// Issuer revokes due to compromise; triggers cascade
    /// quarantine. Requires `--revoked-as-of`.
    RevokeCompromise,
    /// Post-revocation re-attestation. Requires
    /// `--prior-revocation-ref`.
    ReAttest,
}

impl From<TrustOpKind> for OpType {
    fn from(kind: TrustOpKind) -> Self {
        match kind {
            TrustOpKind::Attest => Self::Attest,
            TrustOpKind::RevokeWithdraw => Self::WithdrawRevoke,
            TrustOpKind::RevokeCompromise => Self::CompromiseRevoke,
            TrustOpKind::ReAttest => Self::ReAttest,
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "main() is a flat dispatch over the Command enum; collapsing arms into a \
              helper just adds indirection — each arm calls one cmd_ function"
)]
fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::GenKey { out } => cmd_gen_key(&out),
        Command::Pubkey { key } => cmd_pubkey(&key),
        Command::IssueToken {
            issuer_key,
            subject_pubkey,
            scope,
            expiry,
            out,
        } => cmd_issue_token(&issuer_key, &subject_pubkey, &scope, expiry, &out),
        Command::VerifyToken {
            envelope,
            expected_issuer_pubkey,
        } => cmd_verify_token(&envelope, &expected_issuer_pubkey),
        Command::SignMessage {
            device_key,
            payload,
            payload_file,
            external_aad,
            out,
        } => cmd_sign_message(
            &device_key,
            payload.as_deref(),
            payload_file.as_ref(),
            &external_aad,
            &out,
        ),
        Command::VerifyMessage {
            message,
            token,
            expected_issuer_pubkey,
            external_aad,
            required_capability,
        } => cmd_verify_message(
            &message,
            &token,
            &expected_issuer_pubkey,
            &external_aad,
            required_capability.as_deref(),
        ),
        Command::SimplexSend {
            sender_seed,
            recipient_pubkey,
            message,
            out,
        } => cmd_simplex_send(&sender_seed, &recipient_pubkey, &message, &out),
        Command::SimplexRecv {
            recipient_seed,
            sender_pubkey,
            wire,
        } => cmd_simplex_recv(&recipient_seed, &sender_pubkey, &wire),
        Command::SplitSeed {
            seed,
            threshold,
            num_shares,
            out_prefix,
        } => cmd_split_seed(&seed, threshold, num_shares, &out_prefix),
        Command::ReconstructSeed {
            shares,
            commitment,
            out,
        } => cmd_reconstruct_seed(&shares, &commitment, &out),
        Command::TrustOp {
            kind,
            device_key,
            issuer_pubkey,
            subject_pubkey,
            timestamp,
            prior_hash,
            cert_hash,
            revoked_as_of,
            prior_revocation_ref,
            out,
        } => cmd_trust_op(
            kind,
            &device_key,
            &issuer_pubkey,
            &subject_pubkey,
            timestamp,
            &prior_hash,
            &cert_hash,
            revoked_as_of,
            prior_revocation_ref.as_ref(),
            &out,
        ),
        Command::VerifyTrustOp {
            op,
            token,
            expected_issuer_pubkey,
        } => cmd_verify_trust_op(&op, &token, &expected_issuer_pubkey),
        Command::AttestOperationalIdentity {
            shares,
            commitment,
            new_op_identity_pubkey,
            timestamp,
            out,
        } => cmd_attest_operational_identity(
            &shares,
            &commitment,
            &new_op_identity_pubkey,
            timestamp,
            &out,
        ),
        Command::VerifyMasterAttestation {
            attestation,
            expected_master_pubkey,
        } => cmd_verify_master_attestation(&attestation, &expected_master_pubkey),
        Command::ComputePriorHash { op, out } => cmd_compute_prior_hash(&op, &out),
        Command::ComputeIssuerCertHash { attestation, out } => {
            cmd_compute_issuer_cert_hash(&attestation, &out)
        }
        Command::VerifyTrustChain {
            ops,
            token,
            expected_issuer_pubkey,
        } => cmd_verify_trust_chain(&ops, &token, &expected_issuer_pubkey),
        Command::InspectTrustState { ops } => cmd_inspect_trust_state(&ops),
    }
}

/// Generate a fresh Ed25519 seed and write the 32 bytes to `out`.
///
/// `SigningKey` doesn't expose its inner seed (by design — `SecretBox`
/// discipline). For CLI use we generate seed bytes directly via
/// `OsRng`, then sanity-check by constructing a `SigningKey` from the
/// seed before writing to disk.
fn cmd_gen_key(out: &PathBuf) -> Result<()> {
    use rand_core::RngCore as _;
    let mut rng = OsRng;
    let mut seed_arr = [0u8; SEED_LEN];
    rng.fill_bytes(&mut seed_arr);
    let seed = Zeroizing::new(seed_arr);

    // Sanity check: the seed must produce a valid signing key.
    let _ = SigningKey::from_seed(&seed);

    std::fs::write(out, seed.as_ref())
        .with_context(|| format!("failed to write seed to {}", out.display()))?;
    eprintln!("Wrote 32-byte Ed25519 seed to {}", out.display());
    Ok(())
}

/// Read a seed file and print the derived public key as hex.
fn cmd_pubkey(key: &PathBuf) -> Result<()> {
    let seed = read_seed(key)?;
    let sk = SigningKey::from_seed(&seed);
    let vk = sk.verifying_key();
    let pubkey_bytes = vk.to_bytes();
    println!("{}", hex_encode(&pubkey_bytes));
    Ok(())
}

/// Build a capability token, sign it, and write the envelope.
fn cmd_issue_token(
    issuer_key: &PathBuf,
    subject_pubkey: &PathBuf,
    scope: &str,
    expiry: u64,
    out: &PathBuf,
) -> Result<()> {
    let issuer_seed = read_seed(issuer_key)?;
    let issuer_signing_key = SigningKey::from_seed(&issuer_seed);
    let issuer_verifying_key = issuer_signing_key.verifying_key();

    let subject_verifying_key = read_pubkey(subject_pubkey)?;

    let scope_strs: Vec<String> = scope
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if scope_strs.is_empty() {
        bail!("scope must contain at least one capability string");
    }

    let token = CapabilityToken::new(
        issuer_verifying_key,
        subject_verifying_key,
        scope_strs.clone(),
        expiry,
        // No chain-to-master at this CLI surface; higher layers will
        // populate it. v1 demo accepts empty.
        Vec::new(),
    );
    let signed = token
        .sign(&issuer_signing_key)
        .map_err(|e| anyhow!("token sign failed: {e}"))?;
    let bytes = signed
        .encode(false)
        .map_err(|e| anyhow!("envelope encode failed: {e}"))?;

    std::fs::write(out, &bytes)
        .with_context(|| format!("failed to write envelope to {}", out.display()))?;

    eprintln!(
        "Issued token: {} bytes, {} capabilities, expiry={}",
        bytes.len(),
        scope_strs.len(),
        expiry
    );
    eprintln!("Wrote envelope to {}", out.display());
    Ok(())
}

/// Verify a token envelope; print scope + expiry + subject on success.
fn cmd_verify_token(envelope: &PathBuf, expected_issuer_pubkey: &PathBuf) -> Result<()> {
    let envelope_bytes = std::fs::read(envelope)
        .with_context(|| format!("failed to read envelope from {}", envelope.display()))?;
    let issuer_vk = read_pubkey(expected_issuer_pubkey)?;

    let signed = SignedCapabilityToken::from_bytes(&envelope_bytes, &issuer_vk)
        .map_err(|e| anyhow!("verification failed: {e}"))?;

    let token = signed.token();
    println!("VERIFIED");
    println!("issuer-pubkey:  {}", hex_encode(&token.issuer.to_bytes()));
    println!("subject-pubkey: {}", hex_encode(&token.subject.to_bytes()));
    println!(
        "expiry:         {} (Unix seconds)",
        token.expiry_unix_seconds
    );
    println!("scope:");
    for cap in &token.scope {
        println!("  - {cap}");
    }
    if !token.signature_chain_to_master.is_empty() {
        println!(
            "chain-to-master: {} bytes (NOT verified at this layer — see D0006 §9)",
            token.signature_chain_to_master.len()
        );
    }
    Ok(())
}

/// A file-backed [`SidecarTransport`] for the local messaging demo
/// (D0026 §12 step 6): the "wire" is a single file. `send` writes the
/// opaque (signed + padded) envelope bytes; `recv` reads them back.
/// Single-message (number 0); the production `SimploxideTransport`
/// (D0026 §12) carries multi-message streams over the `SimpleX` WebSocket.
/// No `SimpleX` sidecar is needed — this exercises everything ABOVE the
/// network hop.
struct FileSidecarTransport {
    wire: PathBuf,
}

impl SidecarTransport for FileSidecarTransport {
    async fn create_invitation(&self) -> Result<Invitation, SimplexAdapterError> {
        Ok(Invitation {
            uri: "cairn-cli://file-wire".to_string(),
        })
    }

    async fn accept_invitation(
        &self,
        _invitation: Invitation,
    ) -> Result<ConnectionId, SimplexAdapterError> {
        Ok(ConnectionId("file-wire".to_string()))
    }

    async fn await_connection(&self) -> Result<ConnectionId, SimplexAdapterError> {
        // The file wire is immediately "established".
        Ok(ConnectionId("file-wire".to_string()))
    }

    async fn send(&self, _conn: &ConnectionId, raw: &[u8]) -> Result<(), SimplexAdapterError> {
        // Per D0026 §3.2 (c) the seam carries no message number — the adapter
        // owns the per-pair chain position. The file wire just stores bytes.
        std::fs::write(&self.wire, raw).map_err(|_| SimplexAdapterError::SidecarUnavailable)?;
        Ok(())
    }

    async fn recv(&self, _conn: &ConnectionId) -> Result<Vec<u8>, SimplexAdapterError> {
        std::fs::read(&self.wire).map_err(|_| SimplexAdapterError::SidecarUnavailable)
    }
}

/// Open an in-memory demo store (the `InMemoryKeyProvider` uses reduced
/// Argon2id parameters). The CLI demo does not persist across runs — the
/// envelope crosses between `simplex-send` and `simplex-recv` via the
/// wire file, and each side's `prior_envelope_hash` chain starts at
/// genesis (single message).
fn open_demo_storage() -> Result<Arc<Storage>> {
    let provider = InMemoryKeyProvider::new();
    let passphrase = Zeroizing::new(b"cairn-cli-simplex-demo".to_vec());
    let storage = Storage::open_in_memory(&provider, &passphrase)
        .map_err(|e| anyhow!("failed to open demo storage: {e:?}"))?;
    Ok(Arc::new(storage))
}

/// Send a Cairn message envelope over a local file wire (D0026 §12 step 6).
///
/// Demo simplification: the sender's seed doubles as the device signing
/// key AND the operational identity (production separates them — the
/// device key signs, the operational identity is the envelope sender per
/// D0006 §9). Signing routes through `cairn_simplex_adapter::EnvelopeSigner`
/// over the software `SigningKey` — the same seam the Android FFI handle
/// drives in `StrongBox`.
fn cmd_simplex_send(
    sender_seed: &PathBuf,
    recipient_pubkey: &PathBuf,
    message: &str,
    out: &Path,
) -> Result<()> {
    let seed = read_seed(sender_seed)?;
    let device_signing_key = SigningKey::from_seed(&seed);
    let operational_pubkey = device_signing_key.verifying_key().to_bytes();
    let recipient = read_pubkey(recipient_pubkey)?.to_bytes();

    let config = SimplexAdapterConfig {
        identity: LocalIdentity {
            device_signer: Arc::new(device_signing_key),
            operational_pubkey,
        },
        storage: open_demo_storage()?,
        default_retry_budget: RetryBudget::default(),
    };
    let adapter = SimplexAdapter::new(
        FileSidecarTransport {
            wire: out.to_path_buf(),
        },
        config,
    )
    .map_err(|e| anyhow!("adapter construction failed: {e:?}"))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .context("failed to build tokio runtime")?;
    let sent = runtime
        .block_on(adapter.send(
            &ConnectionId("file-wire".to_string()),
            &recipient,
            message.as_bytes(),
        ))
        .map_err(|e| anyhow!("send failed: {e:?}"))?;

    eprintln!(
        "Wrote wire envelope to {} ({}-byte message, signed + padded)",
        out.display(),
        message.len()
    );
    println!("record-id:           {}", hex_encode(&sent.record_id));
    println!("next-message-number: {}", sent.next_message_number);
    Ok(())
}

/// Receive + verify a Cairn message envelope from a local file wire (the
/// `simplex-send` counterpart). The sender's pubkey doubles as both the
/// expected operational identity AND the device verifying key for the
/// demo.
fn cmd_simplex_recv(recipient_seed: &PathBuf, sender_pubkey: &PathBuf, wire: &Path) -> Result<()> {
    let seed = read_seed(recipient_seed)?;
    let device_signing_key = SigningKey::from_seed(&seed);
    let operational_pubkey = device_signing_key.verifying_key().to_bytes();
    let sender_device_vk = read_pubkey(sender_pubkey)?;
    let sender_operational_pubkey = sender_device_vk.to_bytes();

    let config = SimplexAdapterConfig {
        identity: LocalIdentity {
            device_signer: Arc::new(device_signing_key),
            operational_pubkey,
        },
        storage: open_demo_storage()?,
        default_retry_budget: RetryBudget::default(),
    };
    let adapter = SimplexAdapter::new(
        FileSidecarTransport {
            wire: wire.to_path_buf(),
        },
        config,
    )
    .map_err(|e| anyhow!("adapter construction failed: {e:?}"))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .context("failed to build tokio runtime")?;
    let received = runtime
        .block_on(adapter.recv(
            &ConnectionId("file-wire".to_string()),
            &sender_operational_pubkey,
            &sender_device_vk,
        ))
        .map_err(|e| anyhow!("recv/verify failed: {e:?}"))?;

    println!("VERIFIED");
    println!(
        "sender-pubkey: {}",
        hex_encode(&received.sender_operational_pubkey)
    );
    println!(
        "payload:       {}",
        String::from_utf8_lossy(&received.payload)
    );
    Ok(())
}

/// Read a 32-byte Ed25519 seed from `path` with `Zeroizing` discipline.
fn read_seed(path: &PathBuf) -> Result<Zeroizing<[u8; SEED_LEN]>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read seed from {}", path.display()))?;
    if bytes.len() != SEED_LEN {
        bail!(
            "seed file {} is {} bytes (expected {})",
            path.display(),
            bytes.len(),
            SEED_LEN
        );
    }
    let mut seed_arr = [0u8; SEED_LEN];
    seed_arr.copy_from_slice(&bytes);
    Ok(Zeroizing::new(seed_arr))
}

/// Read a 32-byte Ed25519 public key from `path`.
fn read_pubkey(path: &PathBuf) -> Result<VerifyingKey> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read pubkey from {}", path.display()))?;
    if bytes.len() != PUBLIC_KEY_LEN {
        bail!(
            "pubkey file {} is {} bytes (expected {})",
            path.display(),
            bytes.len(),
            PUBLIC_KEY_LEN
        );
    }
    let mut arr = [0u8; PUBLIC_KEY_LEN];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| anyhow!("pubkey is not a valid Ed25519 curve point: {e}"))
}

/// Encode bytes as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    // `saturating_mul` to satisfy `arithmetic_side_effects`; the
    // saturate case (would-be wraparound) only happens for absurdly
    // large slices that pubkey / signature byte arrays never reach.
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("writing to String cannot fail");
    }
    s
}

/// Sign a payload with a device key, producing a `COSE_Sign1`
/// envelope. The envelope is hop #1 of the D0006 §9 verification
/// chain; it carries the device-key signature over the payload plus
/// the optional external AAD.
fn cmd_sign_message(
    device_key: &PathBuf,
    payload_text: Option<&str>,
    payload_file: Option<&PathBuf>,
    external_aad: &str,
    out: &PathBuf,
) -> Result<()> {
    let payload_bytes: Vec<u8> = match (payload_text, payload_file) {
        (Some(s), None) => s.as_bytes().to_vec(),
        (None, Some(path)) => std::fs::read(path)
            .with_context(|| format!("failed to read payload from {}", path.display()))?,
        (None, None) => bail!("either --payload or --payload-file must be supplied"),
        (Some(_), Some(_)) => bail!("--payload and --payload-file are mutually exclusive"),
    };

    let device_seed = read_seed(device_key)?;
    let device_signing_key = SigningKey::from_seed(&device_seed);

    let mut builder = Sign1Builder::new().with_payload(payload_bytes);
    if !external_aad.is_empty() {
        builder = builder.with_external_aad(external_aad.as_bytes().to_vec());
    }

    let envelope = builder
        .finalize(&device_signing_key)
        .map_err(|e| anyhow!("message sign failed: {e}"))?;
    let bytes = envelope
        .encode(false)
        .map_err(|e| anyhow!("envelope encode failed: {e}"))?;

    std::fs::write(out, &bytes)
        .with_context(|| format!("failed to write message envelope to {}", out.display()))?;

    eprintln!(
        "Signed message: {} byte envelope (payload bound to external AAD of {} bytes)",
        bytes.len(),
        external_aad.len()
    );
    eprintln!("Wrote envelope to {}", out.display());
    Ok(())
}

/// Verify a message envelope against a capability token + expected
/// issuer pubkey, demonstrating the D0006 §9 hop #1 + hop #2 chain.
///
/// Order of checks (defends against subject substitution): verify
/// the token first so the subject pubkey is trusted, THEN verify the
/// message against that pubkey.
fn cmd_verify_message(
    message: &PathBuf,
    token: &PathBuf,
    expected_issuer_pubkey: &PathBuf,
    external_aad: &str,
    required_capability: Option<&str>,
) -> Result<()> {
    // === Hop #2: verify the capability token ===
    let token_bytes = std::fs::read(token)
        .with_context(|| format!("failed to read token from {}", token.display()))?;
    let expected_issuer = read_pubkey(expected_issuer_pubkey)?;
    let signed_token = SignedCapabilityToken::from_bytes(&token_bytes, &expected_issuer)
        .map_err(|e| anyhow!("token verification failed: {e}"))?;
    let cap_token = signed_token.token();
    let device_verifying_key = cap_token.subject;

    // === Hop #1: verify the message against the token's subject ===
    let message_bytes = std::fs::read(message)
        .with_context(|| format!("failed to read message from {}", message.display()))?;
    let message_envelope = CoseSign1::from_bytes(&message_bytes)
        .map_err(|e| anyhow!("message envelope decode failed: {e}"))?;
    message_envelope
        .verify(&device_verifying_key, external_aad.as_bytes())
        .map_err(|e| anyhow!("message signature verification failed: {e}"))?;

    // === Scope check (optional) ===
    if let Some(cap) = required_capability {
        if !cap_token.has_capability(cap) {
            bail!(
                "token does not authorize the required capability: {} (token scope: {:?})",
                cap,
                cap_token.scope
            );
        }
    }

    println!("VERIFIED");
    println!(
        "token-issuer:    {}",
        hex_encode(&cap_token.issuer.to_bytes())
    );
    println!(
        "device-pubkey:   {}",
        hex_encode(&device_verifying_key.to_bytes())
    );
    println!("token-scope:");
    for c in &cap_token.scope {
        println!("  - {c}");
    }
    println!(
        "token-expiry:    {} (Unix seconds)",
        cap_token.expiry_unix_seconds
    );
    if let Some(cap) = required_capability {
        println!("required-capability: {cap} (satisfied)");
    }

    let payload = message_envelope
        .payload()
        .ok_or_else(|| anyhow!("message has no payload"))?;
    println!("payload ({} bytes):", payload.len());
    if let Ok(s) = core::str::from_utf8(payload) {
        println!("{s}");
    } else {
        // `min(4)` guarantees the slice end <= payload.len();
        // `indexing_slicing` allowed at the site since the bound is
        // statically provable.
        let preview_len = payload.len().min(4);
        #[allow(clippy::indexing_slicing)]
        let preview = &payload[..preview_len];
        println!(
            "(non-UTF-8 payload; first {preview_len} bytes hex: {})",
            hex_encode(preview)
        );
    }
    Ok(())
}

/// Split a 32-byte seed into Shamir shares + a BLAKE3 commitment.
///
/// Each share file is 33 bytes (`[id_byte, value_bytes...]`); the
/// commitment file is 32 bytes (BLAKE3-derived). File naming:
/// `<prefix>-share-NN.bin` (`NN` is zero-padded 2-digit) +
/// `<prefix>-commitment.bin`. Distribute shares to N peers per the
/// trust-graph layer; one share per peer with the commitment
/// duplicated to each.
fn cmd_split_seed(
    seed: &PathBuf,
    threshold: u8,
    num_shares: u8,
    out_prefix: &std::path::Path,
) -> Result<()> {
    let seed_bytes = read_seed(seed)?;
    let mut rng = OsRng;
    let (shares, commitment) = split(&seed_bytes, threshold, num_shares, &mut rng)
        .map_err(|e| anyhow!("Shamir split failed: {e}"))?;

    let prefix_str = out_prefix.to_string_lossy();
    for share in &shares {
        let share_path = PathBuf::from(format!("{}-share-{:02}.bin", prefix_str, share.id()));
        let mut share_bytes = [0u8; SECRET_LEN + 1];
        #[allow(clippy::indexing_slicing)]
        {
            // Statically safe: array bounds are compile-time constants.
            share_bytes[0] = share.id();
            share_bytes[1..].copy_from_slice(share.bytes());
        }
        std::fs::write(&share_path, share_bytes)
            .with_context(|| format!("failed to write share to {}", share_path.display()))?;
        eprintln!(
            "Wrote share id={} (33 bytes) to {}",
            share.id(),
            share_path.display()
        );
    }

    let commitment_path = PathBuf::from(format!("{prefix_str}-commitment.bin"));
    std::fs::write(&commitment_path, commitment.to_bytes()).with_context(|| {
        format!(
            "failed to write commitment to {}",
            commitment_path.display()
        )
    })?;
    eprintln!(
        "Wrote BLAKE3 commitment ({} bytes) to {}",
        COMMITMENT_LEN,
        commitment_path.display()
    );

    eprintln!("Split complete: {threshold} of {num_shares} shares required for reconstruction");
    Ok(())
}

/// Reconstruct a 32-byte seed from threshold-many share files +
/// the commitment file, gated on the commitment check.
fn cmd_reconstruct_seed(
    share_paths: &[PathBuf],
    commitment_path: &PathBuf,
    out: &PathBuf,
) -> Result<()> {
    if share_paths.is_empty() {
        bail!("at least one --share must be supplied");
    }

    let mut shares: Vec<Share> = Vec::with_capacity(share_paths.len());
    for path in share_paths {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read share from {}", path.display()))?;
        if bytes.len() != SECRET_LEN + 1 {
            bail!(
                "share file {} has {} bytes (expected {})",
                path.display(),
                bytes.len(),
                SECRET_LEN + 1
            );
        }
        // Statically safe: bytes.len() == SECRET_LEN + 1 verified above.
        #[allow(clippy::indexing_slicing)]
        let id = bytes[0];
        let mut value = [0u8; SECRET_LEN];
        #[allow(clippy::indexing_slicing)]
        value.copy_from_slice(&bytes[1..]);
        let share = Share::try_from_parts(id, Zeroizing::new(value))
            .map_err(|e| anyhow!("invalid share in {}: {e}", path.display()))?;
        shares.push(share);
    }

    let commitment_bytes = std::fs::read(commitment_path).with_context(|| {
        format!(
            "failed to read commitment from {}",
            commitment_path.display()
        )
    })?;
    if commitment_bytes.len() != COMMITMENT_LEN {
        bail!(
            "commitment file {} has {} bytes (expected {})",
            commitment_path.display(),
            commitment_bytes.len(),
            COMMITMENT_LEN
        );
    }
    let mut commitment_arr = [0u8; COMMITMENT_LEN];
    commitment_arr.copy_from_slice(&commitment_bytes);
    let commitment = Commitment::from_bytes(commitment_arr);

    let recovered = reconstruct(&shares, &commitment)
        .map_err(|e| anyhow!("Shamir reconstruction failed: {e}"))?;

    std::fs::write(out, recovered.as_ref())
        .with_context(|| format!("failed to write recovered seed to {}", out.display()))?;
    eprintln!(
        "Reconstructed seed from {} shares; commitment verified.",
        shares.len()
    );
    eprintln!("Wrote 32-byte seed to {}", out.display());
    Ok(())
}

/// Sign a trust-graph operation (`attest` / `revoke-withdraw` /
/// `revoke-compromise` / `re-attest`) per D0006 §2.
///
/// The op is signed by a device key — verification against the
/// associated capability token is performed at verify time via
/// [`SignedTrustGraphOp::verify_chain`]. Variant-required argument
/// validation runs before construction so the type-level guarantees
/// inside [`TrustGraphOp`] are never bypassed by a CLI typo.
#[allow(
    clippy::too_many_arguments,
    reason = "matches the per-variant TrustGraphOp surface; collapsing into a struct \
              would obscure the CLI flag mapping"
)]
#[allow(
    clippy::too_many_lines,
    reason = "variant validation + variant dispatch + sign/encode form one indivisible \
              correctness block per D0006 §2; splitting scatters the per-variant invariants"
)]
fn cmd_trust_op(
    kind: TrustOpKind,
    device_key: &PathBuf,
    issuer_pubkey: &PathBuf,
    subject_pubkey: &PathBuf,
    timestamp: u64,
    prior_hash: &PathBuf,
    cert_hash: &PathBuf,
    revoked_as_of: Option<u64>,
    prior_revocation_ref: Option<&PathBuf>,
    out: &PathBuf,
) -> Result<()> {
    // === Argument validation: variant-required fields ===
    let op_type: OpType = kind.into();
    match op_type {
        OpType::CompromiseRevoke => {
            if revoked_as_of.is_none() {
                bail!("--revoked-as-of is required when --kind=revoke-compromise (per D0006 §2)");
            }
            if prior_revocation_ref.is_some() {
                bail!("--prior-revocation-ref is only valid with --kind=re-attest");
            }
        }
        OpType::ReAttest => {
            if prior_revocation_ref.is_none() {
                bail!("--prior-revocation-ref is required when --kind=re-attest (per D0006 §2)");
            }
            if revoked_as_of.is_some() {
                bail!("--revoked-as-of is only valid with --kind=revoke-compromise");
            }
        }
        OpType::Attest | OpType::WithdrawRevoke => {
            if revoked_as_of.is_some() {
                bail!("--revoked-as-of is only valid with --kind=revoke-compromise");
            }
            if prior_revocation_ref.is_some() {
                bail!("--prior-revocation-ref is only valid with --kind=re-attest");
            }
        }
        // `OpType` is `#[non_exhaustive]` — future protocol variants
        // require a coordinated CLI update before this binary can sign
        // them. Refusing here beats silently accepting an unknown op.
        _ => bail!(
            "trust-graph op type {:?} is not supported by this CLI version; \
             upgrade cairn-cli to a release that ships support for it",
            op_type
        ),
    }

    // === Inputs ===
    let device_seed = read_seed(device_key)?;
    let device_signing_key = SigningKey::from_seed(&device_seed);
    let issuer_vk = read_pubkey(issuer_pubkey)?;
    let subject_vk = read_pubkey(subject_pubkey)?;

    let prior_hash_bytes = std::fs::read(prior_hash)
        .with_context(|| format!("failed to read prior-hash from {}", prior_hash.display()))?;
    let cert_hash_bytes = std::fs::read(cert_hash)
        .with_context(|| format!("failed to read cert-hash from {}", cert_hash.display()))?;

    // === Variant dispatch ===
    let op = match op_type {
        OpType::Attest => TrustGraphOp::new_attest(
            issuer_vk,
            subject_vk,
            timestamp,
            prior_hash_bytes,
            cert_hash_bytes,
        ),
        OpType::WithdrawRevoke => TrustGraphOp::new_withdraw_revoke(
            issuer_vk,
            subject_vk,
            timestamp,
            prior_hash_bytes,
            cert_hash_bytes,
        ),
        OpType::CompromiseRevoke => {
            // Unwrap safe: presence validated above.
            let revoked_as_of_value = revoked_as_of
                .ok_or_else(|| anyhow!("internal: revoked_as_of presence check skipped"))?;
            TrustGraphOp::new_compromise_revoke(
                issuer_vk,
                subject_vk,
                timestamp,
                prior_hash_bytes,
                cert_hash_bytes,
                revoked_as_of_value,
            )
        }
        OpType::ReAttest => {
            // Unwrap safe: presence validated above.
            let prior_ref_path = prior_revocation_ref
                .ok_or_else(|| anyhow!("internal: prior_revocation_ref presence check skipped"))?;
            let prior_ref_bytes = std::fs::read(prior_ref_path).with_context(|| {
                format!(
                    "failed to read prior-revocation-ref from {}",
                    prior_ref_path.display()
                )
            })?;
            TrustGraphOp::new_re_attest(
                issuer_vk,
                subject_vk,
                timestamp,
                prior_hash_bytes,
                cert_hash_bytes,
                prior_ref_bytes,
            )
        }
        // `OpType` is `#[non_exhaustive]`; unreachable here because the
        // validation pass above bails before dispatch on unknown variants.
        _ => bail!(
            "trust-graph op type {:?} is not supported by this CLI version",
            op_type
        ),
    };

    // === Sign + encode ===
    let signed = SignedTrustGraphOp::sign(op, &device_signing_key)
        .map_err(|e| anyhow!("trust-op sign failed: {e}"))?;
    let bytes = signed
        .encode(false)
        .map_err(|e| anyhow!("trust-op envelope encode failed: {e}"))?;

    std::fs::write(out, &bytes)
        .with_context(|| format!("failed to write trust-op envelope to {}", out.display()))?;

    eprintln!(
        "Signed trust-op kind={:?} ({} byte envelope, requires capability \"{}\")",
        kind,
        bytes.len(),
        op_type.required_capability()
    );
    eprintln!("Wrote envelope to {}", out.display());
    Ok(())
}

/// Verify a trust-graph operation envelope against a capability token
/// and an expected operational identity pubkey. Demonstrates the D0006
/// §9 hops #1 and #2 chain. Hop #3 (master-attestation chain-to-master)
/// is handled separately via `verify-master-attestation`.
fn cmd_verify_trust_op(
    op: &PathBuf,
    token: &PathBuf,
    expected_issuer_pubkey: &PathBuf,
) -> Result<()> {
    let op_bytes = std::fs::read(op)
        .with_context(|| format!("failed to read trust-op envelope from {}", op.display()))?;
    let token_bytes = std::fs::read(token)
        .with_context(|| format!("failed to read token from {}", token.display()))?;
    let expected_issuer = read_pubkey(expected_issuer_pubkey)?;

    let signed_op = SignedTrustGraphOp::from_bytes(&op_bytes)
        .map_err(|e| anyhow!("trust-op envelope decode failed: {e}"))?;
    let verified_op = signed_op
        .verify_chain(&token_bytes, &expected_issuer)
        .map_err(|e| anyhow!("trust-op verification failed: {e}"))?;

    println!("VERIFIED");
    println!("op-type:           {:?}", verified_op.op_type);
    println!(
        "required-capability: {}",
        verified_op.op_type.required_capability()
    );
    println!(
        "issuer-pubkey:     {}",
        hex_encode(&verified_op.issuer.to_bytes())
    );
    println!(
        "subject-pubkey:    {}",
        hex_encode(&verified_op.subject.to_bytes())
    );
    println!(
        "timestamp:         {} (Unix seconds)",
        verified_op.timestamp
    );
    println!("prior-hash:        {} bytes", verified_op.prior_hash.len());
    println!(
        "issuer-cert-hash:  {} bytes",
        verified_op.issuer_cert_hash.len()
    );
    if let Some(revoked_as_of) = verified_op.revoked_as_of {
        println!("revoked-as-of:     {revoked_as_of} (Unix seconds)");
    }
    if let Some(prior_ref) = &verified_op.prior_revocation_ref {
        println!("prior-revocation-ref: {} bytes", prior_ref.len());
    }
    Ok(())
}

/// Reconstruct the master from threshold-many shares + a commitment,
/// then sign a master attestation of `new_operational_identity_pubkey`.
///
/// The master seed lives in `Zeroizing` for the duration of the
/// underlying `reconstruct_and_attest` call and is wiped on exit — no
/// seed bytes ever touch disk via this command. The output file
/// contains only the signed attestation envelope (master pubkey +
/// operational identity pubkey + timestamp, COSE_Sign1-wrapped).
fn cmd_attest_operational_identity(
    share_paths: &[PathBuf],
    commitment_path: &PathBuf,
    new_op_identity_pubkey: &PathBuf,
    timestamp: u64,
    out: &PathBuf,
) -> Result<()> {
    if share_paths.is_empty() {
        bail!("at least one --share must be supplied");
    }

    // === Load shares (same 33-byte format as cmd_reconstruct_seed) ===
    let mut shares: Vec<Share> = Vec::with_capacity(share_paths.len());
    for path in share_paths {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read share from {}", path.display()))?;
        if bytes.len() != SECRET_LEN + 1 {
            bail!(
                "share file {} has {} bytes (expected {})",
                path.display(),
                bytes.len(),
                SECRET_LEN + 1
            );
        }
        // Statically safe: length verified above.
        #[allow(clippy::indexing_slicing)]
        let id = bytes[0];
        let mut value = [0u8; SECRET_LEN];
        #[allow(clippy::indexing_slicing)]
        value.copy_from_slice(&bytes[1..]);
        let share = Share::try_from_parts(id, Zeroizing::new(value))
            .map_err(|e| anyhow!("invalid share in {}: {e}", path.display()))?;
        shares.push(share);
    }

    // === Load commitment ===
    let commitment_bytes = std::fs::read(commitment_path).with_context(|| {
        format!(
            "failed to read commitment from {}",
            commitment_path.display()
        )
    })?;
    if commitment_bytes.len() != COMMITMENT_LEN {
        bail!(
            "commitment file {} has {} bytes (expected {})",
            commitment_path.display(),
            commitment_bytes.len(),
            COMMITMENT_LEN
        );
    }
    let mut commitment_arr = [0u8; COMMITMENT_LEN];
    commitment_arr.copy_from_slice(&commitment_bytes);
    let commitment = Commitment::from_bytes(commitment_arr);

    // === Load new operational identity pubkey ===
    let new_op_identity = read_pubkey(new_op_identity_pubkey)?;

    // === Reconstruct + attest (master held in Zeroizing inside) ===
    let signed = reconstruct_and_attest(&shares, &commitment, new_op_identity, timestamp)
        .map_err(|e| anyhow!("reconstruct_and_attest failed: {e}"))?;

    let bytes = signed
        .encode(false)
        .map_err(|e| anyhow!("attestation envelope encode failed: {e}"))?;

    std::fs::write(out, &bytes)
        .with_context(|| format!("failed to write attestation envelope to {}", out.display()))?;

    eprintln!(
        "Reconstructed master from {} shares; commitment verified; master seed wiped.",
        shares.len()
    );
    eprintln!(
        "Signed master attestation of operational-identity {} ({} byte envelope)",
        hex_encode(&new_op_identity.to_bytes()),
        bytes.len()
    );
    eprintln!("Wrote envelope to {}", out.display());
    Ok(())
}

/// Verify a master attestation envelope against an expected master
/// pubkey (typically the one printed on the user's paper backup card).
///
/// This is hop #3 of the D0006 §9 chain: trust the master pubkey
/// out-of-band → verify the master attestation → trust the embedded
/// operational identity → (subsequent commands) verify capability
/// tokens issued by that operational identity.
fn cmd_verify_master_attestation(
    attestation: &PathBuf,
    expected_master_pubkey: &PathBuf,
) -> Result<()> {
    let attestation_bytes = std::fs::read(attestation).with_context(|| {
        format!(
            "failed to read attestation envelope from {}",
            attestation.display()
        )
    })?;
    let expected_master = read_pubkey(expected_master_pubkey)?;

    let signed = SignedMasterAttestation::from_bytes(&attestation_bytes, &expected_master)
        .map_err(|e| anyhow!("master attestation verification failed: {e}"))?;
    let att = signed.attestation();

    println!("VERIFIED");
    println!(
        "master-pubkey:        {}",
        hex_encode(&att.master.to_bytes())
    );
    println!(
        "operational-identity: {}",
        hex_encode(&att.operational_identity.to_bytes())
    );
    println!("timestamp:            {} (Unix seconds)", att.timestamp);
    Ok(())
}

/// Compute the canonical D0006 §5 `prior_hash` for a trust-graph op
/// envelope. Decodes the envelope (does NOT verify the chain — this is
/// a stateless byte-level hash helper) and emits 32 raw bytes per
/// `SignedTrustGraphOp::prior_hash_bytes()`.
fn cmd_compute_prior_hash(op: &PathBuf, out: &PathBuf) -> Result<()> {
    let bytes = std::fs::read(op)
        .with_context(|| format!("failed to read trust-op envelope from {}", op.display()))?;
    let signed_op = SignedTrustGraphOp::from_bytes(&bytes)
        .map_err(|e| anyhow!("trust-op envelope decode failed: {e}"))?;
    let hash = signed_op.prior_hash_bytes();
    std::fs::write(out, hash)
        .with_context(|| format!("failed to write prior-hash to {}", out.display()))?;
    println!("{}", hex_encode(&hash));
    eprintln!(
        "Computed D0006 §5 prior_hash (32 bytes) and wrote to {}",
        out.display()
    );
    Ok(())
}

/// Compute the canonical D0006 §7 `issuer_cert_hash` for a master
/// attestation envelope. Decodes the envelope without verification
/// (this is a stateless byte-level hash helper) and emits 32 raw
/// bytes per `SignedMasterAttestation::issuer_cert_hash()`.
///
/// Note: this command intentionally does NOT verify the master
/// attestation against an expected master pubkey — the hash is a
/// byte-level commitment that callers may want to compute even for
/// envelopes they're inspecting before verification. Use
/// `verify-master-attestation` if you need to verify before hashing.
fn cmd_compute_issuer_cert_hash(attestation: &PathBuf, out: &PathBuf) -> Result<()> {
    let bytes = std::fs::read(attestation).with_context(|| {
        format!(
            "failed to read attestation envelope from {}",
            attestation.display()
        )
    })?;
    // Decode the COSE_Sign1 envelope directly to reach
    // sig_structure_bytes; we don't need to verify here (hash is a
    // byte commitment).
    let envelope = CoseSign1::from_bytes(&bytes)
        .map_err(|e| anyhow!("attestation envelope decode failed: {e}"))?;
    let sig_structure = envelope
        .sig_structure_bytes(cairn_recovery::DOMAIN_TAG)
        .map_err(|e| anyhow!("Sig_structure encode failed: {e}"))?;
    let hash: [u8; 32] = Sha256::digest(&sig_structure).into();
    std::fs::write(out, hash)
        .with_context(|| format!("failed to write issuer-cert-hash to {}", out.display()))?;
    println!("{}", hex_encode(&hash));
    eprintln!(
        "Computed D0006 §7 issuer_cert_hash (32 bytes) and wrote to {}",
        out.display()
    );
    Ok(())
}

/// Verify a sequence of trust-graph op envelopes as a single chain
/// per D0006 §2 + §5 via [`verify_chain_links`].
///
/// On success prints a per-op summary (`op_type` + `timestamp` +
/// `prior_hash` length + `issuer_cert_hash` length) so the caller can
/// audit the chain shape. On failure surfaces the precise structural
/// error (which op index failed, which check failed).
fn cmd_verify_trust_chain(
    op_paths: &[PathBuf],
    token: &PathBuf,
    expected_issuer_pubkey: &PathBuf,
) -> Result<()> {
    if op_paths.is_empty() {
        bail!("at least one --op must be supplied");
    }
    let token_bytes = std::fs::read(token)
        .with_context(|| format!("failed to read token from {}", token.display()))?;
    let expected_issuer = read_pubkey(expected_issuer_pubkey)?;

    let mut signed_ops: Vec<SignedTrustGraphOp> = Vec::with_capacity(op_paths.len());
    for path in op_paths {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read trust-op envelope from {}", path.display()))?;
        let signed = SignedTrustGraphOp::from_bytes(&bytes).map_err(|e| {
            anyhow!(
                "trust-op envelope decode failed for {}: {e}",
                path.display()
            )
        })?;
        signed_ops.push(signed);
    }

    let verified_ops = verify_chain_links(&signed_ops, &token_bytes, &expected_issuer)
        .map_err(|e| anyhow!("chain-walk verification failed: {e}"))?;

    println!("VERIFIED ({} ops in chain)", verified_ops.len());
    for (i, op) in verified_ops.iter().enumerate() {
        println!(
            "  [{i}] op_type={:?} timestamp={} prior_hash_len={} cert_hash_len={}",
            op.op_type,
            op.timestamp,
            op.prior_hash.len(),
            op.issuer_cert_hash.len()
        );
    }
    println!(
        "issuer-pubkey:     {}",
        hex_encode(
            &verified_ops
                .first()
                .ok_or_else(|| anyhow!("internal: empty verified slice"))?
                .issuer
                .to_bytes()
        )
    );
    println!(
        "subject-pubkey:    {}",
        hex_encode(
            &verified_ops
                .first()
                .ok_or_else(|| anyhow!("internal: empty verified slice"))?
                .subject
                .to_bytes()
        )
    );
    Ok(())
}

/// Decode a heterogeneous set of trust-graph op envelopes (across
/// multiple operational identities) and print the D0006 §2 cascade-
/// quarantine status of each via [`compute_quarantine_state`].
///
/// Decodes without per-op verification — the input set spans multiple
/// operational identities so no single token suffices. The op decode
/// step still parses the canonical CBOR payload schema, so structural
/// errors surface here; cryptographic verification is the caller's
/// responsibility via `verify-trust-chain` per chain.
fn cmd_inspect_trust_state(op_paths: &[PathBuf]) -> Result<()> {
    if op_paths.is_empty() {
        bail!("at least one --op must be supplied");
    }

    let mut decoded: Vec<SignedTrustGraphOp> = Vec::with_capacity(op_paths.len());
    for path in op_paths {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read trust-op envelope from {}", path.display()))?;
        let signed = SignedTrustGraphOp::from_bytes(&bytes).map_err(|e| {
            anyhow!(
                "trust-op envelope decode failed for {}: {e}",
                path.display()
            )
        })?;
        decoded.push(signed);
    }

    let op_refs: Vec<&TrustGraphOp> = decoded.iter().map(SignedTrustGraphOp::op).collect();
    let statuses = compute_quarantine_state(&op_refs);

    println!("DECODED-ONLY ({} ops)", op_refs.len());
    println!(
        "WARNING: per-op signature verification was NOT performed. \
         Run verify-trust-chain on each (issuer, subject) chain before \
         trusting this classification."
    );
    println!();
    for (i, (op, status)) in op_refs.iter().zip(statuses.iter()).enumerate() {
        println!(
            "[{i}] op_type={:?} issuer={} subject={} timestamp={}",
            op.op_type,
            hex_encode_short(&op.issuer.to_bytes()),
            hex_encode_short(&op.subject.to_bytes()),
            op.timestamp
        );
        println!("     status: {}", format_status(*status));
    }
    Ok(())
}

/// Render the leading 8 hex chars of a pubkey for compact display.
fn hex_encode_short(bytes: &[u8]) -> String {
    let full = hex_encode(bytes);
    // `min` keeps the slice in bounds for absurdly short inputs that
    // pubkey paths never actually reach.
    let preview_len = full.len().min(16);
    #[allow(clippy::indexing_slicing, reason = "preview_len ≤ full.len() by min()")]
    full[..preview_len].to_string()
}

/// Render a `QuarantineStatus` for human-readable CLI output.
fn format_status(status: QuarantineStatus) -> String {
    match status {
        QuarantineStatus::NotApplicable => "n/a (revocation op)".to_string(),
        QuarantineStatus::Active => "Active".to_string(),
        QuarantineStatus::SoftFlaggedByWithdrawal {
            revoked_by,
            withdrawal_at,
        } => format!(
            "SoftFlaggedByWithdrawal (by {} at t={withdrawal_at})",
            hex_encode_short(&revoked_by.to_bytes())
        ),
        QuarantineStatus::SoftFlaggedPreCompromise {
            revoked_by,
            revoked_as_of,
        } => format!(
            "SoftFlaggedPreCompromise (by {} revoked_as_of={revoked_as_of})",
            hex_encode_short(&revoked_by.to_bytes())
        ),
        QuarantineStatus::HardSuspended {
            revoked_by,
            revoked_as_of,
        } => format!(
            "HardSuspended (by {} revoked_as_of={revoked_as_of})",
            hex_encode_short(&revoked_by.to_bytes())
        ),
        _ => "(unknown variant — CLI built against older cairn-trust-graph)".to_string(),
    }
}
