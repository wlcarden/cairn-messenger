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

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use cairn_crypto::ed25519::{PUBLIC_KEY_LEN, SEED_LEN, SigningKey, VerifyingKey};
use cairn_envelope::cose_sign1::{CoseSign1, Sign1Builder};
use cairn_identity::{CapabilityToken, SignedCapabilityToken};
use cairn_shamir::{COMMITMENT_LEN, Commitment, SECRET_LEN, Share, reconstruct, split};
use clap::{Parser, Subcommand};
use rand_core::OsRng;
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
}

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
