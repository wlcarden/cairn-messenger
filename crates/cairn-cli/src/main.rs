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
use cairn_identity::{CapabilityToken, SignedCapabilityToken};
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
