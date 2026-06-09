// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// CLI exceptions to the workspace library-discipline lints, same as
// cairn-cli: stdout/stderr ARE this tool's output channels, and the
// binary propagates errors through anyhow rather than the library
// Result discipline.
#![allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr)]
// Binary crate: its `mod produce` / `mod roots` items have no external
// consumers, so rustc's workspace `unreachable_pub` fires on every
// intra-binary `pub`. Allowing it crate-wide is the idiomatic choice for
// a multi-module binary and lets the producer modules use plain `pub`,
// which sidesteps the redundant_pub_crate ↔ unreachable_pub conflict
// (cf. cairn-tor-transport/src/control.rs for the library-side variant).
#![allow(unreachable_pub)]

//! # cairn-release
//!
//! The Cairn release-producer CLI: builds + signs a verifiable
//! [`ReleaseBundle`](cairn_sigstore_verify::ReleaseBundle) — the producer
//! counterpart to the `cairn-sigstore-verify` verifier (D0024 §6) and the
//! engineering realization of the D0015 release-security posture's
//! producer side.
//!
//! ## Subcommands
//!
//! - `build` — hash the release artifact(s), assemble + COSE-sign the
//!   manifest, anchor Rekor + Sigsum proofs, and write a single-file
//!   `release-bundle.cbor` plus the `release-roots.json` that pins it,
//!   the `manifest.cbor` chain link, and the `build-provenance.json`
//!   attestation.
//! - `verify` — replay the REAL `verify_release` over a bundle + its
//!   roots on the host (the same orchestration the on-device client runs,
//!   proving producer/verifier agreement before any device is involved).
//!
//! ## Trust-root posture (D0041)
//!
//! v1 mints self-consistent synthetic roots per `build` (phase 1): this
//! proves the pipeline MECHANICS with zero external services. Swapping in
//! real Sigstore staging/production roots (phase 2) is a verifier-config
//! change plus the producer's network legs — not a schema change — so the
//! `release-bundle.cbor` format is stable from here.

mod produce;
mod roots;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use cairn_sigstore_verify::{ReleaseBundle, ReleaseManifest};
use clap::{Args, Parser, Subcommand};

use crate::produce::{ArtifactInput, CosignInputs, ingest_cosign, produce};
use crate::roots::{ReleaseRoots, decode_hex_32, to_hex};

#[derive(Parser)]
#[command(
    name = "cairn-release",
    about = "Build + verify Cairn release bundles (D0024 §6 producer side)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build + sign a self-minted release bundle over the given artifact(s).
    Build(BuildArgs),
    /// Emit ONLY the canonical-CBOR manifest (the blob `cosign sign-blob`
    /// signs) + the build-provenance — the first half of the real keyless
    /// (D0042 §4) pipeline. No synthetic key/bundle is written.
    BuildManifest(BuildArgs),
    /// Ingest stock `cosign sign-blob` outputs (cert + detached sig + Rekor
    /// entry) into a verifiable `release-bundle.cbor` + `release-roots.json`
    /// (D0042 §4, the "2b" path). Sigstore proofs are real; Sigsum synthetic.
    IngestCosign(IngestCosignArgs),
    /// Replay `verify_release` over a bundle against its roots (host oracle).
    Verify(VerifyArgs),
}

#[derive(Args)]
struct BuildArgs {
    /// Path to a release artifact (repeat for multiple; the APK first).
    #[arg(long = "apk", required = true, value_name = "FILE")]
    apks: Vec<PathBuf>,
    /// Semver string identifying this release, e.g. `1.0.0-pilot`.
    #[arg(long)]
    version: String,
    /// Predecessor `manifest.cbor` (omit for the genesis release).
    #[arg(long = "prior-manifest", value_name = "FILE")]
    prior_manifest: Option<PathBuf>,
    /// Output directory (created if absent).
    #[arg(long, default_value = "release-out", value_name = "DIR")]
    out: PathBuf,
}

#[derive(Args)]
struct VerifyArgs {
    /// Path to `release-bundle.cbor`.
    #[arg(long, value_name = "FILE")]
    bundle: PathBuf,
    /// Path to `release-roots.json`.
    #[arg(long, value_name = "FILE")]
    roots: PathBuf,
    /// Expected predecessor manifest hash (64 hex chars). Omit to skip
    /// the rollback-resistance check (e.g. verifying a genesis release).
    #[arg(long = "expected-prior", value_name = "HEX")]
    expected_prior: Option<String>,
}

#[derive(Args)]
struct IngestCosignArgs {
    /// The canonical-CBOR manifest that was signed (from `build-manifest`).
    #[arg(long, value_name = "FILE")]
    manifest: PathBuf,
    /// The Fulcio signing certificate, PEM (`cosign --output-certificate`).
    #[arg(long, value_name = "FILE")]
    cert: PathBuf,
    /// The detached signature, base64 (`cosign --output-signature`).
    #[arg(long, value_name = "FILE")]
    signature: PathBuf,
    /// The raw Rekor entry JSON (`GET /api/v1/log/entries?logIndex=N`).
    #[arg(long = "rekor-entry", value_name = "FILE")]
    rekor_entry: PathBuf,
    /// Pinned Fulcio trust bundle, PEM (root [+ intermediate]).
    #[arg(long = "fulcio-root", value_name = "FILE")]
    fulcio_root: PathBuf,
    /// Pinned Rekor log public key, PEM.
    #[arg(long = "rekor-key", value_name = "FILE")]
    rekor_key: PathBuf,
    /// Pinned CT-log public key, PEM (optional; enables SCT enforcement).
    #[arg(long = "ctlog-key", value_name = "FILE")]
    ctlog_key: Option<PathBuf>,
    /// Expected OIDC issuer (GitHub Actions OIDC by default).
    #[arg(
        long = "oidc-issuer",
        default_value = "https://token.actions.githubusercontent.com"
    )]
    oidc_issuer: String,
    /// Expected CI workflow SAN URI identity (the keyless signer).
    #[arg(long = "oidc-san-uri", value_name = "URI")]
    oidc_san_uri: String,
    /// Output directory (created if absent).
    #[arg(long, default_value = "release-out", value_name = "DIR")]
    out: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Build(args) => run_build(&args),
        Command::BuildManifest(args) => run_build_manifest(&args),
        Command::IngestCosign(args) => run_ingest_cosign(&args),
        Command::Verify(args) => run_verify(&args),
    }
}

fn run_build(args: &BuildArgs) -> Result<()> {
    let artifacts = args
        .apks
        .iter()
        .map(read_artifact)
        .collect::<Result<Vec<_>>>()?;

    let prior_release_hash = read_prior_hash(args.prior_manifest.as_ref())?;
    let is_genesis = prior_release_hash.is_empty();
    let release_timestamp = now_unix()?;

    let produced = produce(
        &artifacts,
        &args.version,
        prior_release_hash,
        release_timestamp,
    )
    .context("produce release bundle")?;

    let bundle_cbor = produced
        .bundle
        .to_canonical_cbor()
        .map_err(|e| anyhow::anyhow!("encode release bundle: {e}"))?;
    let roots_json = produced.roots.to_json_bytes()?;

    fs::create_dir_all(&args.out)
        .with_context(|| format!("create output dir {}", args.out.display()))?;
    write_out(&args.out, "release-bundle.cbor", &bundle_cbor)?;
    write_out(&args.out, "release-roots.json", &roots_json)?;
    write_out(&args.out, "manifest.cbor", &produced.manifest_cbor)?;
    write_out(
        &args.out,
        "build-provenance.json",
        &produced.build_provenance_json,
    )?;

    println!("Built release bundle for version {}", args.version);
    println!("  artifacts:");
    for artifact in &produced.artifacts {
        println!("    {} sha256={}", artifact.name, to_hex(&artifact.sha256));
    }
    println!(
        "  build-provenance sha256: {}",
        to_hex(&produced.build_provenance_sha256)
    );
    println!(
        "  release-leaf hash:       {}",
        to_hex(&produced.release_leaf_hash)
    );
    if is_genesis {
        println!("  prior release:           (genesis — none)");
    } else {
        println!("  prior release:           (chained to predecessor)");
    }
    println!(
        "  this manifest hash:      {}",
        to_hex(&produced.manifest_self_hash)
    );
    println!("    ^ pass this as the NEXT release's --expected-prior");
    println!("  output dir:              {}", args.out.display());
    let prior_flag = if is_genesis {
        ""
    } else {
        " --expected-prior <predecessor-manifest-hash>"
    };
    println!(
        "\nVerify with:\n  cairn-release verify --bundle {0}/release-bundle.cbor --roots {0}/release-roots.json{1}",
        args.out.display(),
        prior_flag
    );
    Ok(())
}

fn run_verify(args: &VerifyArgs) -> Result<()> {
    let bundle_bytes =
        fs::read(&args.bundle).with_context(|| format!("read bundle {}", args.bundle.display()))?;
    let bundle = ReleaseBundle::from_canonical_cbor(&bundle_bytes)
        .map_err(|e| anyhow::anyhow!("decode release bundle: {e}"))?;

    let roots_bytes =
        fs::read(&args.roots).with_context(|| format!("read roots {}", args.roots.display()))?;
    let roots = ReleaseRoots::from_json_slice(&roots_bytes)?;
    let verifier = roots.build_verifier()?;

    let expected_prior = match &args.expected_prior {
        Some(hex) => Some(decode_hex_32(hex).context("parse --expected-prior")?),
        None => None,
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    let outcome = runtime.block_on(verifier.verify_release(&bundle, expected_prior));

    match outcome {
        Ok(report) => {
            println!("verify_release: OK");
            println!("  version:  {}", report.manifest.version);
            println!("  artifacts:");
            for artifact in &report.manifest.artifact_sha256 {
                println!("    {} sha256={}", artifact.name, to_hex(&artifact.sha256));
            }
            if expected_prior.is_some() {
                println!("  rollback: prior_release_hash matched the expected predecessor");
            } else {
                println!("  rollback: not checked (no --expected-prior supplied)");
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("verify_release: FAILED — {e}");
            Err(anyhow::anyhow!("release verification failed"))
        }
    }
}

fn run_build_manifest(args: &BuildArgs) -> Result<()> {
    let artifacts = args
        .apks
        .iter()
        .map(read_artifact)
        .collect::<Result<Vec<_>>>()?;
    let prior_release_hash = read_prior_hash(args.prior_manifest.as_ref())?;
    let release_timestamp = now_unix()?;

    // Reuse `produce` for the manifest assembly (identical bytes to `build`),
    // but write ONLY the blob cosign signs + the provenance — the synthetic
    // bundle/roots it also mints are discarded on the real keyless path.
    let produced = produce(
        &artifacts,
        &args.version,
        prior_release_hash,
        release_timestamp,
    )
    .context("assemble release manifest")?;

    fs::create_dir_all(&args.out)
        .with_context(|| format!("create output dir {}", args.out.display()))?;
    write_out(&args.out, "manifest.cbor", &produced.manifest_cbor)?;
    write_out(
        &args.out,
        "build-provenance.json",
        &produced.build_provenance_json,
    )?;

    println!(
        "Wrote {}/manifest.cbor — the blob to sign with `cosign sign-blob`.",
        args.out.display()
    );
    println!("  artifacts:");
    for artifact in &produced.artifacts {
        println!("    {} sha256={}", artifact.name, to_hex(&artifact.sha256));
    }
    println!(
        "  this manifest hash:      {}",
        to_hex(&produced.manifest_self_hash)
    );
    println!("    ^ pass this as the NEXT release's --expected-prior");
    println!(
        "\nNext (in CI):\n  cosign sign-blob {0}/manifest.cbor --yes \\\n    --output-certificate cert.pem --output-signature sig.b64\n  # then fetch the Rekor entry JSON and run `cairn-release ingest-cosign`",
        args.out.display()
    );
    Ok(())
}

fn run_ingest_cosign(args: &IngestCosignArgs) -> Result<()> {
    let read_text = |path: &PathBuf, what: &str| -> Result<String> {
        let bytes = fs::read(path).with_context(|| format!("read {what} {}", path.display()))?;
        String::from_utf8(bytes).with_context(|| format!("{what} is not valid UTF-8"))
    };

    let manifest_cbor = fs::read(&args.manifest)
        .with_context(|| format!("read manifest {}", args.manifest.display()))?;
    let ctlog_pubkey_pem = match &args.ctlog_key {
        Some(path) => Some(read_text(path, "ctlog key")?),
        None => None,
    };
    let input = CosignInputs {
        manifest_cbor,
        cert_pem: read_text(&args.cert, "certificate")?,
        signature_b64: read_text(&args.signature, "signature")?,
        rekor_entry_json: read_text(&args.rekor_entry, "rekor entry")?,
        fulcio_root_pem: read_text(&args.fulcio_root, "fulcio root")?,
        rekor_pubkey_pem: read_text(&args.rekor_key, "rekor key")?,
        ctlog_pubkey_pem,
        oidc_issuer: args.oidc_issuer.clone(),
        oidc_san_uri: args.oidc_san_uri.clone(),
    };

    let ingested = ingest_cosign(&input).context("ingest cosign outputs")?;
    let bundle_cbor = ingested
        .bundle
        .to_canonical_cbor()
        .map_err(|e| anyhow::anyhow!("encode release bundle: {e}"))?;
    let roots_json = ingested.roots.to_json_bytes()?;

    fs::create_dir_all(&args.out)
        .with_context(|| format!("create output dir {}", args.out.display()))?;
    write_out(&args.out, "release-bundle.cbor", &bundle_cbor)?;
    write_out(&args.out, "release-roots.json", &roots_json)?;

    println!("Ingested cosign outputs into a release bundle (D0042 §4 / proof target 2b).");
    println!(
        "  release-leaf hash:  {}",
        to_hex(&ingested.release_leaf_hash)
    );
    println!("  pinned identity:    {}", args.oidc_san_uri);
    println!("  Sigstore proofs:    REAL (Fulcio cert + detached sig + Rekor inclusion)");
    println!("  Sigsum proof:       synthetic (recruited log is §8 / funding-gated)");
    println!("  output dir:         {}", args.out.display());
    println!(
        "\nVerify with:\n  cairn-release verify --bundle {0}/release-bundle.cbor --roots {0}/release-roots.json",
        args.out.display()
    );
    Ok(())
}

/// Resolve a `--prior-manifest` path to its `canonical_self_hash` (the
/// successor's `prior_release_hash`), or an empty vec for the genesis
/// release. Shared by `build` + `build-manifest`.
fn read_prior_hash(prior_manifest: Option<&PathBuf>) -> Result<Vec<u8>> {
    match prior_manifest {
        Some(path) => {
            let bytes = fs::read(path)
                .with_context(|| format!("read prior manifest {}", path.display()))?;
            let manifest = ReleaseManifest::from_canonical_cbor(&bytes)
                .map_err(|e| anyhow::anyhow!("decode prior manifest: {e}"))?;
            Ok(manifest
                .canonical_self_hash()
                .map_err(|e| anyhow::anyhow!("hash prior manifest: {e}"))?
                .to_vec())
        }
        None => Ok(Vec::new()),
    }
}

/// Current Unix-seconds (the manifest's `release_timestamp`).
fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs())
}

/// Read an artifact file into an [`ArtifactInput`], naming it by file name.
fn read_artifact(path: &PathBuf) -> Result<ArtifactInput> {
    let bytes = fs::read(path).with_context(|| format!("read artifact {}", path.display()))?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("artifact")
        .to_string();
    Ok(ArtifactInput { name, bytes })
}

/// Write `bytes` to `dir/name`, reporting the path on error.
fn write_out(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let path = dir.join(name);
    fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))
}
