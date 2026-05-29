// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cairn maintainers and contributors

// `unwrap_used` allowed at the crate level: this is a bench harness,
// not production code. `unwrap` is used only at one-shot setup sites
// where the inputs (fixed constants) make failure unreachable. The
// dudect-bencher API uses panics to signal harness misconfiguration;
// using `unwrap` aligns with that convention.
#![allow(clippy::unwrap_used)]

//! Empirical constant-time verification harness per D0018 §5.3.
//!
//! Runs Welch's-t-test-based timing-distribution comparisons on
//! secret-byte-handling code paths. Per D0018 §5.3 spec line 461, the
//! CI assertion is "Welch's t-statistic stays below 4.5". This harness
//! defines the bench functions; threshold enforcement happens at the
//! CI invocation layer.
//!
//! ## Invocation
//!
//! Build in release mode (per D0018 §5.3 — `subtle`'s historical
//! `opt-level` regression reintroducing variable time):
//!
//! ```bash
//! cargo build --release --package cairn-ct-bench
//! ./target/release/cairn-ct-bench
//! ```
//!
//! For production validation runs (the 10⁶-iteration depth per
//! D0018 §5.3 line 460), use `--continuous` mode:
//!
//! ```bash
//! ./target/release/cairn-ct-bench --continuous bench_
//! ```
//!
//! For CI smoke-test runs (verifying the harness compiles and the
//! bench functions don't panic), the default one-shot mode at the
//! `N_INPUTS` count defined below is sufficient.
//!
//! ## Bench functions
//!
//! Per D0018 §5.3 line 459, the target functions are:
//! - Shamir reconstruction (`combine_array`)
//! - Ed25519 signing
//! - AEAD tag comparison
//! - Share equality
//! - Constant-time CBOR-encoded-key comparison in the canonical-helper
//!   sort
//!
//! v1 coverage:
//! - [`bench_shamir_split`] — exercises `vsss-rs::Gf256::split_array`
//!   via `cairn-shamir`'s `split`. Polynomial coefficient generation +
//!   evaluation across the field.
//! - [`bench_shamir_reconstruct`] — exercises `Gf256::combine_array`
//!   via `cairn-shamir`'s `reconstruct`. The Lagrange-interpolation path
//!   D0018 §5.3 explicitly cites.
//! - [`bench_ed25519_sign`] — exercises `ed25519_dalek::SigningKey::sign`
//!   via `cairn-crypto::ed25519`'s `SigningKey::sign`. Scalar
//!   multiplication + nonce derivation.
//!
//! Follow-up coverage (deferred — separate v1 surface entries):
//! - AEAD tag comparison
//! - Share `PartialEq` (when added)
//! - Canonical CBOR encoded-key bytewise compare

use cairn_crypto::ed25519::SigningKey;
use cairn_shamir::{Commitment, SECRET_LEN, Share, reconstruct, split};
use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main, rand::RngExt};
use rand_core::OsRng;
use zeroize::Zeroizing;

/// Number of inputs per bench function.
///
/// The dudect paper recommends `~10⁶` iterations for high-confidence
/// detection of variable-time leaks; CI smoke-test runs at the value
/// below (`10_000`) primarily verify the harness compiles + runs
/// without panic.
///
/// Production validation runs should use the `--continuous` flag (per
/// the module docs), which iterates without bound until SIGINT.
const N_INPUTS: usize = 10_000;

/// All-zeros 32-byte secret — `Class::Left` input for Shamir benches.
const ZERO_SECRET: [u8; SECRET_LEN] = [0u8; SECRET_LEN];

/// All-ones 32-byte secret — `Class::Right` input for Shamir benches.
const ONE_SECRET: [u8; SECRET_LEN] = [0xFF_u8; SECRET_LEN];

/// All-zeros 32-byte Ed25519 seed — `Class::Left` input for sign bench.
const ZERO_SEED: [u8; 32] = [0u8; 32];

/// All-ones 32-byte Ed25519 seed — `Class::Right` input for sign bench.
const ONE_SEED: [u8; 32] = [0xFF_u8; 32];

/// Bench: Shamir `split` across `(secret = 0x00…00)` vs
/// `(secret = 0xFF…FF)`.
///
/// If `vsss-rs::Gf256::split_array` is constant-time across the secret
/// bytes (claimed by `vsss-rs-5.4.0/src/gf256.rs:1-9` and confirmed by
/// the Cure53 PVY-01-003 reference per D0018 §3.1), the timing
/// distributions should be statistically indistinguishable.
fn bench_shamir_split(runner: &mut CtRunner, rng: &mut BenchRng) {
    let zero_secret = Zeroizing::new(ZERO_SECRET);
    let one_secret = Zeroizing::new(ONE_SECRET);

    let mut classes = Vec::with_capacity(N_INPUTS);
    let mut secrets: Vec<Zeroizing<[u8; SECRET_LEN]>> = Vec::with_capacity(N_INPUTS);

    for _ in 0..N_INPUTS {
        if rng.random::<bool>() {
            classes.push(Class::Left);
            secrets.push(zero_secret.clone());
        } else {
            classes.push(Class::Right);
            secrets.push(one_secret.clone());
        }
    }

    for (class, secret) in classes.into_iter().zip(secrets.into_iter()) {
        runner.run_one(class, || {
            // `OsRng` is a ZST; constructing a fresh one in the
            // closure is free and avoids the `FnMut` capture issue
            // that `run_one`'s `Fn` bound would otherwise hit.
            let mut split_rng = OsRng;
            let _ = split(&secret, 3, 5, &mut split_rng);
        });
    }
}

/// Bench: Shamir `reconstruct` across share-bytes-from-zero-secret vs
/// share-bytes-from-one-secret.
///
/// Pre-computes the share + commitment for each class outside the
/// timing loop; only the reconstruct call is measured. The commitment
/// check passes for both classes (correct commitments), so the
/// constant-time `Commitment::ct_eq` path runs identically. Any
/// timing difference between Left and Right reflects the
/// `Gf256::combine_array` Lagrange-interpolation path.
fn bench_shamir_reconstruct(runner: &mut CtRunner, rng: &mut BenchRng) {
    let zero_secret = Zeroizing::new(ZERO_SECRET);
    let one_secret = Zeroizing::new(ONE_SECRET);

    let mut split_rng = OsRng;
    let (zero_shares, zero_commit) = split(&zero_secret, 3, 3, &mut split_rng).unwrap();
    let (one_shares, one_commit) = split(&one_secret, 3, 3, &mut split_rng).unwrap();

    let mut classes = Vec::with_capacity(N_INPUTS);
    let mut inputs: Vec<(Vec<Share>, Commitment)> = Vec::with_capacity(N_INPUTS);

    for _ in 0..N_INPUTS {
        if rng.random::<bool>() {
            classes.push(Class::Left);
            inputs.push((zero_shares.clone(), zero_commit));
        } else {
            classes.push(Class::Right);
            inputs.push((one_shares.clone(), one_commit));
        }
    }

    for (class, (shares, commit)) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            let _ = reconstruct(&shares, &commit);
        });
    }
}

/// Bench: Ed25519 `sign` across `(seed = 0x00…00)` vs
/// `(seed = 0xFF…FF)`, fixed payload.
///
/// `ed25519-dalek` claims constant-time signing per the upstream
/// audited construction. This bench is the empirical check at our
/// wrapper layer.
fn bench_ed25519_sign(runner: &mut CtRunner, rng: &mut BenchRng) {
    let zero_key = SigningKey::from_seed(&Zeroizing::new(ZERO_SEED));
    let one_key = SigningKey::from_seed(&Zeroizing::new(ONE_SEED));
    let payload = b"cairn ct-bench payload bytes 0123456789abcdef";

    let mut classes = Vec::with_capacity(N_INPUTS);
    let mut keys: Vec<&SigningKey> = Vec::with_capacity(N_INPUTS);

    for _ in 0..N_INPUTS {
        if rng.random::<bool>() {
            classes.push(Class::Left);
            keys.push(&zero_key);
        } else {
            classes.push(Class::Right);
            keys.push(&one_key);
        }
    }

    for (class, key) in classes.into_iter().zip(keys.into_iter()) {
        runner.run_one(class, || {
            let _ = key.sign(payload);
        });
    }
}

ctbench_main!(
    bench_shamir_split,
    bench_shamir_reconstruct,
    bench_ed25519_sign
);
