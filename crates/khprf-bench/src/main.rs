//! Test 11: key-homomorphic PRF with epochs and rotation via an update tweak.
//!
//! The first real cryptography in the Test 5-12 chain. Tests 8-10 established
//! that deterministic tokens leak linkage unconditionally, that padding it away
//! costs multiples of the index, and that epoch rotation trades that leakage
//! against investigative reach. Rotation is only a usable lever if rotating is
//! cheap, so this measures what it actually costs.
//!
//! Construction. Over Ristretto255, with `H` a hash-to-group:
//!
//!     F(k, x) = k * H(x)
//!
//! Key homomorphism (Boneh-Lewi-Montgomery-Raghunathan, CRYPTO 2013):
//!
//!     F(k1 + k2, x) = F(k1, x) + F(k2, x)
//!
//! Epoch rotation follows the updatable-tokenisation construction of Cachin,
//! Camenisch, Freire-Stoegbuchner and Lehmann (eprint 2017/695). The update
//! tweak for epoch e -> e+1 is the *multiplicative* scalar
//!
//!     delta = k_{e+1} * k_e^{-1}
//!
//! so a stored token rotates as `t' = delta * t`, with no access to the
//! preimage `x` and no re-derivation. That property is the whole point: the
//! party holding the token store never needs the input or the key.
//!
//! This is unaudited research code for measurement only. It implements no key
//! custody, no DKG, no constant-time guarantees beyond what the underlying
//! library provides, and no protocol around the primitive.

use anyhow::Result;
use clap::Parser;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha512};
use std::time::Instant;

const DOMAIN: &[u8] = b"ADAM_KHPRF_V1";

/// Hash-to-group via SHA-512 and Elligator, as provided by ristretto255.
fn hash_to_curve(input: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(DOMAIN);
    h.update(input);
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// F(k, x) = k * H(x)
fn eval(key: &Scalar, input: &[u8]) -> RistrettoPoint {
    hash_to_curve(input) * key
}

fn random_scalar(rng: &mut ChaCha20Rng) -> Scalar {
    let mut b = [0u8; 64];
    use rand::RngCore;
    rng.fill_bytes(&mut b);
    Scalar::from_bytes_mod_order_wide(&b)
}

/// Synthetic entity identifiers. Real telemetry is not needed to measure the
/// primitive, and none is used.
fn synthetic_inputs(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            format!(
                "host-{}.corp.example|user{}|10.{}.{}.{}",
                i % 4096,
                i % 100_003,
                (i >> 16) & 0xff,
                (i >> 8) & 0xff,
                i & 0xff
            )
            .into_bytes()
        })
        .collect()
}

#[derive(Serialize)]
struct Timing {
    label: String,
    items: usize,
    repetitions: usize,
    mean_ms: f64,
    min_ms: f64,
    max_ms: f64,
    per_item_us: f64,
    items_per_second: f64,
}

fn time_it<F: FnMut()>(label: &str, items: usize, repetitions: usize, mut f: F) -> Timing {
    let mut samples = Vec::with_capacity(repetitions);
    for _ in 0..repetitions {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let min = samples.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    Timing {
        label: label.to_string(),
        items,
        repetitions,
        mean_ms: mean,
        min_ms: min,
        max_ms: max,
        per_item_us: mean * 1000.0 / items as f64,
        items_per_second: items as f64 / (mean / 1000.0),
    }
}

/// Resident set size in bytes, read from /proc. Used to check the stored-token
/// figure against something other than arithmetic.
fn rss_bytes() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = s.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4096)
}

#[derive(Serialize)]
struct Correctness {
    key_homomorphism: bool,
    rotation_matches_fresh_derivation: bool,
    rotation_chain_matches_fresh_derivation: bool,
    tokens_differ_across_epochs: bool,
    determinism_within_epoch: bool,
}

fn check_correctness(rng: &mut ChaCha20Rng) -> Correctness {
    let x = b"host-1.corp.example|user7|10.0.0.5";
    let k1 = random_scalar(rng);
    let k2 = random_scalar(rng);

    // F(k1 + k2, x) == F(k1, x) + F(k2, x)
    let homomorphic = eval(&(k1 + k2), x) == eval(&k1, x) + eval(&k2, x);

    // One rotation: delta = k2 * k1^{-1}, t2 = delta * t1
    let t1 = eval(&k1, x);
    let delta = k2 * k1.invert();
    let rotated = t1 * delta;
    let fresh = eval(&k2, x);
    let single = rotated == fresh;

    // A chain of rotations must land on the same point as fresh derivation
    // under the final key, which is what makes multi-epoch storage viable.
    let mut key = k1;
    let mut token = t1;
    for _ in 0..8 {
        let next = random_scalar(rng);
        token *= next * key.invert();
        key = next;
    }
    let chained = token == eval(&key, x);

    let differ = eval(&k1, x) != eval(&k2, x);
    let deterministic = eval(&k1, x) == eval(&k1, x);

    Correctness {
        key_homomorphism: homomorphic,
        rotation_matches_fresh_derivation: single,
        rotation_chain_matches_fresh_derivation: chained,
        tokens_differ_across_epochs: differ,
        determinism_within_epoch: deterministic,
    }
}

#[derive(Parser)]
#[command(about = "Test 11: key-homomorphic PRF epoch rotation measurement")]
struct Args {
    /// Token counts to measure rotation over.
    #[arg(long, value_delimiter = ',', default_values_t = vec![10_000usize, 1_000_000, 10_000_000])]
    rotate: Vec<usize>,
    /// Inputs used for the derivation-throughput measurement.
    #[arg(long, default_value_t = 200_000)]
    derive: usize,
    #[arg(long, default_value_t = 5)]
    repetitions: usize,
    #[arg(long)]
    json: Option<String>,
}

#[derive(Serialize)]
struct Report {
    construction: String,
    group: String,
    token_bytes_compressed: usize,
    correctness: Correctness,
    derivation: Vec<Timing>,
    rotation: Vec<Timing>,
    memory: Vec<MemoryPoint>,
    threads: usize,
}

#[derive(Serialize)]
struct MemoryPoint {
    tokens: usize,
    stored_bytes: usize,
    bytes_per_token: f64,
    measured: bool,
    process_rss_bytes: Option<u64>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut rng = ChaCha20Rng::seed_from_u64(20_260_724);

    let correctness = check_correctness(&mut rng);

    let key = random_scalar(&mut rng);
    let next_key = random_scalar(&mut rng);
    let delta = next_key * key.invert();

    // ---- derivation throughput -------------------------------------------
    let inputs = synthetic_inputs(args.derive);
    let mut derivation = Vec::new();
    let mut sink = RistrettoPoint::default();

    derivation.push(time_it(
        "derive, single thread",
        args.derive,
        args.repetitions,
        || {
            let mut acc = RistrettoPoint::default();
            for x in &inputs {
                acc += eval(&key, x);
            }
            sink = acc;
        },
    ));
    std::hint::black_box(sink);

    let threads = rayon::current_num_threads();
    derivation.push(time_it(
        "derive, all threads",
        args.derive,
        args.repetitions,
        || {
            let acc: RistrettoPoint = inputs
                .par_iter()
                .map(|x| eval(&key, x))
                .reduce(RistrettoPoint::default, |a, b| a + b);
            std::hint::black_box(acc);
        },
    ));

    // Hash-to-curve alone, to attribute the derivation cost.
    derivation.push(time_it(
        "hash-to-curve only, single thread",
        args.derive,
        args.repetitions,
        || {
            let mut acc = RistrettoPoint::default();
            for x in &inputs {
                acc += hash_to_curve(x);
            }
            std::hint::black_box(acc);
        },
    ));

    // ---- rotation ---------------------------------------------------------
    let mut rotation = Vec::new();
    let mut memory = Vec::new();

    for &count in &args.rotate {
        // An in-memory RistrettoPoint is 160 bytes against 32 compressed, so
        // above a threshold only the compressed path is measured: holding
        // several point-vectors of that size would measure swap, not crypto.
        let points_fit = count <= 1_000_000;
        let base = synthetic_inputs(count.min(200_000));

        // Rotation cost does not depend on the preimage, so inputs are reused
        // cyclically above the generated set.
        let compressed: Vec<CompressedRistretto> = (0..count)
            .into_par_iter()
            .map(|i| eval(&key, &base[i % base.len()]).compress())
            .collect();

        memory.push(MemoryPoint {
            tokens: count,
            stored_bytes: compressed.len() * 32,
            bytes_per_token: 32.0,
            measured: true,
            process_rss_bytes: rss_bytes(),
        });

        let reps = if count > 1_000_000 {
            1
        } else {
            args.repetitions.min(3)
        };

        if points_fit {
            let points: Vec<RistrettoPoint> = compressed
                .par_iter()
                .map(|c| c.decompress().expect("valid token"))
                .collect();

            let mut pts = points.clone();
            rotation.push(time_it(
                &format!("rotate in-memory points, {count} tokens, single thread"),
                count,
                reps,
                || {
                    for p in pts.iter_mut() {
                        *p *= delta;
                    }
                },
            ));

            let mut pts2 = points;
            rotation.push(time_it(
                &format!("rotate in-memory points, {count} tokens, all threads"),
                count,
                reps,
                || {
                    pts2.par_iter_mut().for_each(|p| *p *= delta);
                },
            ));
        }

        rotation.push(time_it(
            &format!("rotate stored tokens (decompress+mul+compress), {count} tokens, all threads"),
            count,
            reps,
            || {
                let out: Vec<CompressedRistretto> = compressed
                    .par_iter()
                    .map(|c| (c.decompress().expect("valid token") * delta).compress())
                    .collect();
                std::hint::black_box(out.len());
            },
        ));
    }

    let report = Report {
        construction: "F(k,x) = k * H(x); rotation t' = (k_new * k_old^-1) * t".to_string(),
        group: "ristretto255 (curve25519-dalek 4)".to_string(),
        token_bytes_compressed: 32,
        correctness,
        derivation,
        rotation,
        memory,
        threads,
    };

    let json = serde_json::to_string_pretty(&report)?;
    println!("{json}");
    if let Some(path) = args.json {
        std::fs::write(path, json)?;
    }
    Ok(())
}
