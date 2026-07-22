use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use hss_bench::{
    ddlog, decode_fixed, encode_fixed, encrypt, encrypt_with_randomizer, keygen, pow_signed,
    smul_party, validate, KeyMaterial, CIPHERTEXT_BYTES, INTEGER_BYTES,
};
use rand::{rngs::StdRng, thread_rng, Rng, RngCore, SeedableRng};
use rayon::{prelude::*, ThreadPool, ThreadPoolBuilder};
use rug::{integer::Order, Integer};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(about = "Measurement-only MORSE HSS harness")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Keygen {
        #[arg(long, default_value = "target/hss-key.bin")]
        output: PathBuf,
    },
    Run {
        #[arg(long, default_value = "target/hss-key.bin")]
        key: PathBuf,
        #[arg(long, default_value_t = 1000)]
        alerts: usize,
        #[arg(long, default_value_t = 100)]
        primitive_repetitions: usize,
    },
    Run2b {
        #[arg(long, default_value = "target/hss-key.bin")]
        key: PathBuf,
        #[arg(long, default_value_t = 1000)]
        alerts: usize,
    },
    #[command(hide = true)]
    Party0 {
        #[arg(long)]
        control: String,
        #[arg(long)]
        peer: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value_t = 1)]
        workers: usize,
        #[arg(long, default_value_t = 0.0)]
        rtt_ms: f64,
    },
    #[command(hide = true)]
    Party1 {
        #[arg(long)]
        listen: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value_t = 1)]
        workers: usize,
        #[arg(long, default_value_t = 0.0)]
        rtt_ms: f64,
    },
}

#[derive(Serialize, Deserialize)]
enum Request {
    Smul {
        verify: bool,
    },
    Compare {
        value: u32,
        threshold: u32,
        verify: bool,
    },
    CompareBatch {
        pairs: Vec<(u32, u32)>,
        verify: bool,
    },
    Stop,
}

#[derive(Serialize, Deserialize)]
struct Response {
    result: bool,
    protocol_ns: Option<u64>,
}

#[derive(Clone, Copy)]
struct Stats {
    mean_ms: f64,
    stddev_ms: f64,
    min_ms: f64,
    max_ms: f64,
}

fn stats(samples: &[f64]) -> Stats {
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let variance = samples
        .iter()
        .map(|sample| (sample - mean).powi(2))
        .sum::<f64>()
        / samples.len() as f64;
    Stats {
        mean_ms: mean,
        stddev_ms: variance.sqrt(),
        min_ms: samples.iter().copied().fold(f64::INFINITY, f64::min),
        max_ms: samples.iter().copied().fold(f64::NEG_INFINITY, f64::max),
    }
}

fn write_frame<T: Serialize>(stream: &mut TcpStream, value: &T) -> Result<usize> {
    let payload = bincode::serialize(value)?;
    stream.write_all(&(payload.len() as u64).to_be_bytes())?;
    stream.write_all(&payload)?;
    Ok(8 + payload.len())
}

fn read_frame<T: DeserializeOwned>(stream: &mut TcpStream) -> Result<(T, usize)> {
    let mut length = [0_u8; 8];
    stream.read_exact(&mut length)?;
    let length = u64::from_be_bytes(length) as usize;
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload)?;
    Ok((bincode::deserialize(&payload)?, 8 + length))
}

fn load_keys(path: &Path) -> Result<KeyMaterial> {
    bincode::deserialize_from(File::open(path).with_context(|| format!("open {}", path.display()))?)
        .context("decode key material")
}

fn alpha_shares(keys: &KeyMaterial) -> (Integer, Integer) {
    let share1 = deterministic_exact_bits(641, 0xADA0);
    let share0 = &share1 - Integer::from(2 * &keys.alpha);
    (share0, share1)
}

fn smul_shares(keys: &KeyMaterial) -> (Integer, Integer) {
    let share1 = deterministic_exact_bits(673, 0xAD23);
    let scaled_y = Integer::from(2 * &keys.alpha) * 23;
    let share0 = &share1 - scaled_y;
    (share0, share1)
}

fn deterministic_exact_bits(bits: u32, seed: u64) -> Integer {
    let mut bytes = vec![0_u8; bits.div_ceil(8) as usize];
    StdRng::seed_from_u64(seed).fill_bytes(&mut bytes);
    *bytes.last_mut().expect("positive bit length") |= 1 << ((bits - 1) % 8);
    Integer::from_digits(&bytes, Order::Lsf)
}

fn shared_smul_cipher(keys: &KeyMaterial) -> Integer {
    let r = deterministic_exact_bits(512, 0xC117);
    encrypt_with_randomizer(&keys.public, &Integer::from(17), &r)
}

fn connect_retry(address: &str) -> Result<TcpStream> {
    for _ in 0..200 {
        if let Ok(stream) = TcpStream::connect(address) {
            stream.set_nodelay(true)?;
            return Ok(stream);
        }
        thread::sleep(Duration::from_millis(25));
    }
    bail!("timed out connecting to {address}")
}

fn transport_delay(rtt_ms: f64) {
    if rtt_ms > 0.0 {
        thread::sleep(Duration::from_secs_f64(rtt_ms / 2_000.0));
    }
}

fn party1(address: &str, key_path: &Path, workers: usize, rtt_ms: f64) -> Result<()> {
    let keys = load_keys(key_path)?;
    let pool = ThreadPoolBuilder::new().num_threads(workers).build()?;
    let (_, alpha_share1) = alpha_shares(&keys);
    let encrypted_zero = encrypt(&keys.public, &Integer::from(0));
    let encrypted_one = encrypt(&keys.public, &Integer::from(1));
    let smul_cipher = shared_smul_cipher(&keys);
    let (_, smul_share1) = smul_shares(&keys);
    let listener = TcpListener::bind(address)?;
    let (mut peer, _) = listener.accept()?;
    peer.set_nodelay(true)?;
    loop {
        let mut command = [0_u8; 1];
        if peer.read_exact(&mut command).is_err() {
            return Ok(());
        }
        match command[0] {
            1 => {
                let mut d_bytes = vec![0; CIPHERTEXT_BYTES];
                let mut z0_bytes = vec![0; INTEGER_BYTES];
                peer.read_exact(&mut d_bytes)?;
                peer.read_exact(&mut z0_bytes)?;
                let d_cipher = decode_fixed(&d_bytes);
                let z0 = decode_fixed(&z0_bytes);
                let z1 = ddlog(
                    &keys.public.n,
                    &pow_signed(&d_cipher, &alpha_share1, &keys.public.n2),
                );
                let d = (z1 - z0).modulo(&keys.public.n);
                let answer = if d > Integer::from(&keys.public.n / 2) {
                    &encrypted_zero
                } else {
                    &encrypted_one
                };
                peer.write_all(&encode_fixed(answer, CIPHERTEXT_BYTES)?)?;
            }
            2 => {
                let started = Instant::now();
                let z1 = smul_party(&keys.public, &smul_cipher, &smul_share1);
                let elapsed_ns = started.elapsed().as_nanos() as u64;
                peer.write_all(&encode_fixed(&z1, INTEGER_BYTES)?)?;
                peer.write_all(&elapsed_ns.to_be_bytes())?;
            }
            3 => {
                let mut count_bytes = [0_u8; 4];
                peer.read_exact(&mut count_bytes)?;
                let count = u32::from_be_bytes(count_bytes) as usize;
                let mut inputs = Vec::with_capacity(count);
                for _ in 0..count {
                    let mut d_bytes = vec![0; CIPHERTEXT_BYTES];
                    let mut z0_bytes = vec![0; INTEGER_BYTES];
                    peer.read_exact(&mut d_bytes)?;
                    peer.read_exact(&mut z0_bytes)?;
                    inputs.push((decode_fixed(&d_bytes), decode_fixed(&z0_bytes)));
                }
                let answers: Vec<Integer> = pool.install(|| {
                    inputs
                        .par_iter()
                        .map(|(d_cipher, z0)| {
                            let z1 = ddlog(
                                &keys.public.n,
                                &pow_signed(d_cipher, &alpha_share1, &keys.public.n2),
                            );
                            let d = (z1 - z0).modulo(&keys.public.n);
                            if d > Integer::from(&keys.public.n / 2) {
                                encrypted_zero.clone()
                            } else {
                                encrypted_one.clone()
                            }
                        })
                        .collect()
                });
                transport_delay(rtt_ms);
                for answer in answers {
                    peer.write_all(&encode_fixed(&answer, CIPHERTEXT_BYTES)?)?;
                }
            }
            255 => return Ok(()),
            other => bail!("unknown peer command {other}"),
        }
    }
}

struct PreparedComparison {
    d_cipher: Integer,
    z0: Integer,
    pi: bool,
}

struct BatchExecution<'a> {
    pool: &'a ThreadPool,
    rtt_ms: f64,
    verify: bool,
}

fn prepare_comparison(
    keys: &KeyMaterial,
    alpha_share0: &Integer,
    encrypted: &[Integer],
    x: u32,
    y: u32,
) -> Result<PreparedComparison> {
    let pi = thread_rng().gen_bool(0.5);
    let r1 = {
        let mut bytes = [0_u8; 16];
        thread_rng().fill_bytes(&mut bytes);
        Integer::from_digits(&bytes, Order::Lsf) + 1
    };
    let offset = Integer::from(thread_rng().gen::<u128>()) % &r1;
    let r2 = Integer::from(&keys.public.n / 2) - offset;
    let cx = &encrypted[x as usize];
    let cy = &encrypted[y as usize];
    let base = if !pi {
        let cy_inverse = cy
            .clone()
            .invert(&keys.public.n2)
            .map_err(|_| anyhow::anyhow!("invert cy"))?;
        (cx * cy_inverse * &encrypted[1]).modulo(&keys.public.n2)
    } else {
        let cx_inverse = cx
            .clone()
            .invert(&keys.public.n2)
            .map_err(|_| anyhow::anyhow!("invert cx"))?;
        (cy * cx_inverse).modulo(&keys.public.n2)
    };
    let d_cipher = pow_signed(&base, &r1, &keys.public.n2);
    let z0 = (ddlog(
        &keys.public.n,
        &pow_signed(&d_cipher, alpha_share0, &keys.public.n2),
    ) - r2)
        .modulo(&keys.public.n);

    Ok(PreparedComparison { d_cipher, z0, pi })
}

fn finish_comparison(
    keys: &KeyMaterial,
    encrypted: &[Integer],
    prepared: &PreparedComparison,
    mu0: Integer,
) -> Result<Integer> {
    let output = if !prepared.pi {
        mu0
    } else {
        let inverse = mu0
            .invert(&keys.public.n2)
            .map_err(|_| anyhow::anyhow!("invert result"))?;
        (&encrypted[1] * inverse).modulo(&keys.public.n2)
    };
    let rerandomized = (output * &encrypted[0]).modulo(&keys.public.n2);
    Ok(rerandomized)
}

fn scmp(
    keys: &KeyMaterial,
    alpha_share0: &Integer,
    encrypted: &[Integer],
    x: u32,
    y: u32,
    peer: &mut TcpStream,
) -> Result<Integer> {
    let prepared = prepare_comparison(keys, alpha_share0, encrypted, x, y)?;
    peer.write_all(&[1])?;
    peer.write_all(&encode_fixed(&prepared.d_cipher, CIPHERTEXT_BYTES)?)?;
    peer.write_all(&encode_fixed(&prepared.z0, INTEGER_BYTES)?)?;
    let mut response = vec![0; CIPHERTEXT_BYTES];
    peer.read_exact(&mut response)?;
    finish_comparison(keys, encrypted, &prepared, decode_fixed(&response))
}

fn scmp_batch(
    keys: &KeyMaterial,
    alpha_share0: &Integer,
    encrypted: &[Integer],
    pairs: &[(u32, u32)],
    peer: &mut TcpStream,
    execution: BatchExecution<'_>,
) -> Result<bool> {
    let prepared: Vec<PreparedComparison> = execution.pool.install(|| {
        pairs
            .par_iter()
            .map(|&(x, y)| prepare_comparison(keys, alpha_share0, encrypted, x, y))
            .collect::<Result<Vec<_>>>()
    })?;
    transport_delay(execution.rtt_ms);
    peer.write_all(&[3])?;
    peer.write_all(&(prepared.len() as u32).to_be_bytes())?;
    for comparison in &prepared {
        peer.write_all(&encode_fixed(&comparison.d_cipher, CIPHERTEXT_BYTES)?)?;
        peer.write_all(&encode_fixed(&comparison.z0, INTEGER_BYTES)?)?;
    }
    let mut responses = Vec::with_capacity(prepared.len());
    for _ in 0..prepared.len() {
        let mut response = vec![0; CIPHERTEXT_BYTES];
        peer.read_exact(&mut response)?;
        responses.push(decode_fixed(&response));
    }
    let outputs = execution.pool.install(|| {
        prepared
            .par_iter()
            .zip(responses.into_par_iter())
            .map(|(comparison, response)| finish_comparison(keys, encrypted, comparison, response))
            .collect::<Result<Vec<_>>>()
    })?;
    if execution.verify {
        Ok(outputs
            .iter()
            .zip(pairs)
            .all(|(output, &(x, y))| (hss_bench::decrypt(keys, output) == 1) == (x < y)))
    } else {
        Ok(true)
    }
}

fn party0(
    control: &str,
    peer_address: &str,
    key_path: &Path,
    workers: usize,
    rtt_ms: f64,
) -> Result<()> {
    let keys = load_keys(key_path)?;
    let pool = ThreadPoolBuilder::new().num_threads(workers).build()?;
    let (alpha_share0, _) = alpha_shares(&keys);
    let encrypted: Vec<Integer> = (0..=100)
        .map(|value| encrypt(&keys.public, &Integer::from(value)))
        .collect();
    let smul_cipher = shared_smul_cipher(&keys);
    let (smul_share0, _) = smul_shares(&keys);
    let mut peer = connect_retry(peer_address)?;
    let listener = TcpListener::bind(control)?;
    let (mut client, _) = listener.accept()?;
    client.set_nodelay(true)?;
    loop {
        let (request, _) = read_frame::<Request>(&mut client)?;
        let (result, protocol_ns) = match request {
            Request::Smul { verify } => {
                peer.write_all(&[2])?;
                let started = Instant::now();
                let z0 = smul_party(&keys.public, &smul_cipher, &smul_share0);
                let party0_ns = started.elapsed().as_nanos() as u64;
                let mut z1_bytes = vec![0; INTEGER_BYTES];
                peer.read_exact(&mut z1_bytes)?;
                let mut timing_bytes = [0_u8; 8];
                peer.read_exact(&mut timing_bytes)?;
                let party1_ns = u64::from_be_bytes(timing_bytes);
                let correct = if verify {
                    let product = (decode_fixed(&z1_bytes) - z0).modulo(&keys.public.n);
                    let inverse = Integer::from(2 * &keys.alpha)
                        .invert(&keys.public.n)
                        .map_err(|_| anyhow::anyhow!("invert alpha"))?;
                    (product * inverse).modulo(&keys.public.n) == 17 * 23
                } else {
                    true
                };
                (correct, Some(party0_ns.max(party1_ns)))
            }
            Request::Compare {
                value,
                threshold,
                verify,
            } => {
                let output = scmp(
                    &keys,
                    &alpha_share0,
                    &encrypted,
                    value,
                    threshold,
                    &mut peer,
                )?;
                (
                    !verify || (hss_bench::decrypt(&keys, &output) == 1) == (value < threshold),
                    None,
                )
            }
            Request::CompareBatch { pairs, verify } => {
                let correct = scmp_batch(
                    &keys,
                    &alpha_share0,
                    &encrypted,
                    &pairs,
                    &mut peer,
                    BatchExecution {
                        pool: &pool,
                        rtt_ms,
                        verify,
                    },
                )?;
                (correct, None)
            }
            Request::Stop => {
                peer.write_all(&[255])?;
                write_frame(
                    &mut client,
                    &Response {
                        result: true,
                        protocol_ns: None,
                    },
                )?;
                return Ok(());
            }
        };
        write_frame(
            &mut client,
            &Response {
                result,
                protocol_ns,
            },
        )?;
    }
}

fn free_address() -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.to_string())
}

fn stop_children(children: &mut [Child]) {
    for child in children {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn round_trip(stream: &mut TcpStream, request: &Request) -> Result<(Duration, usize, Option<u64>)> {
    let started = Instant::now();
    let sent = write_frame(stream, request)?;
    let (response, received) = read_frame::<Response>(stream)?;
    let elapsed = started.elapsed();
    if !response.result {
        bail!("protocol returned an incorrect result");
    }
    Ok((elapsed, sent + received, response.protocol_ns))
}

fn start_pair(
    executable: &Path,
    key_path: &Path,
    workers: usize,
    rtt_ms: f64,
) -> Result<(Vec<Child>, TcpStream)> {
    let peer_address = free_address()?;
    let control_address = free_address()?;
    let workers_arg = workers.to_string();
    let rtt_arg = rtt_ms.to_string();
    let children = vec![
        Command::new(executable)
            .args(["party1", "--listen", &peer_address, "--key"])
            .arg(key_path)
            .args(["--workers", &workers_arg, "--rtt-ms", &rtt_arg])
            .stdout(Stdio::null())
            .spawn()?,
        Command::new(executable)
            .args([
                "party0",
                "--control",
                &control_address,
                "--peer",
                &peer_address,
                "--key",
            ])
            .arg(key_path)
            .args(["--workers", &workers_arg, "--rtt-ms", &rtt_arg])
            .stdout(Stdio::null())
            .spawn()?,
    ];
    let control = connect_retry(&control_address)?;
    Ok((children, control))
}

fn synthetic_pairs(first_alert: usize, alert_count: usize, thresholds: usize) -> Vec<(u32, u32)> {
    let mut pairs = Vec::with_capacity(alert_count * thresholds);
    for alert in first_alert..first_alert + alert_count {
        for node in 0..thresholds {
            let feature = (alert * 17 + node * 13) % 50;
            let value = ((alert * 31 + feature * 7) % 101) as u32;
            let threshold = ((node * 19 + 23) % 101) as u32;
            pairs.push((value, threshold));
        }
    }
    pairs
}

struct ScenarioResult {
    per_alert: Stats,
    alerts_per_second: f64,
}

fn measure_batch_scenario(
    executable: &Path,
    key_path: &Path,
    workers: usize,
    rtt_ms: f64,
    thresholds: usize,
    batch_alerts: usize,
    alerts: usize,
) -> Result<ScenarioResult> {
    let (mut children, mut control) = start_pair(executable, key_path, workers, rtt_ms)?;
    let result = (|| -> Result<ScenarioResult> {
        round_trip(
            &mut control,
            &Request::CompareBatch {
                pairs: synthetic_pairs(0, 1, thresholds),
                verify: true,
            },
        )?;
        let mut samples = Vec::with_capacity(alerts.div_ceil(batch_alerts));
        let mut measured = Duration::ZERO;
        let mut completed = 0;
        while completed < alerts {
            let in_batch = batch_alerts.min(alerts - completed);
            let (elapsed, _, _) = round_trip(
                &mut control,
                &Request::CompareBatch {
                    pairs: synthetic_pairs(completed, in_batch, thresholds),
                    verify: false,
                },
            )?;
            measured += elapsed;
            samples.push(elapsed.as_secs_f64() * 1000.0 / in_batch as f64);
            completed += in_batch;
        }
        round_trip(&mut control, &Request::Stop)?;
        let mut per_alert = stats(&samples);
        per_alert.mean_ms = measured.as_secs_f64() * 1000.0 / alerts as f64;
        Ok(ScenarioResult {
            per_alert,
            alerts_per_second: alerts as f64 / measured.as_secs_f64(),
        })
    })();
    stop_children(&mut children);
    result
}

fn run_2b(key_path: &Path, alerts: usize) -> Result<()> {
    validate(&load_keys(key_path)?)?;
    let executable = std::env::current_exe()?;
    println!("# HSS Test 2B raw results");
    println!("alerts_per_scenario={alerts}");

    for thresholds in [20_usize, 50, 100, 200, 500] {
        let result = measure_batch_scenario(&executable, key_path, 16, 0.0, thresholds, 1, alerts)?;
        println!(
            "high_k k={thresholds} workers=16 mean_ms={:.6} stddev_ms={:.6} min_ms={:.6} max_ms={:.6} alerts_per_second={:.6} bytes_per_alert={} us_per_threshold={:.6}",
            result.per_alert.mean_ms,
            result.per_alert.stddev_ms,
            result.per_alert.min_ms,
            result.per_alert.max_ms,
            result.alerts_per_second,
            thresholds * 1920,
            result.per_alert.mean_ms * 1000.0 / thresholds as f64,
        );
    }

    for workers in [1_usize, 2, 4, 8, 16] {
        let result = measure_batch_scenario(&executable, key_path, workers, 0.0, 50, 1, alerts)?;
        println!(
            "parallel k=50 workers={workers} mean_ms={:.6} stddev_ms={:.6} min_ms={:.6} max_ms={:.6} alerts_per_second={:.6}",
            result.per_alert.mean_ms,
            result.per_alert.stddev_ms,
            result.per_alert.min_ms,
            result.per_alert.max_ms,
            result.alerts_per_second,
        );
    }

    for rtt_ms in [0.0_f64, 1.0, 5.0, 20.0] {
        for batch_alerts in [1_usize, 10, 100, 1000] {
            let result = measure_batch_scenario(
                &executable,
                key_path,
                16,
                rtt_ms,
                50,
                batch_alerts,
                alerts,
            )?;
            println!(
                "network k=50 workers=16 rtt_ms={rtt_ms:.1} batch={batch_alerts} mean_ms={:.6} stddev_ms={:.6} min_ms={:.6} max_ms={:.6} alerts_per_second={:.6}",
                result.per_alert.mean_ms,
                result.per_alert.stddev_ms,
                result.per_alert.min_ms,
                result.per_alert.max_ms,
                result.alerts_per_second,
            );
        }
    }
    Ok(())
}

fn run(key_path: &Path, alerts: usize, primitive_repetitions: usize) -> Result<()> {
    let keys = load_keys(key_path)?;
    validate(&keys)?;
    let peer_address = free_address()?;
    let control_address = free_address()?;
    let executable = std::env::current_exe()?;
    let mut children = vec![
        Command::new(&executable)
            .args(["party1", "--listen", &peer_address, "--key"])
            .arg(key_path)
            .stdout(Stdio::null())
            .spawn()?,
        Command::new(&executable)
            .args([
                "party0",
                "--control",
                &control_address,
                "--peer",
                &peer_address,
                "--key",
            ])
            .arg(key_path)
            .stdout(Stdio::null())
            .spawn()?,
    ];
    let result = (|| -> Result<()> {
        let mut control = connect_retry(&control_address)?;
        for (value, threshold) in [(17, 50), (50, 50), (83, 50)] {
            for _ in 0..4 {
                round_trip(
                    &mut control,
                    &Request::Compare {
                        value,
                        threshold,
                        verify: true,
                    },
                )?;
            }
        }
        round_trip(&mut control, &Request::Smul { verify: true })?;
        let base = encrypt(&keys.public, &Integer::from(42));
        let exponent = deterministic_exact_bits(673, 0xE673);
        let g = pow_signed(&base, &exponent, &keys.public.n2);
        let mut modexp_samples = Vec::with_capacity(primitive_repetitions);
        let mut ddlog_samples = Vec::with_capacity(primitive_repetitions);
        for _ in 0..primitive_repetitions {
            let start = Instant::now();
            let _ = pow_signed(&base, &exponent, &keys.public.n2);
            modexp_samples.push(start.elapsed().as_secs_f64() * 1000.0);
            let start = Instant::now();
            let _ = ddlog(&keys.public.n, &g);
            ddlog_samples.push(start.elapsed().as_secs_f64() * 1000.0);
        }

        let mut smul_wall_samples = Vec::with_capacity(primitive_repetitions);
        let mut smul_compute_samples = Vec::with_capacity(primitive_repetitions);
        let mut smul_control_bytes = 0;
        for _ in 0..primitive_repetitions {
            let (elapsed, bytes, protocol_ns) =
                round_trip(&mut control, &Request::Smul { verify: false })?;
            smul_wall_samples.push(elapsed.as_secs_f64() * 1000.0);
            smul_compute_samples.push(protocol_ns.expect("SMUL timing") as f64 / 1_000_000.0);
            smul_control_bytes += bytes;
        }

        let mut scmp_samples = Vec::with_capacity(primitive_repetitions);
        let mut scmp_control_bytes = 0;
        for i in 0..primitive_repetitions {
            let (elapsed, bytes, _) = round_trip(
                &mut control,
                &Request::Compare {
                    value: (i % 100) as u32,
                    threshold: 50,
                    verify: false,
                },
            )?;
            scmp_samples.push(elapsed.as_secs_f64() * 1000.0);
            scmp_control_bytes += bytes;
        }

        let mut scorer = Vec::new();
        for thresholds in [5_usize, 10, 20, 50] {
            let mut alert_samples = Vec::with_capacity(alerts);
            let mut control_bytes = 0_usize;
            for alert in 0..alerts {
                let started = Instant::now();
                for node in 0..thresholds {
                    let feature = ((alert * 17 + node * 13) % 50) as u32;
                    let value = ((alert * 31 + feature as usize * 7) % 101) as u32;
                    let threshold = ((node * 19 + 23) % 101) as u32;
                    let (_, bytes, _) = round_trip(
                        &mut control,
                        &Request::Compare {
                            value,
                            threshold,
                            verify: false,
                        },
                    )?;
                    control_bytes += bytes;
                }
                alert_samples.push(started.elapsed().as_secs_f64() * 1000.0);
            }
            scorer.push((thresholds, stats(&alert_samples), control_bytes / alerts));
        }
        let _ = round_trip(&mut control, &Request::Stop)?;

        let modexp = stats(&modexp_samples);
        let ddlog_result = stats(&ddlog_samples);
        let smul_wall = stats(&smul_wall_samples);
        let smul_compute = stats(&smul_compute_samples);
        let scmp_result = stats(&scmp_samples);
        println!("# HSS benchmark raw results");
        println!("primitive_repetitions={primitive_repetitions} alerts_per_k={alerts}");
        print_stats("modexp", modexp, 0, 0);
        print_stats("ddlog", ddlog_result, 0, 0);
        print_stats("smul_compute", smul_compute, 0, 0);
        print_stats(
            "smul_process_wall",
            smul_wall,
            0,
            smul_control_bytes / primitive_repetitions,
        );
        print_stats(
            "scmp",
            scmp_result,
            1920,
            scmp_control_bytes / primitive_repetitions,
        );
        for (k, result, control_bytes) in scorer {
            println!(
                "scorer_k={k} mean_ms={:.6} stddev_ms={:.6} min_ms={:.6} max_ms={:.6} peer_payload_bytes={} peer_framed_bytes={} control_framed_bytes={}",
                result.mean_ms,
                result.stddev_ms,
                result.min_ms,
                result.max_ms,
                k * 1920,
                k * 1921,
                control_bytes,
            );
        }
        Ok(())
    })();
    stop_children(&mut children);
    result
}

fn print_stats(name: &str, result: Stats, peer_payload: usize, control_bytes: usize) {
    println!(
        "{name} mean_ms={:.6} stddev_ms={:.6} min_ms={:.6} max_ms={:.6} peer_payload_bytes={peer_payload} control_framed_bytes={control_bytes}",
        result.mean_ms, result.stddev_ms, result.min_ms, result.max_ms
    );
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Keygen { output } => {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            let started = Instant::now();
            let keys = keygen();
            validate(&keys)?;
            bincode::serialize_into(File::create(&output)?, &keys)?;
            eprintln!(
                "generated and validated 3072-bit key in {:.1}s: {}",
                started.elapsed().as_secs_f64(),
                output.display()
            );
            Ok(())
        }
        Commands::Run {
            key,
            alerts,
            primitive_repetitions,
        } => run(&key, alerts, primitive_repetitions),
        Commands::Run2b { key, alerts } => run_2b(&key, alerts),
        Commands::Party0 {
            control,
            peer,
            key,
            workers,
            rtt_ms,
        } => party0(&control, &peer, &key, workers, rtt_ms),
        Commands::Party1 {
            listen,
            key,
            workers,
            rtt_ms,
        } => party1(&listen, &key, workers, rtt_ms),
    }
}
