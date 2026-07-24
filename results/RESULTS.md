# ADAM research results

Only absolute measurements belong here. Data for the benchmark experiments
(Tests 1–4) is synthetic. The corpus analyses (Tests 5 onward) use public
corpora, cloned separately and not vendored; where those tests still need a
distribution that no public corpus carries — such as command execution
frequency in Test 8 — the assumed model is marked synthetic at the point of
use.

## Test 1: MORSE HSS throughput

### Result

Run completed 2026-07-22. This is a single-host localhost measurement of two
separate party processes, not a WAN projection.

| Operation | Repetitions | Mean (ms) | Std. dev. (ms) | Min (ms) | Max (ms) | MORSE peer payload (bytes/op) |
|---|---:|---:|---:|---:|---:|---:|
| Modular exponentiation mod N², dense 673-bit exponent | 500 | 8.713 | 0.210 | 8.603 | 10.596 | 0 |
| DDLog | 500 | 0.029 | 0.006 | 0.026 | 0.061 | 0 |
| SMUL_HSS, max local compute of the two parties | 500 | 8.914 | 0.757 | 8.650 | 14.395 | 0 |
| SMUL_HSS, coordinator wall-clock over localhost TCP | 500 | 9.120 | 0.765 | 8.844 | 14.653 | 0¹ |
| SCMP_HSS, coordinator wall-clock over localhost TCP | 500 | 19.483 | 1.493 | 18.701 | 29.584 | 1,920 |

¹ SMUL_HSS is non-interactive in MORSE. The process harness exchanges a 1-byte
start command, the 384-byte output share, and an 8-byte timing value solely to
synchronize and verify the separate processes. These 393 harness bytes are not
cryptographic protocol bandwidth. The coordinator control channel adds 31
application-framing bytes per measured operation. For SCMP, the party channel
uses the 1,920-byte protocol transcript plus a 1-byte harness command, while the
coordinator control channel adds 31 bytes. TCP/IP headers are not included.

Criterion independently measured the same local primitives (100 statistical
samples after a 3-second warmup):

| Criterion benchmark | Estimate |
|---|---:|
| Modular exponentiation mod N², dense 673-bit exponent | 8.969 ms (95% CI 8.941–9.010 ms) |
| DDLog | 0.02523 ms (95% CI 0.02519–0.02528 ms) |

### Synthetic alert scorer

The scorer has 50 encrypted synthetic features and evaluates all K threshold
nodes. Each row is an independent measurement of exactly 1,000 alerts. The
estimated column is `K × 19.483 ms`, using the separately measured mean SCMP;
the measured column is the actual end-to-end 1,000-alert run.

| K thresholds | Alerts | Measured ms/alert | Std. dev. (ms) | Min (ms) | Max (ms) | Bytes/alert | Estimert ms per varsel ved K terskler |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 | 1,000 | 96.459 | 4.664 | 93.820 | 130.998 | 9,600 | 97.414 |
| 10 | 1,000 | 192.840 | 8.001 | 187.777 | 269.468 | 19,200 | 194.828 |
| 20 | 1,000 | 385.908 | 14.142 | 375.272 | 516.971 | 38,400 | 389.655 |
| 50 | 1,000 | 956.206 | 18.596 | 938.061 | 1,191.708 | 96,000 | 974.139 |

### Hardware and software

- Secure E2B orb (KVM), Linux 6.1.158, x86-64
- Intel Xeon Processor at 2.60 GHz; 1 socket, 8 physical cores, 2 threads/core,
  16 logical CPUs exposed
- 33,672,245,248 bytes RAM (31.36 GiB), no swap
- Rust 1.97.1, release profile; `rug` 1.30.0 over GMP 6.2.1
- One thread per party; two persistent OS processes over localhost TCP
- FastPaillier `|N| = 3072`, `|alpha| = 512`, statistical security parameter
  128 bits, 32-bit synthetic values

### Comparison with MORSE

Deng et al. report SCMP_HSS at **13.9 ms and 1.874 KB** on an Intel i7-11700
at 2.50 GHz with Python/gmpy2, using 500 repetitions. This run measures
**19.483 ms and 1,920 bytes (1.875 KiB)**. The bandwidth agrees with the
paper's `5|N|`-bit formula after unit rounding. Runtime is materially different:
the absolute gap is **5.583 ms per comparison**.

This discrepancy is explicitly flagged rather than converted into a speedup.
The implementation was checked for accidental decryption/setup work in the
timed region, unused modular inversions, sparse exponents, and serialized party
execution; those issues are not present in this run. Correctness warmups verify
FastPaillier encryption/decryption, SMUL reconstruction, and SCMP output. The
remaining runtime gap may reflect CPU, language/binding, GMP build, and
localhost orchestration differences, so these numbers should be treated as an
ADAM feasibility measurement, not as a bit-for-bit reproduction of the paper's
machine.

### Reproduction

```sh
cargo run --release -p hss-bench -- keygen
cargo bench -p hss-bench --bench primitives
cargo run --release -p hss-bench -- run \
  --primitive-repetitions 500 --alerts 1000
```

## Test 2B: locating the actual limit

Run completed 2026-07-22 on the same hardware and FastPaillier parameters listed
above. Every row covers exactly 1,000 synthetic alerts. The two parties remained
separate persistent processes over localhost TCP.

The batched protocol evaluates independent SCMP instances concurrently and
sends all `(D, z0)` values in one request and all encrypted answers in one
response. It therefore uses one party-to-party round per batch without changing
the statement or bandwidth: every comparison still transfers exactly 1,920
protocol bytes. One correctness batch is decrypted outside the timed region
before each scenario.

### Higher K

Each alert is one batch, using 16 worker threads in each party. Input generation,
encryption, process startup, pool creation, and warmup are excluded; wall-clock
includes coordinator framing, both party compute phases, TCP transfer, and the
single protocol round.

| K | Alerts | Mean ms/alert | Std. dev. (ms) | Min (ms) | Max (ms) | Alerts/s | Bytes/alert |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 20 | 1,000 | 40.705 | 0.823 | 39.355 | 46.105 | 24.567 | 38,400 |
| 50 | 1,000 | 78.635 | 1.136 | 77.280 | 88.853 | 12.717 | 96,000 |
| 100 | 1,000 | 136.591 | 3.472 | 134.225 | 180.527 | 7.321 | 192,000 |
| 200 | 1,000 | 253.154 | 8.606 | 248.136 | 379.322 | 3.950 | 384,000 |
| 500 | 1,000 | 615.991 | 9.758 | 604.487 | 703.103 | 1.623 | 960,000 |

An affine fit is `ms/alert = 16.854 + 1.19633 × K`, with `R² = 0.999937`.
Therefore wall-clock remains linear over K=20–500. Strict proportionality
through the origin does not hold at low K because a fixed round/setup cost and
partially filled 16-worker waves are visible; this is not a cryptographic
linearity break. Protocol bytes are exactly linear at `1,920 × K`.

### Parallelism at K=50

Each alert contains 50 comparisons in one round. Both parties use the stated
number of worker threads.

| Workers/party | Alerts | Mean effective ms/alert | Std. dev. (ms) | Min (ms) | Max (ms) | Alerts/s | Absolute scaling vs. 1 worker | Efficiency |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1,000 | 960.409 | 18.085 | 946.105 | 1,222.494 | 1.041 | 1.000× | 100.0% |
| 2 | 1,000 | 488.776 | 18.053 | 471.921 | 628.925 | 2.046 | 1.965× | 98.2% |
| 4 | 1,000 | 247.316 | 5.358 | 243.032 | 292.775 | 4.043 | 3.883× | 97.1% |
| 8 | 1,000 | 133.884 | 2.069 | 132.034 | 147.391 | 7.469 | 7.173× | 89.7% |
| 16 | 1,000 | 78.193 | 1.066 | 77.047 | 86.894 | 12.789 | 12.283× | 76.8% |

There is no hard Amdahl plateau by 16 workers, but scaling is no longer linear
after four workers. The measured 16-worker ceiling on this 8-core/16-thread orb
is 12.789 alerts/s at K=50. This is consistent with SMT contention, fixed
round/serialization work, and the sequential party-0 → party-1 → party-0 phases.

### RTT and batch size at K=50

All rows use 16 workers per party and 1,000 alerts. Artificial RTT is implemented
as a transport-layer sleep: party 0 waits RTT/2 before the batch request and
party 1 waits RTT/2 before its response. `tc netem` was deliberately not used,
because shaping loopback would also delay the coordinator channel and unrelated
orb traffic. The sleep is inside the measured interval and occurs once per
batch, not once per comparison.

| Artificial RTT | Batch 1 ms/alert | Batch 10 ms/alert | Batch 100 ms/alert | Batch 1,000 ms/alert |
|---:|---:|---:|---:|---:|
| 0 ms | 78.418 ± 1.231 | 61.174 ± 0.432 | 60.502 ± 0.322 | 61.008 ± 0.000¹ |
| 1 ms | 79.585 ± 1.211 | 61.275 ± 0.507 | 60.150 ± 0.283 | 60.172 ± 0.000¹ |
| 5 ms | 83.641 ± 1.686 | 61.762 ± 0.545 | 60.331 ± 0.210 | 60.378 ± 0.000¹ |
| 20 ms | 98.682 ± 1.639 | 63.396 ± 0.545 | 60.595 ± 0.209 | 60.659 ± 0.000¹ |

¹ Batch 1,000 has one batch observation containing all 1,000 alerts, so its
standard deviation is mechanically zero; it is an amortized batch result, not
an alert-latency distribution.

The batching hypothesis is supported. At batch 1, adding 20 ms RTT increases
wall-clock from 78.418 to 98.682 ms/alert. At batch 10 the corresponding values
are 61.174 and 63.396 ms/alert. At batch 100 and 1,000 the expected RTT terms are
0.200 and 0.020 ms/alert, respectively, below ordinary run-to-run compute noise.
RTT is therefore a real limit for unbatched alerts and is effectively amortized
away by large batches. Batching also improves the 0-RTT compute result because
larger worker queues amortize coordinator/round overhead and keep the pools full.

### Inter-cluster bandwidth projection

Decimal GB (`10⁹` bytes), counting the combined two-direction MORSE transcript.
This is traffic volume, not a measured WAN throughput claim.

| K | Bytes/alert | 1,000 alerts/day | 10,000 alerts/day | 100,000 alerts/day |
|---:|---:|---:|---:|---:|
| 20 | 38,400 | 0.0384 GB/day | 0.384 GB/day | 3.84 GB/day |
| 50 | 96,000 | 0.0960 GB/day | 0.960 GB/day | 9.60 GB/day |
| 100 | 192,000 | 0.192 GB/day | 1.92 GB/day | 19.20 GB/day |
| 200 | 384,000 | 0.384 GB/day | 3.84 GB/day | 38.40 GB/day |
| 500 | 960,000 | 0.960 GB/day | 9.60 GB/day | 96.00 GB/day |

Even the largest projection, 96 GB/day, averages 8.89 Mbit/s over a day. The
volume grows exactly linearly with K, but this localhost experiment does not
measure congestion, cloud egress pricing, or sustained WAN capacity.

### Compute cost model

Assumptions:

- **USD 0.04 per vCPU-hour** (explicit modeling assumption, not a vendor quote)
- one customer produces **10,000 alerts/day**, 365 days/year
- K=50 one-worker wall-clock is 960.409 ms/alert; K=20 and K=200 are projected
  linearly from that absolute baseline
- conservative provisioned-runtime accounting: each party is charged for the
  full end-to-end one-worker wall-clock, including time waiting for its peer;
  two parties therefore double billed vCPU time as requested
- no idle, memory, storage, network, orchestration, or minimum-instance cost

| K | Compute ms/alert/party | Billed vCPU-hours/alert, two parties | Compute USD/alert | Billed vCPU-hours/customer/year | Compute USD/customer/year |
|---:|---:|---:|---:|---:|---:|
| 20 | 384.163 | 0.0002134 | 0.00000854 | 779.0 | 31.16 |
| 50 | 960.409 | 0.0005336 | 0.00002134 | 1,947.5 | 77.90 |
| 200 | 3,841.634 | 0.0021342 | 0.00008537 | 7,790.0 | 311.60 |

Parallel workers reduce latency and increase throughput but do not remove the
underlying vCPU-seconds, so the cost model deliberately uses the one-worker
baseline rather than treating the 16-worker wall-clock as free compute.

### Test 2B conclusion

- **K is not a nonlinear failure point:** compute time and bytes remain linear.
- **CPU parallelism remains useful:** 1 to 16 workers raises K=50 throughput
  from 1.041 to 12.789 alerts/s, with diminishing efficiency but no hard plateau.
- **RTT is only a limit without batching:** one shared round amortizes it to
  `RTT / batch_size` per alert.
- **Bandwidth is deterministic:** `1,920 × K` bytes/alert. At the requested daily
  volumes the projection is 0.0384–96.00 GB/day.
- On this hardware, after batching, the measured per-alert wall-clock is still
  dominated by cryptographic compute (~60–61 ms at K=50), not RTT. Whether
  bandwidth becomes the deployment limit requires a rate-limited WAN test;
  Test 2B establishes the exact traffic volume but does not assume that result.

Reproduce the complete matrix with:

```sh
cargo run --release -p hss-bench -- run2b --alerts 1000
```

## Test 3: SP1 verifiable-encryption statement

### Result

Run completed 2026-07-22 with SP1 6.3.1. The benchmark proves one synthetic
ADAM alert per proof.

| Mode | Repetitions | Mean (ms/alert) | Std. dev. (ms) | Min (ms) | Max (ms) | zkVM cycles |
|---|---:|---:|---:|---:|---:|---:|
| Execute (non-proving baseline) | 10 | 80.218 | 9.138 | 72.278 | 105.207 | 480,879 |
| Mock prover, compressed mode | 3 | 78.940 | 2.954 | 75.739 | 82.866 | 480,879¹ |
| CPU prover, compressed proof | 1 | 138,986.358 | N/A² | 138,986.358 | 138,986.358 | 480,879¹ |

¹ Cycle count is SP1's total RISC-V instruction count from the execute report;
the execution also reported 8,359 syscall events. Mock and real proving use the
same ELF and witness. Syscall events are not added to instruction cycles.

² One real proof was generated because this is the expensive feasibility
measurement; variance cannot be estimated from `n=1`.

| Artifact/phase | Absolute result |
|---|---:|
| Bincode-serialized `SP1Proof::Compressed` | 1,272,546 bytes |
| Serialized proof bundle (proof, public values, SP1 metadata) | 1,272,994 bytes |
| Serialized public values | 425 bytes |
| CPU setup/proving-key generation, excluded from prove time | 1,681.026 ms |
| Proof verification | 52.174 ms |

The proof verified successfully. Key generation, synthetic input construction,
signing, encryption, ELF build, and SP1 setup are outside the reported proving
interval. Per-repetition SP1 stdin construction/serialization is inside it.
The verification time excludes the separate public-value comparison.

### Statement measured

The guest checks the complete statement rather than only a schema version and
length:

1. Every fixed ADAM v1 field constraint is checked: nonzero 16-byte alert ID,
   timestamp range, severity/category range, ASCII/nonempty text, and explicit
   maximum lengths for user, machine, process, IP, and file path.
2. SHA-256 of the full field/type/bound descriptor, including every checked
   range and the bincode-1 serialization convention, must equal the committed
   schema hash.
3. A secp256k1 ECDSA signature over the bincode-1-serialized alert must verify
   under the sensor public key. The key is a public value so a verifier can
   compare it with its authorized synthetic sensor key.
4. The guest enforces a 2048-bit modulus. Re-encrypting the private alert with
   RSA-2048 OAEP-SHA256 and the private OAEP randomness must exactly reproduce
   the public 256-byte ciphertext. The committed recipient-key hash binds the
   statement to the RSA public key.
5. The scoped nullifier is derived as
   `SHA256("ADAM_SCOPED_NULLIFIER_V1" || org_secret || campaign_id || epoch)`.

The private witness is the alert content, signature, OAEP randomness,
organization secret, and RSA public-key preimage needed by the checks.
The committed public values are the ciphertext, schema commitment, sensor
public key, recipient-key hash, campaign ID, epoch, and nullifier. Host-side
verification additionally checks those values against the expected synthetic
statement.

Negative unit tests reject malformed fields, a wrong schema commitment, an
invalid signature, and a mismatched ciphertext, and verify that changing the
scope cannot reproduce the expected nullifier.

### Hardware and interpretation

- Same secure E2B orb as Test 1: Linux 6.1.158, x86-64
- Intel Xeon Processor at 2.60 GHz; 8 physical cores / 16 logical CPUs
- 33,672,245,248 bytes RAM (31.36 GiB), no swap
- Rust 1.97.1 host toolchain; SP1 6.3.1 Succinct guest toolchain
- Local SP1 CPU prover; no network prover or accelerator

The absolute result is **138.986 seconds and 1,272,546 bincode-serialized proof
bytes per alert** on this CPU. That is a valid feasibility datapoint, not a
production capacity claim:
the implementation is measurement-only, unaudited research code, uses fixed
synthetic inputs, and does not implement key authorization or lifecycle outside
the proved statement.

Reproduce with:

```sh
SP1_PROVER=cpu cargo run --release -p ve-circuit -- \
  --execute-repetitions 10 --mock-repetitions 3 --real-repetitions 1
```

## Test 4: threshold-OPRF pseudonymisation quality

### Threshold OPRF and token latency

Run completed 2026-07-22. The harness uses a custom, non-RFC simulated 2-of-2
additive-share base OPRF over Ristretto255: the client hashes the typed entity to
the group and blinds it, each holder performs a separate scalar multiplication
with its key share, and the client aggregates and unblinds before deriving a
128-bit display token with SHA-256. It is not RFC 9497 VOPRF. The two holders are
simulated in one process, so this is a cryptographic compute measurement, not
network or holder-isolation latency.

| Repetitions | Mean µs/token | Std. dev. (µs) | Min (µs) | Max (µs) |
|---:|---:|---:|---:|---:|
| 10,000 | 174.708 | 14.228 | 163.272 | 573.125 |

Hardware: the same secure E2B orb used above—Intel Xeon Processor at 2.60 GHz,
8 physical cores / 16 logical CPUs, 33,672,245,248 bytes RAM (31.36 GiB), Linux
6.1.158, x86-64; Rust 1.97.1 release profile. The remote LLM hardware is unknown.

The fixed research key produced the same token for the same typed input across
different client blindings and separate program runs. Entity-type domain
separation produced different tokens for equal strings in different fields.
This deterministic key and RNG setup is for reproducible measurement only.

| Cross-customer check under the shared threshold key | Result |
|---|---:|
| External IP `203.0.113.77` | identical token |
| File hash `aaaa…aaaa` (64 hex characters) | identical token |
| Private IP `10.0.0.8` | identical token |

Under one fixed public research key, equal typed inputs produced equal tokens
across different client blindings. This demonstrates functional shared-key
determinism only; organization isolation, nondisclosure, and resistance to
offline dictionary evaluation were not measured. The source-derived test key
makes offline dictionary evaluation trivial and must never protect data. A real
shared key would still create deliberate cross-customer linkability and the
frequency risk measured below.

### Synthetic corpus and LLM method

The corpus contains exactly 30 synthetic Defender-like alerts: five each for
credential dumping, lateral movement, phishing, data exfiltration, privilege
escalation, and ransomware preparation. It includes LSASS/svchost paths,
service and person accounts, RFC1918/public IPs, LOLBins, and signed Microsoft
binaries. IDs, timestamps, relationships, command structure, PIDs, byte counts,
and all other numeric fields remain unchanged.

Full mode tokenizes users, machines, processes, parent processes, IPs, file
paths, domains, and file hashes, including occurrences inside command lines and
relationships. A local reverse table de-pseudonymizes the LLM answer. A raw-value
audit over all 30 serialized full-mode alerts passed. Alert IDs, PIDs, byte counts,
and timestamps were generated independently of attack technique so
they cannot act as a label side channel. No raw customer data was used.

For every alert, `moonshotai/kimi-k3` was called through OpenRouter once with
the original and once with the fully pseudonymized alert. Hybrid was a third
call. All 90 successful calls used the same prompt, model, temperature 0,
reasoning disabled, and strict JSON categories. The technique ground truth was
not serialized or sent to the model. Remote LLM hardware is unknown; this is a
quality experiment, not an LLM latency benchmark.

### Per-alert comparison

`sev` and `tiltak` mean equality against original analysis A; action equality is
exact canonical-set equality. All 60 B runs retained relationship count and all
techniques matched A, so those repeated columns are omitted. No B run introduced
a technique hallucination under the narrow ground-truth definition. Relationship
count is a coarse metric (outputs were capped at three); it does not prove that
relationship semantics were identical.

| Alert | Technique A | Full B (technique; sev; tiltak) | Hybrid B (technique; sev; tiltak) |
|---|---|---|---|
| ALRT-107f575b25d06d7e | credential_dumping | credential_dumping; nei; ja | credential_dumping; ja; ja |
| ALRT-0f42cc9b480bfb72 | credential_dumping | credential_dumping; ja; nei | credential_dumping; ja; nei |
| ALRT-fbf014826e7393f7 | credential_dumping | credential_dumping; ja; ja | credential_dumping; ja; ja |
| ALRT-51c7f36a84cf1165 | credential_dumping | credential_dumping; nei; nei | credential_dumping; ja; nei |
| ALRT-42100265f8efa9b3 | credential_dumping | credential_dumping; nei; nei | credential_dumping; nei; nei |
| ALRT-ff0f23d42b378c12 | lateral_movement | lateral_movement; ja; nei | lateral_movement; ja; nei |
| ALRT-269d17353fb7b173 | lateral_movement | lateral_movement; ja; nei | lateral_movement; ja; ja |
| ALRT-cb1c16e893597fba | lateral_movement | lateral_movement; ja; nei | lateral_movement; ja; nei |
| ALRT-ed14887fd22401ae | lateral_movement | lateral_movement; ja; ja | lateral_movement; ja; ja |
| ALRT-b6aa4c8626ea1953 | lateral_movement | lateral_movement; ja; ja | lateral_movement; ja; nei |
| ALRT-38f6108988b5b27b | phishing | phishing; nei; nei | phishing; ja; ja |
| ALRT-debb0ccf54f7fbc6 | phishing | phishing; ja; nei | phishing; ja; nei |
| ALRT-b6c3c76f0a2c1d09 | phishing | phishing; ja; nei | phishing; ja; nei |
| ALRT-d310d74e381412e0 | phishing | phishing; ja; nei | phishing; ja; nei |
| ALRT-cb5d7325fd29fed7 | phishing | phishing; nei; nei | phishing; ja; nei |
| ALRT-9d0de850bc1a86e2 | data_exfiltration | data_exfiltration; ja; nei | data_exfiltration; ja; nei |
| ALRT-cba9df05368bdfc2 | data_exfiltration | data_exfiltration; ja; nei | data_exfiltration; ja; ja |
| ALRT-2fd46add4c1d94cf | data_exfiltration | data_exfiltration; ja; nei | data_exfiltration; ja; ja |
| ALRT-b901ff0c18aa7346 | data_exfiltration | data_exfiltration; ja; ja | data_exfiltration; ja; nei |
| ALRT-1dded46d559ab85f | data_exfiltration | data_exfiltration; ja; ja | data_exfiltration; ja; ja |
| ALRT-152879b19fdec80e | privilege_escalation | privilege_escalation; ja; nei | privilege_escalation; ja; nei |
| ALRT-fa9f42b27ff58bf5 | privilege_escalation | privilege_escalation; ja; ja | privilege_escalation; ja; ja |
| ALRT-1dda5036e8b8ab88 | privilege_escalation | privilege_escalation; ja; ja | privilege_escalation; ja; nei |
| ALRT-b1ec6dd47c71b274 | privilege_escalation | privilege_escalation; ja; ja | privilege_escalation; ja; ja |
| ALRT-96e77767110541d2 | privilege_escalation | privilege_escalation; ja; nei | privilege_escalation; ja; ja |
| ALRT-e2e995f09de92a37 | ransomware_preparation | ransomware_preparation; ja; ja | ransomware_preparation; ja; ja |
| ALRT-22dd4810e0321fbe | ransomware_preparation | ransomware_preparation; ja; ja | ransomware_preparation; ja; ja |
| ALRT-7cd45aa1e8bf4bc8 | ransomware_preparation | ransomware_preparation; ja; ja | ransomware_preparation; ja; ja |
| ALRT-6183a905754ef533 | ransomware_preparation | ransomware_preparation; ja; ja | ransomware_preparation; nei; nei |
| ALRT-afbee8840d819303 | ransomware_preparation | ransomware_preparation; ja; ja | ransomware_preparation; nei; ja |

| Quality measure against original A | Full B | Hybrid B |
|---|---:|---:|
| Same attack technique | 30/30 | 30/30 |
| Same severity | 25/30 | 27/30 |
| Exact same canonical action set | 14/30 | 15/30 |
| Mean action-set Jaccard overlap | 0.794 | 0.843 |
| Action-set Jaccard overlap ≥ 0.5 | 27/30 | 29/30 |
| Same technique + severity + actions | 13/30 | 14/30 |
| Fewer relationships | 0/30 | 0/30 |
| Technique hallucination introduced by pseudonymisation | 0/30 | 0/30 |
| Ground-truth technique accuracy | 30/30 | 30/30 |

Original A ground-truth technique accuracy was also 30/30, so the comparison
has a valid baseline rather than merely matching an inaccurate original answer.

The primary result is positive but bounded: Kimi K3 retained the **attack
technique and relationship count in 30/30** full-mode alerts. Severity matched
in 25/30. Recommended actions matched exactly in 14/30, but average action-set
overlap was 0.794 and 27/30 had at least 0.5 overlap. Exact equality is strict
and does not distinguish a harmless extra containment step from a contradictory
recommendation.

### Hybrid result and leakage

Hybrid mode additionally reveals service/person account class, RFC1918/public
IP class, known system/LOLBin process basenames, and file basenames. Exact user,
host, IP, directory, domain, and hash identities remain tokenized.

Hybrid retained the same 30/30 techniques and relationship counts. In this
single run it had higher agreement with A: severity 27/30 versus 25/30, exact
actions 15/30 versus 14/30, and mean action overlap 0.843 versus 0.794. With one
response per condition and no independent severity/action ground truth, these
differences cannot be attributed causally to revealed semantics or interpreted
as improved answer quality. Hybrid exposes process semantics (`lsass.exe`,
`svchost.exe`, LOLBins and signed Microsoft binaries), service/person class,
private/public IP class, and known basenames while exact identities stay hidden.

### Frequency-analysis risk

The harness first generated 5,000 actual OPRF tokens from six entities with
probabilities 40%, 25%, 15%, 10%, 6%, and 4%, producing six distinct labels.
It then ran 500 seeded Monte Carlo count trials of 5,000 observations; direct
counts are rank-equivalent because OPRF labels are deterministic and 128-bit
collisions are negligible here. An attacker was assumed to have a candidate
dictionary and know the underlying rank prior. Ties count as failures.
“Recovered at 95%” means at least 475/500 trials had the correct rank at that
event count and every later count through 5,000 also met that threshold.

| Rank inference | Observations required |
|---|---:|
| Most frequent entity (top 1), 95% of trials | 71 |
| Exact ordered top 3, 95% of trials | 293 |

Under this deliberately small and strongly skewed distribution, rank leakage
appears quickly. The 293-event result is **not a universal safe rotation cutoff**:
it depends on population size, skew, attacker knowledge, and workload. A time
interval cannot be inferred without an event rate. Pilot policy must measure its
own distribution and choose an event-count/key scope accordingly. Rotation also
breaks cross-epoch matching, exposing a direct tradeoff between Collective
correlation and frequency privacy.

### Test 4 conclusion

- Threshold OPRF compute is small on this host: **0.174708 ms/token**.
- Shared-key cross-customer determinism works for external IP and file hash.
- Full pseudonymisation preserved Kimi K3's technique result in **30/30** alerts,
  severity in **25/30**, and relationship count in **30/30**.
- Exact recommended-action sets only matched in **14/30**; downstream use must
  not assume recommendation text is invariant under token substitution.
- Hybrid had small single-run agreement deltas but disclosed additional semantic
  classes; causality and quality improvement were not established.
- Deterministic tokens expose frequency and equality; epoch/key scope must be an
  explicit privacy-versus-correlation choice.

This is unaudited, single-process research code. It does not implement DKG,
malicious-share validation, verifiable partial evaluations, independent holder
processes, key custody, or production side-channel protections.

Reproduce the cryptographic measurements with:

```sh
cargo run --release -p oprf-eval -- oprf-only --repetitions 10000
```

Run the LLM matrix against an OpenAI-compatible endpoint with:

```sh
OPENROUTER_API_KEY=... cargo run --release -p oprf-eval -- run \
  --llm-url https://openrouter.ai/api/v1/chat/completions \
  --model moonshotai/kimi-k3 \
  --output target/oprf-eval/raw.json \
  --report target/oprf-eval/report.md \
  --repetitions 10000
```

## Test 5: operation distribution in detection content

This test is a static analysis of public detection rules, not a benchmark and
not a cryptographic measurement. It asks how detection work splits between
matching (join/lookup) and numeric computation, because MORSE HSS is cheap for
addition and linear work and expensive for matching. The ratio bounds how much
of a detection workload that primitive could serve at all.

Unlike Tests 1–4 the input is not synthetic: it is the public SigmaHQ corpus.

### Method

Run completed 2026-07-24 against SigmaHQ/sigma at commit
`5e969bc529d1bca15d33f4ded100290a2a1a6f4c` (2026-07-24), analysed with Python
3.11.15 and PyYAML 6.0.1. The corpus was cloned outside this repository and is
not vendored here.

The **counting unit is one field predicate**, not one rule and not one literal
value: `CommandLine|contains: [a, b, c]` is one set-membership lookup, not
three. A sensitivity check using a per-literal-value denominator is reported
below. Operations are classified as:

- **Join/lookup:** equality, `contains`, `startswith`, `endswith`, `re`,
  `cidr`, `fieldref`, `exists`, unstructured keyword search, aggregation
  group-by keys, and `near` temporal correlation.
- **Numeric:** `gt`/`gte`/`lt`/`lte` comparisons, aggregation functions
  (`count`, `sum`, `min`, `max`, `avg`), aggregation thresholds, and
  `timeframe` windows.
- **Other**, held outside the denominator and reported separately: boolean
  condition logic, `N of`/`all of` quantifiers, and encoding transforms
  (`base64`, `base64offset`, `wide`, `utf16`) counted as a decode step
  distinct from the comparison that follows it.

Per the experiment definition the result is **unweighted**. No rule execution
frequency data was available, so every rule contributes equally regardless of
how often it would fire in production.

### Result: supported corpus

The supported corpus is `rules`, `rules-compliance`, `rules-dfir`,
`rules-emerging-threats`, and `rules-threat-hunting`. All 3,755 rules parsed
with **0 parse errors**.

| Class | Operations | Share of classified |
|---|---:|---:|
| Join/lookup | 12,411 | 100.0000% |
| Numeric computation | 0 | 0.0000% |
| **Classified denominator** | **12,411** | **100%** |
| Other (excluded from denominator) | 4,381 | n/a |
| Total operations | 16,792 | n/a |

The numeric count is exactly zero. That was verified independently of the
parser: the supported corpus contains no `|gt`/`|gte`/`|lt`/`|lte` modifier,
no pipe aggregation in any `condition`, and no `detection.timeframe` key. Three
supported rules contain the string "timeframe" in prose description text only.

Composition of the 12,411 join/lookup operations, and of the 4,381 excluded:

| Operation | Count | Operation | Count |
|---|---:|---|---:|
| `contains` | 4,601 | boolean logic (`and`/`or`/`not`) | 2,390 |
| `endswith` | 3,417 | boolean quantifier (`N of`) | 1,979 |
| equality (string) | 2,891 | `base64offset` decode | 9 |
| equality (numeric-valued field) | 597 | `wide` decode | 2 |
| `startswith` | 555 | `base64` decode | 1 |
| `re` | 201 | | |
| keyword (unstructured) | 107 | | |
| `cidr` | 39 | | |
| `fieldref` | 3 | | |

Equality against a numeric-valued field (`EventID: 4624`, 597 operations) is
counted as a lookup, not arithmetic: it is a comparison against a constant with
no computation. It is broken out above so a reader can audit that call.

### Breakdown by rule category

The three requested slices are disjoint in this corpus — no rule falls into more
than one — and 1,530 supported rules fall into none of them.

| Slice | Rules | Join/lookup | Numeric | Numeric share | Other |
|---|---:|---:|---:|---:|---:|
| `process_creation` | 1,628 | 5,836 | 0 | 0.0000% | 2,276 |
| network | 294 | 1,068 | 0 | 0.0000% | 294 |
| cloud | 303 | 578 | 0 | 0.0000% | 61 |

Slice definitions: `process_creation` is `logsource.category`; network is
`logsource.category` in {`network_connection`, `dns_query`, `dns`, `firewall`,
`proxy`, `webserver`, `netflow`, `zeek`} or a `network/` path component; cloud
is `logsource.product`/`service` in a cloud-provider set or a `cloud/` path
component.

**The match/arithmetic split does not vary between categories: it is 100%/0% in
all three.** What varies is the kind of matching, which is a different result
than the one this test set out to measure:

| Slice | Substring (`contains`/`startswith`/`endswith`) | Exact equality | Regex | CIDR |
|---|---:|---:|---:|---:|
| `process_creation` | 81.6% | 16.8% | 1.6% | 0.0% |
| network | 55.5% | 37.9% | 0.7% | 3.2% |
| cloud | 12.3% | 86.5% | 0.3% | 0.0% |

Cloud rules are overwhelmingly flat equality against structured API fields.
`process_creation` rules are dominated by substring matching over command-line
strings. Both are lookups, but they are not equally expensive to make private:
exact equality is the case an OPRF or encrypted index handles well, and
substring matching over attacker-controlled free text is the case it does not.

### Where the arithmetic actually is

Every aggregation rule in the corpus lives in `unsupported/`, which SigmaHQ
excludes from the supported rule set. This is the only place numeric operations
appear at all:

| Class | Operations | Share of classified |
|---|---:|---:|
| Join/lookup | 286 | 67.2941% |
| Numeric computation | 139 | 32.7059% |
| **Classified denominator** | **425** | **100%** |
| Other (excluded) | 77 | n/a |
| Total operations | 502 | n/a |

87 unsupported rules parsed; 53 of them actually aggregate. The 139 numeric
operations are 47 `timeframe` windows, 46 thresholds, 44 `count()` calls, and
2 `sum()` calls. Their logsource categories are `process_creation` (6), `dns`
(5), `firewall` (3), `ps_script` (2), and one each of `webserver`,
`image_load`, and `dns_query`.

### Sensitivity to the counting unit

Recounting with every literal value as its own operation instead of every field
predicate changes the magnitude but not the conclusion: 46,082 join/lookup
operations against 0 numeric operations in the supported corpus. The result is
not an artifact of treating a value list as a single set-membership test.

### Interpretation and limits

The headline number is real but it must not be read as "detection work contains
no arithmetic". Three limits bound it, and the first is severe:

1. **The corpus is partly measuring the Sigma language, not detection
   practice.** Sigma's supported specification deliberately excludes
   aggregation; the aggregating rules were moved to `unsupported/`. A detection
   engineer who wants a rate or a threshold does not write it in supported
   Sigma, so the zero is partly definitional. Statistical, UEBA, and
   beaconing-style detections are out of scope of this corpus by construction,
   and those are exactly the detections that would be arithmetic-heavy. This
   measurement therefore establishes the distribution **for signature-style
   detection content expressed in Sigma**, and nothing wider.
2. **Static, not runtime.** These are the operations a rule declares, not the
   operations a SIEM backend executes. A backend performs its own indexing,
   grouping, and scan work per event that no rule text mentions.
3. **Unweighted.** Without execution frequency data, a rule that fires
   constantly counts the same as one that never fires.

For ADAM specifically: within this corpus, the arithmetic capability that MORSE
HSS provides cheaply addresses 0 of 12,411 operations, and the substring
matching that dominates `process_creation` is the hardest case for any
encrypted-lookup approach. That is a genuine negative signal for applying an
arithmetic-oriented primitive directly to signature detection content. It is
not evidence about the alert-scoring workload measured in Tests 1 and 2B, which
is thresholding over already-extracted numeric features — an arithmetic
workload that this corpus does not describe and this test does not measure.

### Reproduce

```sh
git clone --depth 1 https://github.com/SigmaHQ/sigma.git /tmp/sigma
python3 analysis/op_distribution.py --corpus /tmp/sigma
```

## Test 6: operation distribution in the unsupported Sigma corpus

Test 5 found that all aggregation in the Sigma corpus lives in `unsupported/`.
This is the same parser, the same classification, and the same table form
pointed at that directory, to see whether the match/arithmetic split varies by
category once arithmetic is permitted at all. Same corpus pin as Test 5.

| Slice | Rules | Join/lookup | Numeric | Join share | Numeric share | Other |
|---|---:|---:|---:|---:|---:|---:|
| Whole `unsupported/` corpus | 87 | 286 | 139 | 67.2941% | 32.7059% | 77 |
| `process_creation` | 9 | 34 | 9 | 79.0698% | 20.9302% | 14 |
| network | 15 | 36 | 36 | 50.0000% | 50.0000% | 14 |
| cloud | 9 | 25 | 21 | 54.3478% | 45.6522% | 3 |

33 of the 87 rules fall into one of the three slices; the slices are disjoint.
Numeric operations by kind: `timeframe` windows and `count()` calls dominate,
with `sum()` appearing only in the network slice (2 operations).

**The split does vary by category here, unlike in Test 5.** Network rules are
the most arithmetic-heavy at 50.0%, cloud next at 45.7%, and `process_creation`
least at 20.9%. That ordering is plausible — rate and volume thresholds are
natural for DNS, firewall, and API-call telemetry, and unnatural for individual
process launches — but it rests on very few rules.

**These percentages are fragile and should not be quoted as rates.** The slice
denominators are 43, 72, and 46 operations drawn from 9, 15, and 9 rules. A
single rule changes any of them by several percentage points. The corpus is
also unsupported by definition: these rules were removed from the maintained
set, so they describe what Sigma authors once wrote, not current practice. Test
6 establishes that arithmetic-heavy detection content exists and is
category-dependent; it does not measure how much.

Reproduce with the Test 5 command; the `unsupported_slices` key holds this
table.

## Test 7: can substring search be expressed as a set operation?

Test 5 found that substring matching dominates the `process_creation` (81.6%)
and network (55.5%) slices, and that it is the hardest case for any encrypted
lookup. The standard way to turn a substring query into a set operation is
n-gram tokenisation: store the set of n-grams of each field, and answer a query
by testing whether the query's n-gram set is contained in the field's.

This test measures what that transformation costs. **No cryptography is
involved** — this measures the tokenisation itself, which bounds any scheme
built on it.

### Method

Run completed 2026-07-24. Patterns come from SigmaHQ/sigma at the Test 5 commit
`5e969bc529d1bca15d33f4ded100290a2a1a6f4c`, extracted with the Test 5 parser.
Input command lines come from redcanaryco/atomic-red-team at commit
`1ba1dd8d9ce6f74700f7aec2e60de5632f667f03` (2026-07-19), with `#{...}` input
arguments replaced by their declared defaults and each executor command block
split into lines, because a process `CommandLine` field holds one line rather
than a whole script.

| Corpus | Extent |
|---|---:|
| Substring pattern occurrences (process_creation + network) | 22,685 |
| Unique patterns | 14,726 |
| — `contains` | 12,254 |
| — `endswith` | 2,309 |
| — `startswith` | 163 |
| Unique patterns on CommandLine-like fields | 11,171 |
| Input command lines | 6,110 |
| Atomic tests contributing them | 1,801 |

All strings are lowercased, because Sigma matching is case-insensitive by
default. That is the faithful model and it also increases n-gram collisions.
Anchored patterns (`startswith`/`endswith`) are reported separately from
unanchored `contains` throughout.

The set model is **complete but not sound**: if P is a substring of S then every
n-gram of P is an n-gram of S, so the filter never misses a true match, but the
converse fails. This was verified empirically as well as argued — over 7,123
true substring occurrences the filter produced 0 misses. The filter's exact
positive set was also cross-checked against a naive subset test over a 400
pattern × 600 input sample at all three n, with identical counts.

### 1. Inflation

Per pattern, over expressible patterns only:

| n | Mean n-grams | Median | p95 | Max |
|---:|---:|---:|---:|---:|
| 3 | 14.21 | 10 | 41 | 176 |
| 4 | 13.64 | 9 | 41 | 175 |
| 5 | 13.82 | 9 | 41 | 174 |

Per input field — the number of tokens that must actually be stored per
command line:

| n | Mean positions | Median | p95 | Max | Mean distinct | Median distinct |
|---:|---:|---:|---:|---:|---:|---:|
| 3 | 68.38 | 55 | 157 | 1,493 | 60.25 | 51 |
| 4 | 67.47 | 54 | 156 | 1,492 | 61.53 | 51 |
| 5 | 66.77 | 54 | 155 | 1,491 | 62.12 | 51 |

**Inflation is approximately one token per character of stored field, and it is
essentially independent of n.** A median 55-character command line becomes
51 distinct stored tokens. Raising n does not reduce the index size; it only
shifts which tokens are stored. Any per-token cost in an encrypted index is
therefore multiplied by roughly the field length, not by a small constant.

### 2. Patterns shorter than n

| n | Inexpressible | Share of unique patterns | `contains` | `endswith` | `startswith` |
|---:|---:|---:|---:|---:|---:|
| 3 | 2,525 | 17.15% | 2,503 | 21 | 1 |
| 4 | 2,906 | 19.73% | 2,803 | 100 | 3 |
| 5 | 3,921 | 26.63% | 3,654 | 257 | 10 |

At n=5 more than a quarter of the pattern set cannot be expressed at all. These
are not marginal patterns — short `contains` fragments such as flag strings and
short path components are ordinary detection content. A deployment would have
to fall back to some other mechanism for them, which is the point at which the
privacy property of the whole index is at risk of being lost.

### 3. Frequency distribution of distinct n-grams

This is the leakage measure. An encrypted n-gram index reveals which token is
being touched, so the shape of this distribution bounds what an observer learns
without breaking anything. Measured over the input corpus, which is where the
leakage sits; the pattern side is secondary.

| n | Distinct n-grams | Occurrences | Top 100 share of occurrences | Top 100 as share of distinct | n-grams covering 50% | covering 90% |
|---:|---:|---:|---:|---:|---:|---:|
| 3 | 22,073 | 399,435 | 19.07% | 0.45% | 583 (2.64%) | 5,418 (24.5%) |
| 4 | 50,550 | 393,594 | 13.28% | 0.20% | 1,556 (3.08%) | 19,683 (38.9%) |
| 5 | 76,663 | 387,760 | 10.60% | 0.13% | 2,938 (3.83%) | 37,887 (49.4%) |

| n | Hapax n-grams | Hapax share | Entropy (bits) | Max entropy | Normalised |
|---:|---:|---:|---:|---:|---:|
| 3 | 7,843 | 35.53% | 11.8977 | 14.4300 | 0.8245 |
| 4 | 22,375 | 44.26% | 13.3745 | 15.6254 | 0.8559 |
| 5 | 39,060 | 50.95% | 14.2207 | 16.2262 | 0.8764 |

The distribution is Zipf-like and clearly non-uniform: at n=3, **2.64% of
distinct n-grams carry half of all occurrences**, and the single most common
3-gram appears 1,924 times. Larger n flattens it — normalised entropy rises
from 0.82 to 0.88 and the top-100 share falls from 19.07% to 10.60% — but never
approaches uniform, and the tail grows correspondingly heavier: at n=5 half of
all distinct n-grams occur exactly once.

Both ends of that distribution are informative to an observer. Frequent n-grams
make access patterns predictable; hapax n-grams are near-unique identifiers of
the specific line that contains them. This is the same structural weakness the
Test 4 frequency analysis found in deterministic OPRF tokens, reappearing at
the token level.

**This is a distributional measurement, not an attack.** Skew is a necessary
condition for a frequency attack, not a demonstration of one. No inference was
run, and unlike Test 4 no observation count for recovering anything is claimed
here. Anyone quoting this section should quote the distribution, not a
capability.

### 4. False positives

Primary result, restricted to patterns whose target field is CommandLine-like,
matching the input corpus:

| n | Filter positives | True positives | False positives | Precision |
|---:|---:|---:|---:|---:|
| 3 | 60,710 | 54,859 | 5,851 | 90.36% |
| 4 | 45,397 | 41,825 | 3,572 | 92.13% |
| 5 | 30,445 | 28,772 | 1,673 | 94.50% |

The aggregate hides the real structure. Split by anchoring:

| n | `contains` precision | `contains` FP | Anchored precision | Anchored FP |
|---:|---:|---:|---:|---:|
| 3 | 97.47% | 1,403 | 16.04% | 4,448 |
| 4 | 98.91% | 454 | 16.99% | 3,118 |
| 5 | 99.12% | 251 | 21.95% | 1,422 |

**For unanchored `contains`, the set model works well**: 99.12% precision at
n=5, with completeness guaranteed. **For anchored patterns it fails**, at
16–22% precision, because an unordered set discards position entirely — knowing
that every n-gram of `\system` occurs somewhere in a line says almost nothing
about whether the line ends with it. Anchored patterns are only 2,472 of 14,726
unique patterns but produce the majority of all false positives.

That failure is a modelling artifact rather than a fundamental limit, and it is
cheap to fix: position-tagging the terminal n-gram of an anchored pattern
restores the anchor at no change to index size. This is the concrete reason the
two kinds were separated rather than pooled — pooled, the headline precision
would read 90.36% at n=3 and would have misattributed an addressable design
flaw to the technique itself.

Against the full pattern set including path-targeted fields such as `Image`,
precision is lower — 83.74%, 85.19%, and 88.49% at n=3, 4, and 5 — but that
comparison applies patterns to a field type they were not written for, so the
CommandLine-restricted figures above are the meaningful ones.

### Interpretation and limits

Answering the question directly: **yes for unanchored substring search, at a
real price.** The price is roughly one stored token per character of every
indexed field, 17–27% of the pattern set becoming inexpressible depending on n,
and an n-gram frequency distribution far from uniform. Anchored search needs
position tagging, without which it is unusable.

The choice of n is a genuine tension rather than a tuning detail. Larger n
gives better precision (97.47% → 99.12%) and flatter frequency leakage
(normalised entropy 0.82 → 0.88), but costs more inexpressible patterns
(17.15% → 26.63%) and a heavier unique-token tail (35.53% → 50.95% hapax). No
value of n is good at all four at once, and index size barely moves.

Three limits bound these numbers:

1. **The false-positive rate is not general.** Atomic Red Team is a corpus of
   attack commands, not benign background traffic. The precision figures
   describe the filter's behaviour on 6,110 attack-like command lines. The
   number that would decide a deployment — precision against production volumes
   of benign command lines, where true positives are rare and the FP term
   dominates — is not measured here and is likely to be materially worse,
   because precision falls as the true-positive base rate falls.
2. **The skew figures describe this corpus.** A different command-line
   population would produce a different distribution; the Zipf-like shape is
   expected to be robust, the specific percentages are not.
3. **Static and unweighted, inherited from Test 5.** Patterns count once each
   regardless of how often their rule fires.

For ADAM: this establishes that the substring-matching majority of detection
content identified in Test 5 is expressible as a set operation, so the barrier
is not expressiveness. The barrier is per-field token inflation and a token
frequency distribution that leaks structure — the same problem class as the
Test 4 OPRF frequency result, at a finer granularity.

### Reproduce

```sh
git clone --depth 1 https://github.com/SigmaHQ/sigma.git /tmp/sigma
git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git /tmp/art
python3 analysis/ngram_cost.py --corpus /tmp/sigma --input-corpus /tmp/art
```

## Test 8: frequency attack against the n-gram index

Test 7 measured that the n-gram frequency distribution is Zipf-like but
deliberately stopped short of turning skew into an attack number. This closes
that loop in the same shape as the Test 4 OPRF frequency analysis.

### Threat model

The index stores, per field, the set of tokens of its n-grams. Tokens are
deterministic: the same n-gram always yields the same token, globally. The
attacker sees token sets and nothing else, and breaks no primitive — everything
below follows from determinism plus skew. Tokens are modelled as a secret
random relabelling of the n-gram space, which is what a PRF-based scheme
provides. The attacker code touches only token identity and token frequency,
never the underlying string, including for tie-breaking.

Two capability levels are separated:

- **Uninformed** — holds the public dictionary of candidate command lines but
  no knowledge of how often the victim runs each. This is the realistic
  baseline, because the dictionary here is a public repository.
- **Informed** — additionally knows the victim's execution-frequency
  distribution. This is the upper bound on what frequency knowledge buys.

Execution frequencies do not exist in any public corpus, so the victim
distribution is **synthetic**: Zipf(s) over command lines in randomised rank
order. Sensitivity to s is reported and turns out to dominate everything else.
Corpus and pins are the Test 7 ones; 20 trials per point, seed 20260724.

### Population and ceiling

| n | Distinct lines | n-gram vocabulary | Indistinguishable classes | Ceiling |
|---:|---:|---:|---:|---:|
| 3 | 4,844 | 22,073 | 4,844 | 100.0% |
| 4 | 4,839 | 50,550 | 4,839 | 100.0% |
| 5 | 4,827 | 76,663 | 4,827 | 100.0% |

No two distinct command lines share an n-gram set at any n, so nothing is
hidden by collision: perfect identification is possible in principle, and the
measured rates below are not capped by the corpus.

### Linkage is free

Because tokens are deterministic, two executions of the same command line
produce byte-identical token sets. An attacker can therefore say "these two
records are the same command" with **zero background knowledge and two
observations**, at every n. This needs no frequency analysis and no dictionary,
and no amount of observation is required beyond the second. Identification —
saying *which* command — is the part that needs more, and is what the rest of
this section measures.

### The set-size fingerprint, at one observation

|token set| equals |n-gram set|, which the attacker computes for every public
candidate. This needs no frequency knowledge and a single observation.

| n | Classes with globally unique size | Median candidates after size filter | Largest bucket |
|---:|---:|---:|---:|
| 3 | 48 (0.9909%) | 14 | 66 |
| 4 | 45 (0.9299%) | 13 | 71 |
| 5 | 57 (1.1809%) | 13 | 78 |

Size alone rarely identifies — about 1% of records — but it narrows roughly
4,840 candidates to a median of 13–14 from a single observation, a ~370x
reduction, for free. That floor matters for reading the next table.

### Identification versus observations

Zipf s=1.0. "Traffic" is the share of observations identified, which is
dominated by frequent lines; "distinct" is the share of distinct lines seen.

| n | Attacker | N=10 | N=10² | N=10³ | N=10⁴ | N=10⁵ | Observations for 50% of traffic |
|---:|---|---:|---:|---:|---:|---:|---:|
| 3 | uninformed | 4.0% | 4.25% | 5.355% | 5.979% | 5.4479% | not reached |
| 3 | informed | 22.0% | 31.4% | 37.38% | 57.1195% | 80.6336% | 4358 |
| 4 | uninformed | 6.5% | 5.9% | 7.28% | 8.1475% | 7.8868% | not reached |
| 4 | informed | 8.5% | 22.85% | 37.36% | 50.7295% | 68.3142% | 8819 |
| 5 | uninformed | 2.5% | 4.0% | 4.11% | 4.8015% | 5.4136% | not reached |
| 5 | informed | 20.5% | 29.75% | 39.14% | 51.3705% | 66.7653% | 7726 |

Neither attacker reaches 90% of traffic within 10⁵ observations at s=1.0.

**The uninformed attacker's frequency attack fails.** It plateaus at 5–8% of
traffic no matter how long it observes, which is approximately the 1-in-13
floor the size fingerprint already provides. Ranking tokens by document
frequency in the public dictionary does not survive contact with a skewed
victim distribution: recovered token→n-gram accuracy stays at 0.01–0.19%.

**The informed attacker succeeds, and succeeds on the traffic that matters
first.** At n=3 she identifies 22% of traffic from 10 observations and 80.6%
from 10⁵, while only reaching 69.4% of *distinct* lines — she de-anonymises
frequent commands early and rare ones late, exactly the pattern Test 4 found
for OPRF tokens. Her token map is still poor in absolute terms (0.74%
unweighted at best) but occurrence-weighted accuracy reaches 21.2%, and that
is what the overlap scoring uses.

### Sensitivity to the assumed skew

Observations for the informed attacker to reach 50% of traffic:

| n | s=0.8 | s=1.0 | s=1.2 |
|---:|---:|---:|---:|
| 3 | 30,717 | 4,358 | 101 |
| 4 | 42,839 | 8,819 | 296 |
| 5 | 80,086 | 7,726 | 144 |

**This is the most important number in the test, and it is not a property of
the index.** The threshold moves by nearly three orders of magnitude — from 101
to 80,086 observations — purely from the assumed traffic skew. The uninformed
attacker moves the other way, getting *worse* as skew rises (9.3% → 3.0% of
traffic at n=3), because a uniform prior is more wrong the more skewed reality
is.

Choice of n barely matters by comparison. n=3 is consistently the most
vulnerable, but the n=3-to-n=5 spread is small next to the s=0.8-to-s=1.2
spread.

### Interpretation and limits

1. **These are lower bounds on leakage, not upper bounds.** The measured attack
   is a frequency attack, the Test 4 analogue that this test set out to run. It
   is not the strongest available. Recovered token-map accuracy is very low
   (≤0.74% unweighted), which means most of the identification comes from the
   size filter plus a handful of high-frequency tokens — a structural attack
   using token co-occurrence across records, or iterative constraint
   propagation seeded from confidently-mapped tokens, would do materially
   better. That attack was not implemented and is not measured here. **Nothing
   in this section should be read as evidence that the index is safe against
   the uninformed attacker;** it is evidence that one specific attack fails.
2. **The frequency model is synthetic and dominates the result.** Zipf over
   command lines is an assumption, not a measurement, and the sensitivity table
   shows the answer is mostly determined by it. A deployment must measure its
   own command-line distribution before quoting any observation count.
3. **The population is a public attack corpus.** 4,840 distinct Atomic Red Team
   lines is far smaller and far less diverse than a real environment's command
   line population. A larger population makes identification harder per
   observation but does not remove the linkage result, which is
   population-independent.
4. Inherited from Test 7: static, unweighted pattern extraction, lowercased.

For ADAM: the load-bearing finding is not an observation count, because that
number is mostly an artifact of the assumed skew. It is that **linkage is
unconditional and free** — deterministic tokens make repeated identical
commands visible as repeats to anyone who can see the index, with no
background knowledge and no frequency analysis at all. That property does not
depend on the traffic distribution, cannot be tuned away with a larger n, and
is the same structural weakness Test 4 found in deterministic OPRF tokens.
Test 9 measures what removing it costs.

### Reproduce

```sh
git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git /tmp/art
python3 analysis/freq_attack.py --input-corpus /tmp/art --zipf 0.8 1.0 1.2
```
