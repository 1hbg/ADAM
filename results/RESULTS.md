# ADAM research results

Only absolute measurements belong here. All data used by the experiments is
synthetic.

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
