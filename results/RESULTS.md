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
