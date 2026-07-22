# ADAM architecture measurements

This repository contains one-off research measurements for BORG/ADAM. It is
**not product code**, not a production cryptographic implementation, and not a
starting point for a connector, service, dashboard, or API.

The repository exists to measure whether selected privacy-preserving
primitives are practical for security telemetry. The first and most important
question is the absolute throughput and bandwidth of MORSE-style Homomorphic
Secret Sharing (HSS) over a 3072-bit FastPaillier modulus. Later experiments
evaluate a real verifiable-encryption statement and threshold-OPRF
pseudonymisation quality.

All inputs are synthetic. Results, including hardware and variance, are kept in
[`results/RESULTS.md`](results/RESULTS.md).

## Scope

- `crates/hss-bench`: MORSE HSS primitive and synthetic alert benchmarks
- `crates/ve-circuit`: reserved for the verifiable-encryption experiment
- `crates/oprf-eval`: reserved for the OPRF pseudonymisation experiment

Only the measurement harness is in scope. Do not use this code to protect real
data.
