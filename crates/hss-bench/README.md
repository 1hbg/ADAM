# MORSE HSS benchmark

Measurement-only Rust implementation of the algorithms in Deng et al.,
“MORSE: An Efficient Homomorphic Secret Sharing Scheme Enabling Non-Linear
Operation,” arXiv:2410.06514v1 (2024).

The harness uses GMP through `rug`, a structured 3072-bit FastPaillier modulus,
a 512-bit private key, 128-bit statistical masks, and 32-bit synthetic values.
The two parties are separate OS processes connected by localhost TCP. Timings
are end-to-end wall-clock at the coordinator. Encryption and key generation are
setup costs and are outside timed cloud operations.

`SMUL_HSS` itself has zero inter-party communication. A one-byte harness command
and a 384-byte result are used only to synchronize and verify the two process
outputs; they are not reported as cryptographic protocol bandwidth.

`SCMP_HSS` sends fixed-width `(D, z0)` from party 0 and one ciphertext from party
1: 768 + 384 + 768 = 1920 application bytes. The harness adds a one-byte command.
TCP/IP packet headers are not counted.

The synthetic scorer has 50 encrypted features and evaluates every threshold
in trees with K in `{5, 10, 20, 50}`. Every K measurement contains exactly 1000
alerts. The data is generated arithmetically and contains no customer data.

## Test 2B batching and parallelism

`run2b` extends the scorer without changing the cryptographic statement. A
batch contains `B × K` independent SCMP instances but sends all party-0 values
in one message and all party-1 answers in one response. It therefore uses one
protocol round per batch while retaining exactly 1,920 bytes per comparison.
Each party owns a fixed-size Rayon pool; no cryptographic work runs on the
coordinator.

Artificial latency is implemented in the transport layer rather than with
`tc netem`: party 0 sleeps for RTT/2 before its batched request and party 1
sleeps for RTT/2 before its response. This isolates the party channel and adds
one RTT per batch without delaying the coordinator control channel or unrelated
loopback traffic in the orb. Sleep and both directions of TCP transfer are
inside the wall-clock interval. Process startup, key loading, synthetic input
generation, encryption, pool creation, and one correctness warmup are outside.

## Reproduce

```sh
cargo run --release -p hss-bench -- keygen
cargo bench -p hss-bench --bench primitives
cargo run --release -p hss-bench -- run \
  --primitive-repetitions 500 --alerts 1000
cargo run --release -p hss-bench -- run2b --alerts 1000
```

This code has not been audited and must not be used as a cryptographic library.
