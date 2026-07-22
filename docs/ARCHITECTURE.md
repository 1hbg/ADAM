# ADAM research architecture

BORG is evaluating ADAM, a cloud cybersecurity architecture intended to run AI
over customer data without giving BORG access to that data. The selected design
does not rely on trusted execution environments or fully homomorphic
encryption.

A customer connector splits data into shares. Two independent BORG clusters
compute locally on those shares, while a collaborative SNARK (coSNARK) proves
that the intended code ran.

The candidate primitives are:

- Homomorphic Secret Sharing (HSS) over FastPaillier for cloud scoring
- Function Secret Sharing / Distributed Point Functions for private rules
- Pseudorandom Correlation Generators / silent OT for correlated randomness
- threshold OPRF for Chat pseudonymisation
- TAPAS for cross-customer aggregation
- coSNARK, verifiable encryption, nullifiers, and FROST for integrity

The only unverified architectural assumption is whether HSS is fast enough for
security telemetry. This repository is a research harness for measuring that
assumption, not an implementation of the ADAM product.
