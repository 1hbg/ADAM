# analysis

Standalone corpus analyses that support the ADAM measurements but are not
benchmarks of a cryptographic primitive. The `crates/` workspace measures
primitive performance; this directory measures properties of detection
content. Results are written up in [`../results/RESULTS.md`](../results/RESULTS.md).

## `op_distribution.py` — Tests 5 and 6

Classifies every atomic operation in a Sigma rule corpus as a join/lookup
(matching) or a numeric computation, to bound how much of a detection workload
an arithmetic-oriented primitive such as MORSE HSS could serve.

Unlike the rest of this repository the input is **not synthetic**: it is the
public SigmaHQ corpus, which is cloned separately and deliberately not vendored
here.

```sh
git clone --depth 1 https://github.com/SigmaHQ/sigma.git /tmp/sigma
python3 analysis/op_distribution.py --corpus /tmp/sigma --json /tmp/test5.json
```

Requires Python 3 and PyYAML. Prints a JSON summary covering the supported
corpus (Test 5, under `supported` and `slices`) and the `unsupported/` corpus
(Test 6, under `unsupported` and `unsupported_slices`), each broken down into
the `process_creation`, network, and cloud slices.

This is a static analysis of what rules *declare*. It does not execute rules,
does not observe an event stream, and uses no rule-frequency weighting — see
the limits section of the Test 5 writeup before quoting any number from it.

## `ngram_cost.py` — Test 7

Measures what it costs to express substring search as a set operation via
n-gram tokenisation, at n = 3, 4, 5: index inflation, patterns too short to be
expressed, the frequency distribution of distinct n-grams (the leakage
measure), and the false-positive rate of the set filter.

Reuses the Test 5 parser to extract substring patterns from the
`process_creation` and network slices. Input command lines come from Atomic Red
Team — a corpus of *attack* commands, which is why the false-positive figures
are not a general rate. Both corpora are cloned separately.

```sh
git clone --depth 1 https://github.com/SigmaHQ/sigma.git /tmp/sigma
git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git /tmp/art
python3 analysis/ngram_cost.py --corpus /tmp/sigma --input-corpus /tmp/art
```

No cryptography is involved: this measures the tokenisation, which bounds any
scheme built on it, not a scheme.

## `freq_attack.py` — Test 8

Turns the Test 7 skew measurement into an attack number: how many observations
an attacker needs before she can say which command line is behind an observed
token set. Separates an uninformed attacker (public dictionary only) from an
informed one (also knows the victim's execution frequencies), and reports
linkage separately from identification.

Tokens are modelled as a secret random relabelling of the n-gram space. The
attacker code touches only token identity and frequency, never the underlying
string — including for tie-breaking, which would otherwise smuggle plaintext
order into the attack.

```sh
python3 analysis/freq_attack.py --input-corpus /tmp/art --zipf 0.8 1.0 1.2
```

The victim frequency distribution is **synthetic** (Zipf), because no public
corpus carries command execution frequencies, and the sensitivity sweep shows
it dominates the answer. Runs for tens of minutes.

## `mitigation.py` — Test 9

The cost/leakage curve for defending that index: size padding and frequency
padding, measured as index-size multiplier against residual identification.
Re-runs the Test 8 attack against each padded index.

The attacker is assumed to know the defence but not the secret padding, which
determines what she can still rule out by observed set size. Scoring a padded
index against exact-size buckets would credit the defence with hiding something
she never needed — see the candidate models at the top of the file.

```sh
python3 analysis/mitigation.py --input-corpus /tmp/art --n 4 \
  --trials 10 --observations 10000
```

The traffic-identification metric is heavy-tailed under Zipf — a handful of
frequent lines carry most of it — so it needs many trials to stabilise. Ten is
not enough; see the Test 9 writeup.

## `epoch_utility.py` — Test 10

Simulates how much investigative work survives token rotation at 1h / 6h / 24h
/ 7d. No cryptography and no corpus: the investigation-span distribution is
**synthetic**, a three-component lognormal mixture, and the writeup reports the
result against a sensitivity sweep rather than the central case alone.

```sh
python3 analysis/epoch_utility.py --trials 200000
```

## `sketch_compression.py` — Test 12

Measures how far security telemetry compresses under Count-Min and HyperLogLog
sketching before it reaches HSS, as compression ratio against precision loss on
realistic aggregation questions. Both sketches are textbook implementations
written for measurement, not optimised or hardened.

```sh
python3 analysis/sketch_compression.py --input-corpus /tmp/art --events 200000
```

The event stream is **synthetic**: command lines come from Atomic Red Team, but
entity cardinalities and the Zipf skew are modelling assumptions, and the
compression ratio depends directly on them.
