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
