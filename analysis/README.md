# analysis

Standalone corpus analyses that support the ADAM measurements but are not
benchmarks of a cryptographic primitive. The `crates/` workspace measures
primitive performance; this directory measures properties of detection
content. Results are written up in [`../results/RESULTS.md`](../results/RESULTS.md).

## `op_distribution.py` — Test 5

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
corpus, the `unsupported/` corpus, and the `process_creation`, network, and
cloud slices.

This is a static analysis of what rules *declare*. It does not execute rules,
does not observe an event stream, and uses no rule-frequency weighting — see
the limits section of the Test 5 writeup before quoting any number from it.
