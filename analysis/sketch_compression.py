#!/usr/bin/env python3
"""Test 12: compression before cryptography.

Tests 1 and 2B measured that MORSE HSS costs about 19.5 ms and 1,920 protocol
bytes per comparison, linear in the number of values. That makes the number of
values entering the cryptography the dominant cost lever - larger than any
constant-factor tuning of the primitive itself.

Sketches attack exactly that. A Count-Min sketch answers frequency questions
from a fixed-size array whose size does not depend on how many distinct keys
exist; a HyperLogLog answers distinct-count questions from a fixed register
array. If the aggregation an analyst actually needs can be answered from the
sketch, only the sketch has to enter HSS.

This measures the trade: compression ratio against precision loss, on
aggregation questions of the shape security telemetry actually asks.

Both sketches are textbook implementations written for measurement, not
optimised or hardened. No cryptography is involved here.

The event stream is SYNTHETIC. Entity cardinalities and the Zipf skew are
modelling assumptions, matching the frequency model used in Test 8; command
lines are drawn from the public Atomic Red Team corpus. Real telemetry
cardinality distributions are not public, and the compression ratio depends
directly on them, so the ratio is reported as a function of cardinality rather
than as a single number.
"""

import argparse
import hashlib
import json
import math
import random
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ngram_cost import load_atomic_red_team  # noqa: E402

SEED = 20260724


# ------------------------------------------------------------------ sketches

class CountMin:
    """Count-Min sketch over 32-bit counters."""

    def __init__(self, width, depth, seed=0):
        self.width = width
        self.depth = depth
        self.seed = seed
        self.table = [[0] * width for _ in range(depth)]

    @staticmethod
    def raw_hashes(key, depth, seed=0):
        """Depth 64-bit hashes of a key, independent of sketch width.

        Cached by the caller so a key is hashed once per corpus rather than
        once per (event, width) pair.
        """
        b = key if isinstance(key, bytes) else str(key).encode()
        return [
            int.from_bytes(
                hashlib.blake2b(b, digest_size=8,
                                key=f"cm{seed}:{i}".encode()[:16]).digest(),
                "little")
            for i in range(depth)
        ]

    def add_hashed(self, hashes, count=1):
        for i, h in enumerate(hashes):
            self.table[i][h % self.width] += count

    def estimate_hashed(self, hashes):
        return min(self.table[i][h % self.width] for i, h in enumerate(hashes))

    def size_bytes(self):
        return self.width * self.depth * 4


class HyperLogLog:
    """HyperLogLog with 8-bit registers and the standard bias-free estimator."""

    def __init__(self, p=12, seed=0):
        self.p = p
        self.m = 1 << p
        self.seed = seed
        self.registers = [0] * self.m

    def add(self, key):
        b = key if isinstance(key, bytes) else str(key).encode()
        h = hashlib.blake2b(b, digest_size=8,
                            key=f"hll{self.seed}".encode()[:16]).digest()
        x = int.from_bytes(h, "little")
        idx = x & (self.m - 1)
        w = x >> self.p
        rho = (64 - self.p) - w.bit_length() + 1 if w else (64 - self.p) + 1
        if rho > self.registers[idx]:
            self.registers[idx] = rho

    def count(self):
        m = self.m
        alpha = {16: 0.673, 32: 0.697, 64: 0.709}.get(m, 0.7213 / (1 + 1.079 / m))
        raw = alpha * m * m / sum(2.0 ** -r for r in self.registers)
        zeros = self.registers.count(0)
        if raw <= 2.5 * m and zeros:
            return m * math.log(m / zeros)
        return raw

    def size_bytes(self):
        return self.m  # one byte per register


# -------------------------------------------------------------- event stream

def build_stream(lines, events, hosts, dests, rng):
    """A synthetic telemetry stream with Zipf-skewed entity popularity.

    Each event is (host, process command line, destination). Entity
    cardinalities are parameters, because the compression ratio depends on them
    and no public source fixes them.
    """
    # Sample from a precomputed CDF by bisection. `random.choices` re-derives
    # the cumulative weights on every call, which makes stream construction
    # quadratic in the entity cardinality and is unusable at these sizes.
    import bisect
    from itertools import accumulate

    def cdf(n, s=1.0):
        c = list(accumulate(1.0 / ((i + 1) ** s) for i in range(n)))
        total = c[-1]
        return [x / total for x in c]

    cdfs = {
        "hosts": cdf(hosts),
        "lines": cdf(len(lines)),
        "dests": cdf(dests),
    }

    def pick(which):
        return bisect.bisect_left(cdfs[which], rng.random())

    stream = []
    for _ in range(events):
        h = f"host-{pick('hosts')}"
        c = lines[pick('lines')]
        d_idx = pick("dests")
        d = f"198.51.{d_idx // 256}.{d_idx % 256}"
        stream.append((h, c, d))
    return stream


# ------------------------------------------------------------- measurements

def measure_count_min(stream, widths, depth, key_index, label):
    truth = Counter(ev[key_index] for ev in stream)
    distinct = len(truth)
    total = sum(truth.values())

    # Exact aggregation must carry one counter per distinct key into HSS.
    exact_values = distinct

    heavy_threshold = 0.001 * total
    heavy = {k for k, v in truth.items() if v >= heavy_threshold}

    # Hash each distinct key once; a Count-Min sketch is linear, so inserting
    # a key with its exact count is identical to inserting it once per event.
    hashes = {k: CountMin.raw_hashes(k, depth, seed=1) for k in truth}

    out = []
    for width in widths:
        cm = CountMin(width, depth, seed=1)
        for k, v in truth.items():
            cm.add_hashed(hashes[k], v)

        errors, rel_errors = [], []
        estimates = {}
        for k, v in truth.items():
            est = cm.estimate_hashed(hashes[k])
            estimates[k] = est
            errors.append(est - v)
            rel_errors.append((est - v) / v)
        rel_errors.sort()

        est_heavy = {k for k, e in estimates.items() if e >= heavy_threshold}
        tp = len(heavy & est_heavy)
        recall = tp / len(heavy) if heavy else None
        precision = tp / len(est_heavy) if est_heavy else None

        sketch_values = width * depth
        out.append({
            "field": label,
            "distinct_keys": distinct,
            "total_events": total,
            "width": width,
            "depth": depth,
            "sketch_bytes": cm.size_bytes(),
            "exact_values_into_hss": exact_values,
            "sketch_values_into_hss": sketch_values,
            "value_compression_ratio": round(exact_values / sketch_values, 4),
            "mean_absolute_overestimate": round(sum(errors) / len(errors), 4),
            "median_relative_error_pct": round(
                100.0 * rel_errors[len(rel_errors) // 2], 4),
            "p95_relative_error_pct": round(
                100.0 * rel_errors[int(0.95 * len(rel_errors))], 4),
            "max_relative_error_pct": round(100.0 * rel_errors[-1], 4),
            "exact_estimates_pct": round(
                100.0 * sum(1 for e in errors if e == 0) / len(errors), 4),
            "heavy_hitters": len(heavy),
            "heavy_hitter_recall_pct": round(100.0 * recall, 4) if recall is not None else None,
            "heavy_hitter_precision_pct": round(100.0 * precision, 4) if precision is not None else None,
        })
    return out


def measure_hll(stream, precisions, key_index, label, trials=5):
    truth = len({ev[key_index] for ev in stream})
    out = []
    for p in precisions:
        errs = []
        size = None
        for t in range(trials):
            hll = HyperLogLog(p=p, seed=t)
            for ev in stream:
                hll.add(ev[key_index])
            size = hll.size_bytes()
            errs.append((hll.count() - truth) / truth)
        mean_abs = sum(abs(e) for e in errs) / len(errs)
        out.append({
            "field": label,
            "true_distinct": truth,
            "precision_p": p,
            "registers": 1 << p,
            "sketch_bytes": size,
            "exact_values_into_hss": truth,
            "sketch_values_into_hss": 1 << p,
            "value_compression_ratio": round(truth / (1 << p), 4),
            "mean_signed_error_pct": round(100.0 * sum(errs) / len(errs), 4),
            "mean_absolute_error_pct": round(100.0 * mean_abs, 4),
            "theoretical_error_pct": round(100.0 * 1.04 / math.sqrt(1 << p), 4),
            "trials": trials,
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-corpus", required=True, type=Path)
    ap.add_argument("--events", type=int, default=200000)
    ap.add_argument("--hosts", type=int, default=5000)
    ap.add_argument("--dests", type=int, default=50000)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    lines, _ = load_atomic_red_team(args.input_corpus)
    lines = sorted({s for s in lines})
    rng = random.Random(SEED)
    stream = build_stream(lines, args.events, args.hosts, args.dests, rng)

    result = {
        "stream_model": "SYNTHETIC Zipf-skewed telemetry; command lines from "
                        "the public Atomic Red Team corpus, entity "
                        "cardinalities are parameters",
        "events": args.events,
        "hosts_parameter": args.hosts,
        "dests_parameter": args.dests,
        "hss_reference": {
            "ms_per_comparison": 19.483,
            "protocol_bytes_per_comparison": 1920,
            "source": "Test 1 / Test 2B",
        },
        "count_min": [],
        "hyperloglog": [],
    }

    widths = [256, 1024, 4096, 16384, 65536]
    for idx, label in ((2, "destination"), (1, "command_line"), (0, "host")):
        result["count_min"] += measure_count_min(stream, widths, 4, idx, label)
        result["hyperloglog"] += measure_hll(stream, [8, 10, 12, 14], idx, label)

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
