#!/usr/bin/env python3
"""Test 10: epoch length against investigative utility.

Tests 8 and 9 establish that deterministic tokens leak linkage unconditionally,
and that padding it away is expensive. Epoch rotation is the other lever: keys
roll on a fixed schedule and tokens are unlinkable across epochs, so leakage is
bounded by the epoch rather than by the lifetime of the data.

The cost is investigative. Any analysis that has to connect two events falling
either side of a rotation boundary loses that link. This measures how much
investigative work survives at rotation every 1h / 6h / 24h / 7d.

No cryptography is involved; Test 11 implements the rotation primitive itself.

Modelling choice, stated up front. How long a real investigation spans is not
published in any form usable here: incident-response reporting gives dwell time
(intrusion to detection), which is a different and much longer quantity than
the window an analyst must correlate across. So the span distribution is
SYNTHETIC. It is modelled as a three-component lognormal mixture, because
investigative work is not one population:

    triage    70%  median 30 min  - single-alert enrichment, pivot on a host
                                    or user over a short window
    incident  25%  median 12 h    - multi-host incident reconstruction
    campaign   5%  median 21 d    - slow, low-and-slow campaign correlation

Both the weights and the medians are assumptions. The sensitivity section
varies them, and the conclusion is reported against that spread rather than
against the central case alone.

Epoch boundaries are fixed wall-clock, not per-investigation, so an
investigation's position within its epoch is uniform. That is what makes short
epochs costly even for short investigations: a 30-minute span still has a
30/60 chance of straddling an hourly boundary.
"""

import argparse
import json
import math
import random
import sys
from collections import Counter
from pathlib import Path

HOUR = 3600.0
DAY = 24 * HOUR

EPOCHS = {
    "1h": HOUR,
    "6h": 6 * HOUR,
    "24h": DAY,
    "7d": 7 * DAY,
}

# (weight, median seconds, sigma of the underlying normal)
BASE_MIXTURE = [
    ("triage", 0.70, 30 * 60.0, 1.0),
    ("incident", 0.25, 12 * HOUR, 1.2),
    ("campaign", 0.05, 21 * DAY, 1.5),
]

EVENTS_PER_INVESTIGATION = 8


def sample_span(mixture, rng):
    u = rng.random()
    acc = 0.0
    for name, w, median, sigma in mixture:
        acc += w
        if u <= acc:
            return max(1.0, rng.lognormvariate(math.log(median), sigma)), name
    name, _, median, sigma = mixture[-1]
    return max(1.0, rng.lognormvariate(math.log(median), sigma)), name


def simulate(mixture, epoch_seconds, trials, events, rng):
    """Fraction of investigative work surviving rotation at this epoch."""
    fully = 0
    pair_fractions = []
    fragment_counts = []
    by_class = Counter()
    by_class_total = Counter()

    for _ in range(trials):
        span, cls = sample_span(mixture, rng)
        by_class_total[cls] += 1

        # Epoch boundaries are fixed wall-clock; the investigation's offset
        # within its epoch is uniform.
        start = rng.random() * epoch_seconds
        times = [start] + [start + rng.random() * span for _ in range(events - 1)]
        epochs = [int(t // epoch_seconds) for t in times]

        distinct = len(set(epochs))
        fragment_counts.append(distinct)
        if distinct == 1:
            fully += 1
            by_class[cls] += 1

        # Fraction of event pairs still linkable.
        same = total = 0
        for i in range(len(epochs)):
            for j in range(i + 1, len(epochs)):
                total += 1
                if epochs[i] == epochs[j]:
                    same += 1
        pair_fractions.append(same / total if total else 1.0)

    return {
        "fully_linkable_pct": round(100.0 * fully / trials, 4),
        "mean_pairwise_links_preserved_pct": round(
            100.0 * sum(pair_fractions) / len(pair_fractions), 4),
        "mean_epoch_fragments": round(
            sum(fragment_counts) / len(fragment_counts), 4),
        "fully_linkable_by_class_pct": {
            cls: round(100.0 * by_class[cls] / by_class_total[cls], 4)
            for cls in by_class_total if by_class_total[cls]
        },
    }


def run(mixture, trials, events, seed):
    return {
        label: simulate(mixture, seconds, trials, events, random.Random(seed))
        for label, seconds in EPOCHS.items()
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=200000)
    ap.add_argument("--events", type=int, default=EVENTS_PER_INVESTIGATION)
    ap.add_argument("--seed", type=int, default=20260724)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    result = {
        "span_model": "SYNTHETIC three-component lognormal mixture; no public "
                      "source gives investigation span distributions",
        "base_mixture": [
            {"class": c, "weight": w, "median_seconds": m, "sigma": s}
            for c, w, m, s in BASE_MIXTURE
        ],
        "events_per_investigation": args.events,
        "trials": args.trials,
        "base": run(BASE_MIXTURE, args.trials, args.events, args.seed),
        "sensitivity": {},
    }

    # Sensitivity 1: shift the population toward longer work.
    heavy = [
        ("triage", 0.40, 30 * 60.0, 1.0),
        ("incident", 0.40, 12 * HOUR, 1.2),
        ("campaign", 0.20, 21 * DAY, 1.5),
    ]
    light = [
        ("triage", 0.90, 30 * 60.0, 1.0),
        ("incident", 0.09, 12 * HOUR, 1.2),
        ("campaign", 0.01, 21 * DAY, 1.5),
    ]
    result["sensitivity"]["heavy_tail_mix"] = run(heavy, args.trials, args.events, args.seed)
    result["sensitivity"]["triage_dominated_mix"] = run(light, args.trials, args.events, args.seed)

    # Sensitivity 2: medians an order of magnitude apart either way.
    for factor, label in ((0.1, "medians_10x_shorter"), (10.0, "medians_10x_longer")):
        scaled = [(c, w, m * factor, s) for c, w, m, s in BASE_MIXTURE]
        result["sensitivity"][label] = run(scaled, args.trials, args.events, args.seed)

    # Sensitivity 3: number of events an investigation must join.
    for ev in (2, 4, 16, 64):
        result["sensitivity"][f"events_{ev}"] = run(
            BASE_MIXTURE, args.trials, ev, args.seed)

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
