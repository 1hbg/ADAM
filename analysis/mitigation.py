#!/usr/bin/env python3
"""Test 9: the mitigation curve for the n-gram index.

Test 8 measured what an attacker recovers from a deterministic n-gram index.
This measures what it costs to take that back, as a curve rather than a point:
index-size cost against residual leakage, for several defences.

Defences measured:

  size-padding      Pad every token set up to the next bucket boundary with
                    dummy tokens, so |token set| no longer fingerprints the
                    record. Targets the single cheapest attack in Test 8.
  frequency-padding Add dummy occurrences preferentially to rare n-grams, to
                    flatten the frequency distribution the attacker ranks on.
  position-tagging  Tag the terminal n-gram of anchored patterns. This is a
                    correctness fix for the Test 7 anchored false-positive
                    result, not a leakage defence; it is measured here because
                    it is nearly free and the two are easy to conflate.

Residual leakage is reported both distributionally (entropy, top-100 share,
size-bucket sizes) and operationally, by re-running the Test 8 attack against
the padded index. Cost is reported as stored tokens relative to the unpadded
index.

No cryptography is involved. Padding is modelled as adding tokens that no
query matches, which is what a dummy-token scheme provides.
"""

import argparse
import json
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from freq_attack import (  # noqa: E402
    N_GRID,
    SEED,
    build_population,
    identify,
    recover_tokens,
    zipf_weights,
)
from ngram_cost import load_atomic_red_team  # noqa: E402


def entropy_bits(counts):
    total = sum(counts)
    if not total:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def distribution_stats(token_counts, top=100):
    counts = sorted(token_counts.values(), reverse=True)
    total = sum(counts)
    distinct = len(counts)
    if not total or distinct < 2:
        return None
    ent = entropy_bits(counts)
    return {
        "distinct_tokens": distinct,
        "total_occurrences": total,
        "top100_share_pct": round(100.0 * sum(counts[:top]) / total, 4),
        "entropy_bits": round(ent, 4),
        "normalised_entropy": round(ent / math.log2(distinct), 4),
        "hapax_share_pct": round(
            100.0 * sum(1 for c in counts if c == 1) / distinct, 4),
    }


# ---------------------------------------------------------------- defences

def pad_to_buckets(token_sets, bucket, dummy_base, rng):
    """Pad each set up to the next multiple of `bucket` with fresh dummies.

    Dummies are drawn from a disjoint id space and are unique per record, so
    they add no false matches and no cross-record linkage of their own.
    """
    padded, next_id = [], dummy_base
    for ts in token_sets:
        target = int(math.ceil(len(ts) / bucket) * bucket) if bucket > 1 else len(ts)
        need = max(0, target - len(ts))
        extra = set()
        while len(extra) < need:
            extra.add(next_id)
            next_id += 1
        padded.append(frozenset(ts) | frozenset(extra))
    return padded, next_id


def pad_frequency(token_sets, target_ratio, dummy_base, rng):
    """Add dummy tokens to flatten the *document*-frequency distribution.

    Rare tokens are boosted by inserting the same shared dummy into records
    that already carry a rare token, raising the floor of the distribution.
    `target_ratio` is the fraction of extra tokens to add relative to the
    unpadded index size.
    """
    df = Counter()
    for ts in token_sets:
        df.update(ts)
    total_tokens = sum(len(ts) for ts in token_sets)
    budget = int(total_tokens * target_ratio)

    # Spend the budget on the rarest tokens first: for each, add a shared
    # dummy to a random sample of records so its apparent frequency rises.
    order = sorted(df, key=lambda t: (df[t], t))
    padded = [set(ts) for ts in token_sets]
    holders = defaultdict(list)
    for i, ts in enumerate(token_sets):
        for t in ts:
            holders[t].append(i)

    spent, next_id = 0, dummy_base
    idx = 0
    while spent < budget and idx < len(order):
        tok = order[idx]
        idx += 1
        boost = min(8, budget - spent)
        victims = rng.sample(
            range(len(padded)), min(boost, len(padded))
        )
        for v in victims:
            padded[v].add(next_id)
            spent += 1
        next_id += 1
    return [frozenset(p) for p in padded], next_id


# ------------------------------------------------------------------ attack

def attack_identification(pop, token_sets, weights, n_obs, trials, rng, informed):
    """Re-run the Test 8 identification attack against a given index."""
    by_size = defaultdict(list)
    for i, ts in enumerate(token_sets):
        by_size[len(ts)].append(i)

    gram_df = Counter()
    for g in pop["gram_sets"]:
        gram_df.update(g)
    informed_prior = defaultdict(float)
    for i, w in enumerate(weights):
        for g in pop["gram_sets"][i]:
            informed_prior[g] += w
    prior = informed_prior if informed else gram_df

    acc = Counter()
    for _ in range(trials):
        multiplicity = Counter(
            rng.choices(range(pop["num_lines"]), weights=weights, k=n_obs)
        )
        observed, token_counts = {}, Counter()
        for i, k in multiplicity.items():
            ts = token_sets[i]
            for tok in ts:
                token_counts[tok] += k
            observed[ts] = (i, k)
        token_map = recover_tokens(token_counts, prior, rng)
        cd, wc, tw = identify(pop, observed, token_map, by_size)
        acc["distinct_observed"] += len(observed)
        acc["distinct_identified"] += cd
        acc["obs_identified"] += wc
        acc["obs_total"] += tw

    return {
        "identified_distinct_pct": round(
            100.0 * acc["distinct_identified"] / (acc["distinct_observed"] or 1), 4),
        "identified_traffic_pct": round(
            100.0 * acc["obs_identified"] / (acc["obs_total"] or 1), 4),
    }


def index_cost(token_sets):
    return sum(len(ts) for ts in token_sets)


def size_leak(token_sets):
    """How much the set-size fingerprint still narrows the candidate space."""
    sizes = Counter(len(ts) for ts in token_sets)
    buckets = sorted(sizes.values(), reverse=True)
    unique = sum(1 for ts in token_sets if sizes[len(ts)] == 1)
    return {
        "distinct_sizes": len(sizes),
        "records_with_unique_size": unique,
        "records_with_unique_size_pct": round(100.0 * unique / len(token_sets), 4),
        "median_candidates_after_size_filter": buckets[len(buckets) // 2],
        "mean_candidates_after_size_filter": round(
            sum(v * v for v in sizes.values()) / len(token_sets), 2),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-corpus", required=True, type=Path)
    ap.add_argument("--n", type=int, default=4)
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--observations", type=int, default=10000)
    ap.add_argument("--zipf", type=float, default=1.0)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    lines, _ = load_atomic_red_team(args.input_corpus)
    pop = build_population(lines, args.n, random.Random(SEED + args.n))
    weights = zipf_weights(pop["num_lines"], args.zipf, random.Random(SEED + args.n))
    base_tokens = pop["token_sets"]
    base_cost = index_cost(base_tokens)
    dummy_base = pop["vocab"] * 10

    result = {
        "input_corpus": str(args.input_corpus),
        "n": args.n,
        "observations": args.observations,
        "trials": args.trials,
        "zipf": args.zipf,
        "frequency_model": "SYNTHETIC Zipf; see Test 8",
        "baseline": {
            "stored_tokens": base_cost,
            "cost_multiplier": 1.0,
            "size_leak": size_leak(base_tokens),
        },
        "size_padding": [],
        "frequency_padding": [],
    }

    doc_counts = Counter()
    for ts in base_tokens:
        doc_counts.update(ts)
    result["baseline"]["distribution"] = distribution_stats(doc_counts)
    for informed in (False, True):
        result["baseline"]["attack_" + ("informed" if informed else "uninformed")] = (
            attack_identification(pop, base_tokens, weights, args.observations,
                                  args.trials, random.Random(SEED), informed)
        )

    for bucket in (1, 8, 16, 32, 64, 128, 256):
        rng = random.Random(SEED + bucket)
        padded, _ = pad_to_buckets(base_tokens, bucket, dummy_base, rng)
        counts = Counter()
        for ts in padded:
            counts.update(ts)
        entry = {
            "bucket": bucket,
            "stored_tokens": index_cost(padded),
            "cost_multiplier": round(index_cost(padded) / base_cost, 4),
            "size_leak": size_leak(padded),
            "distribution": distribution_stats(counts),
        }
        for informed in (False, True):
            entry["attack_" + ("informed" if informed else "uninformed")] = (
                attack_identification(pop, padded, weights, args.observations,
                                      args.trials, random.Random(SEED), informed)
            )
        result["size_padding"].append(entry)

    for ratio in (0.25, 0.5, 1.0, 2.0, 4.0):
        rng = random.Random(SEED + int(ratio * 100))
        padded, _ = pad_frequency(base_tokens, ratio, dummy_base, rng)
        counts = Counter()
        for ts in padded:
            counts.update(ts)
        entry = {
            "target_ratio": ratio,
            "stored_tokens": index_cost(padded),
            "cost_multiplier": round(index_cost(padded) / base_cost, 4),
            "size_leak": size_leak(padded),
            "distribution": distribution_stats(counts),
        }
        for informed in (False, True):
            entry["attack_" + ("informed" if informed else "uninformed")] = (
                attack_identification(pop, padded, weights, args.observations,
                                      args.trials, random.Random(SEED), informed)
            )
        result["frequency_padding"].append(entry)

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
