#!/usr/bin/env python3
"""Test 9: the mitigation curve for the n-gram index.

Test 8 measured what an attacker recovers from a deterministic n-gram index.
This measures what it costs to take that back, as a curve rather than a point:
index-size cost against residual leakage.

Defences measured:

  size-padding      Pad every token set up to the next multiple of B with
                    dummy tokens, so |token set| no longer pins the record to
                    its exact size bucket. Targets the cheapest Test 8 attack.
  frequency-padding Inject decoy tokens whose document-frequency profile is
                    drawn from the real one, so they interleave with real
                    tokens in the attacker's frequency ranking and corrupt the
                    rank alignment her token recovery depends on.

The attacker is assumed to know the defence (Kerckhoffs), just not the secret
padding. That determines which candidates she can still rule out by size:

  * unpadded          observed size is the exact n-gram set size
  * size-padding B    the true size lies in (S-B, S], so candidates are the
                      lines that would pad to exactly S
  * frequency-padding padding only adds tokens, so candidates are the lines
                      with n-gram set size <= S

Getting this wrong in the defender's favour is the easy mistake here: scoring a
padded index against exact-size buckets would credit the defence with hiding
something the attacker never needed.

Residual leakage is reported both distributionally and operationally, by
re-running the Test 8 attack. Cost is stored tokens relative to the unpadded
index.

Position-tagging is discussed in the writeup rather than measured here: it is a
correctness fix for the Test 7 anchored false-positive result, not a leakage
defence, and the two are easy to conflate.

No cryptography is involved. Padding is modelled as adding tokens that no query
matches, which is what a dummy-token scheme provides.
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
    SEED,
    build_gram_index,
    build_population,
    identify_fast,
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
        "top100_share_pct": round(100.0 * sum(counts[:top]) / total, 4),
        "entropy_bits": round(ent, 4),
        "normalised_entropy": round(ent / math.log2(distinct), 4),
        "hapax_share_pct": round(
            100.0 * sum(1 for c in counts if c == 1) / distinct, 4),
    }


# ---------------------------------------------------------------- defences

def pad_to_buckets(token_sets, bucket, dummy_base):
    """Pad each set up to the next multiple of `bucket` with fresh dummies.

    Dummies are unique per record and drawn from a disjoint id space, so they
    add no false matches and no linkage of their own.
    """
    padded, next_id = [], dummy_base
    for ts in token_sets:
        target = int(math.ceil(len(ts) / bucket) * bucket) if bucket > 1 else len(ts)
        need = max(0, target - len(ts))
        extra = set()
        while len(extra) < need:
            extra.add(next_id)
            next_id += 1
        padded.append(frozenset(ts) | extra)
    return padded


def pad_frequency(token_sets, target_ratio, dummy_base, rng):
    """Inject decoy tokens whose df profile matches the real distribution.

    A dummy that appears in exactly as many records as a typical real token is
    indistinguishable from one by frequency alone, so it displaces real tokens
    in the attacker's ranking. `target_ratio` is extra stored tokens as a
    fraction of the unpadded index.
    """
    df = Counter()
    for ts in token_sets:
        df.update(ts)
    real_dfs = list(df.values())
    budget = int(sum(len(ts) for ts in token_sets) * target_ratio)

    padded = [set(ts) for ts in token_sets]
    records = len(padded)
    spent, next_id = 0, dummy_base
    while spent < budget:
        d = min(rng.choice(real_dfs), records, budget - spent)
        if d <= 0:
            break
        for v in rng.sample(range(records), d):
            padded[v].add(next_id)
        spent += d
        next_id += 1
    return [frozenset(p) for p in padded]


# ------------------------------------------------------- candidate models

def buckets_exact(pop):
    by = defaultdict(list)
    for i, g in enumerate(pop["gram_sets"]):
        by[len(g)].append(i)
    return lambda size: by.get(size, ())


def buckets_size_padded(pop, bucket):
    by = defaultdict(list)
    for i, g in enumerate(pop["gram_sets"]):
        padded = int(math.ceil(len(g) / bucket) * bucket) if bucket > 1 else len(g)
        by[padded].append(i)
    return lambda size: by.get(size, ())


def buckets_window(pop, base_tokens, padded_tokens):
    """Attacker who knows the padding *distribution*, not just its direction.

    Frequency padding adds a random number of decoys per record. An attacker
    who knows the scheme knows that count's mean and spread, so she can bound
    the true size from both sides instead of only from above. The window is
    mean +/- 2 sd, which covers essentially all of it; scoring against the
    weaker "size <= S" bound would flatter the defence.
    """
    import bisect

    pads = [len(p) - len(b) for b, p in zip(base_tokens, padded_tokens)]
    mean = sum(pads) / len(pads)
    var = sum((p - mean) ** 2 for p in pads) / len(pads)
    sd = math.sqrt(var)
    lo_pad = max(0, mean - 2 * sd)
    hi_pad = mean + 2 * sd

    order = sorted(range(pop["num_lines"]), key=lambda i: len(pop["gram_sets"][i]))
    sizes = [len(pop["gram_sets"][i]) for i in order]

    def fn(size):
        lo = size - hi_pad
        hi = size - lo_pad
        return order[bisect.bisect_left(sizes, lo):bisect.bisect_right(sizes, hi)]

    return fn


# ------------------------------------------------------------------ attack

def attack(pop, token_sets, candidate_fn, weights, n_obs, trials, rng,
           informed, gram_index, priors):
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
        token_map = recover_tokens(
            token_counts, priors["informed" if informed else "uninformed"], rng
        )
        by_size = {}
        for ts in observed:
            if len(ts) not in by_size:
                by_size[len(ts)] = candidate_fn(len(ts))
        cd, wc, tw = identify_fast(pop, observed, token_map, by_size, gram_index)
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


def size_leak(token_sets, candidate_fn):
    """How much the size filter still narrows the candidate space."""
    per_record = [len(candidate_fn(len(ts))) for ts in token_sets]
    per_record.sort()
    unique = sum(1 for c in per_record if c == 1)
    return {
        "records_pinned_to_one_candidate": unique,
        "records_pinned_to_one_candidate_pct": round(
            100.0 * unique / len(per_record), 4),
        "median_candidates_after_size_filter": per_record[len(per_record) // 2],
        "mean_candidates_after_size_filter": round(
            sum(per_record) / len(per_record), 2),
    }


def evaluate(pop, token_sets, candidate_fn, weights, args, gram_index, priors,
             base_cost, label):
    counts = Counter()
    for ts in token_sets:
        counts.update(ts)
    stored = sum(len(ts) for ts in token_sets)
    entry = {
        "defence": label,
        "stored_tokens": stored,
        "cost_multiplier": round(stored / base_cost, 4),
        "size_leak": size_leak(token_sets, candidate_fn),
        "distribution": distribution_stats(counts),
    }
    for informed in (False, True):
        entry["attack_" + ("informed" if informed else "uninformed")] = attack(
            pop, token_sets, candidate_fn, weights, args.observations,
            args.trials, random.Random(SEED), informed, gram_index, priors,
        )
    return entry


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
    gram_index = build_gram_index(pop)

    gram_df = Counter()
    for g in pop["gram_sets"]:
        gram_df.update(g)
    informed_prior = defaultdict(float)
    for i, w in enumerate(weights):
        for g in pop["gram_sets"][i]:
            informed_prior[g] += w
    priors = {"uninformed": gram_df, "informed": informed_prior}

    base_tokens = pop["token_sets"]
    base_cost = sum(len(ts) for ts in base_tokens)
    dummy_base = pop["vocab"] * 10

    result = {
        "input_corpus": str(args.input_corpus),
        "n": args.n,
        "observations": args.observations,
        "trials": args.trials,
        "zipf": args.zipf,
        "frequency_model": "SYNTHETIC Zipf; see Test 8",
        "baseline": evaluate(pop, base_tokens, buckets_exact(pop), weights, args,
                             gram_index, priors, base_cost, "none"),
        "size_padding": [],
        "frequency_padding": [],
    }

    for bucket in (8, 16, 32, 64, 128, 256):
        padded = pad_to_buckets(base_tokens, bucket, dummy_base)
        entry = evaluate(pop, padded, buckets_size_padded(pop, bucket), weights,
                         args, gram_index, priors, base_cost,
                         f"size-padding B={bucket}")
        entry["bucket"] = bucket
        result["size_padding"].append(entry)

    for ratio in (0.25, 0.5, 1.0, 2.0, 4.0):
        padded = pad_frequency(base_tokens, ratio, dummy_base,
                               random.Random(SEED + int(ratio * 100)))
        entry = evaluate(pop, padded, buckets_window(pop, base_tokens, padded),
                         weights, args, gram_index, priors, base_cost,
                         f"frequency-padding r={ratio}")
        entry["target_ratio"] = ratio
        result["frequency_padding"].append(entry)

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
