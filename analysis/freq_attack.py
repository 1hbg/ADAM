#!/usr/bin/env python3
"""Test 8: frequency attack against the n-gram index.

Test 7 measured that the n-gram frequency distribution is Zipf-like but
deliberately stopped short of converting skew into an attack number. This
closes that loop, in the same shape as the Test 4 OPRF frequency analysis:
how many observations does an attacker need before she can say which command
line is behind an observed token set?

Threat model. The index stores, per field, the set of tokens of its n-grams.
Tokens are deterministic pseudonymous labels: the same n-gram always yields the
same token, globally. The attacker sees token sets and nothing else. She does
not break any primitive; everything here follows from determinism plus skew.

Tokens are modelled as a secret random relabelling of the n-gram space, which
is what a PRF-based token scheme provides. The attacker code below touches only
token identity and token frequency, never the underlying string - including for
tie-breaking, which would otherwise smuggle plaintext order into the attack.

Two capability levels are separated, because they answer different questions:

  * Uninformed  - holds the public dictionary of candidate command lines but
                  no knowledge of how often the victim runs each one. This is
                  the realistic baseline, since the dictionary here is a public
                  repository.
  * Informed    - additionally knows the victim's execution-frequency
                  distribution. This is the upper bound on what frequency
                  knowledge buys.

Linkage is reported separately from identification. Because tokens are
deterministic, two executions of the same command line produce byte-identical
token sets, so an attacker can tell "these two records are the same command"
with zero background knowledge and two observations. Identification - saying
*which* command - is what needs the dictionary.

No cryptography is involved here; Test 11 implements the real primitive.
"""

import argparse
import json
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ngram_cost import load_atomic_red_team, ngrams  # noqa: E402

N_GRID = [10, 100, 1000, 10000, 100000]
TRIALS = 20
SEED = 20260724


# ------------------------------------------------------------- population

def build_population(lines, n, rng):
    """Distinct lines, their n-gram sets, opaque token sets, and the ceiling.

    Lines whose n-gram sets are identical can never be told apart by any
    attacker against this index, so identification is scored against
    equivalence classes rather than against raw lines.
    """
    distinct = sorted({s.lower() for s in lines})
    gram_sets, kept = [], []
    for s in distinct:
        g = frozenset(ngrams(s, n))
        if g:
            gram_sets.append(g)
            kept.append(s)

    # Secret relabelling: n-gram -> opaque token id. The attacker sees only
    # these ids, so any statistic she computes must be frequency or structure.
    vocab = sorted({g for gs in gram_sets for g in gs})
    ids = list(range(len(vocab)))
    rng.shuffle(ids)
    token_of = dict(zip(vocab, ids))
    gram_of = {v: k for k, v in token_of.items()}

    token_sets = [frozenset(token_of[g] for g in gs) for gs in gram_sets]

    classes = {}
    for i, g in enumerate(gram_sets):
        classes.setdefault(g, []).append(i)
    class_of = {}
    for members in classes.values():
        for i in members:
            class_of[i] = members[0]

    return {
        "lines": kept,
        "gram_sets": gram_sets,
        "token_sets": token_sets,
        "token_of": token_of,
        "gram_of": gram_of,
        "class_of": class_of,
        "num_lines": len(kept),
        "num_classes": len(classes),
        "collapsed": len(kept) - len(classes),
        "vocab": len(vocab),
    }


def zipf_weights(k, s, rng):
    """Zipf(s) over k lines in a randomised rank order.

    SYNTHETIC. No public corpus carries real execution frequencies, so this is
    a modelling assumption, not a measurement. Sensitivity to s is reported.
    """
    order = list(range(k))
    rng.shuffle(order)
    w = [0.0] * k
    for rank, idx in enumerate(order, start=1):
        w[idx] = 1.0 / (rank ** s)
    total = sum(w)
    return [x / total for x in w]


# ----------------------------------------------------------------- attacks

def size_fingerprint(pop):
    """A0: identification from token-set size alone.

    Needs no frequency knowledge and a single observation. |token set| equals
    |n-gram set|, which the attacker can compute for every public candidate.
    """
    class_rep = {}
    for i, g in enumerate(pop["gram_sets"]):
        class_rep.setdefault(pop["class_of"][i], g)
    class_sizes = Counter(len(g) for g in class_rep.values())
    unique_classes = sum(1 for g in class_rep.values() if class_sizes[len(g)] == 1)
    buckets = sorted(class_sizes.values(), reverse=True)
    return {
        "classes_with_unique_set_size": unique_classes,
        "classes_with_unique_set_size_pct": round(
            100.0 * unique_classes / pop["num_classes"], 4),
        "largest_size_bucket": buckets[0] if buckets else 0,
        "median_size_bucket": buckets[len(buckets) // 2] if buckets else 0,
    }


def recover_tokens(token_counts, prior_scores, tie_rng):
    """Map token id -> n-gram by matching observed rank to prior rank.

    Ties are broken by an attacker-side random draw, never by the underlying
    string: the attacker has no access to it.
    """
    tokens = sorted(token_counts, key=lambda t: (-token_counts[t], tie_rng.random()))
    grams = sorted(prior_scores, key=lambda g: (-prior_scores[g], tie_rng.random()))
    return dict(zip(tokens, grams))


def identify(pop, observed, token_map, by_size):
    """Identify each distinct observed token set against the dictionary.

    |token set| is known exactly, so only candidates of that size are possible;
    within the bucket the best overlap under the recovered token map wins.
    """
    correct_distinct = weighted_correct = total_weight = 0
    for tokens, (truth, weight) in observed.items():
        total_weight += weight
        mapped = {token_map[t] for t in tokens if t in token_map}
        candidates = by_size.get(len(tokens), ())
        best, best_score = None, -1
        for idx in candidates:
            score = len(mapped & pop["gram_sets"][idx])
            if score > best_score:
                best, best_score = idx, score
        if best is not None and pop["class_of"][best] == pop["class_of"][truth]:
            correct_distinct += 1
            weighted_correct += weight
    return correct_distinct, weighted_correct, total_weight


def build_gram_index(pop):
    """gram -> dictionary line indices, for the fast identifier."""
    index = defaultdict(list)
    for i, gs in enumerate(pop["gram_sets"]):
        for g in gs:
            index[g].append(i)
    return index


def identify_fast(pop, observed, token_map, by_size, gram_index):
    """Same result as identify(), but scored through an inverted index.

    Padding (Test 9) makes size buckets large, at which point scanning every
    candidate per record is the bottleneck. Overlap is sparse, so accumulating
    through posting lists is much cheaper. Candidate iteration order and the
    strict-greater tie-break are kept identical to identify() so the two agree
    exactly; `test_identify_equivalence` asserts it.
    """
    correct_distinct = weighted_correct = total_weight = 0
    for tokens, (truth, weight) in observed.items():
        total_weight += weight
        candidates = by_size.get(len(tokens), ())
        if not candidates:
            continue
        in_bucket = set(candidates)
        scores = Counter()
        for t in tokens:
            g = token_map.get(t)
            if g is None:
                continue
            for i in gram_index.get(g, ()):
                if i in in_bucket:
                    scores[i] += 1
        best, best_score = None, -1
        for idx in candidates:
            score = scores.get(idx, 0)
            if score > best_score:
                best, best_score = idx, score
        if best is not None and pop["class_of"][best] == pop["class_of"][truth]:
            correct_distinct += 1
            weighted_correct += weight
    return correct_distinct, weighted_correct, total_weight


def run_trial(pop, weights, n_obs, rng, prior, by_size):
    # Draw N observations, then fold repeats: a line seen k times contributes
    # its token set k times, so counting multiplicities first turns N set
    # updates into at most one per distinct line.
    multiplicity = Counter(rng.choices(range(pop["num_lines"]), weights=weights, k=n_obs))

    observed = {}
    token_counts = Counter()
    for i, k in multiplicity.items():
        t = pop["token_sets"][i]
        for tok in t:
            token_counts[tok] += k
        observed[t] = (i, k)

    token_map = recover_tokens(token_counts, prior, rng)

    correct = sum(1 for t, g in token_map.items() if pop["token_of"][g] == t)
    weighted = sum(
        token_counts[t] for t, g in token_map.items() if pop["token_of"][g] == t
    )
    occ = sum(token_counts.values())

    cd, wc, tw = identify(pop, observed, token_map, by_size)
    return {
        "distinct_observed": len(observed),
        "distinct_identified": cd,
        "obs_identified": wc,
        "obs_total": tw,
        "token_map_accuracy": correct / len(token_map) if token_map else 0.0,
        "token_map_accuracy_weighted": weighted / occ if occ else 0.0,
    }


def crossing(curve, key, threshold):
    """First N on the grid at which `key` reaches threshold, log-interpolated."""
    prev_n = prev_v = None
    for point in curve:
        v = point[key]
        if v >= threshold:
            if prev_n is None or v == prev_v:
                return point["n_observations"]
            frac = (threshold - prev_v) / (v - prev_v)
            return int(round(math.exp(
                math.log(prev_n)
                + frac * (math.log(point["n_observations"]) - math.log(prev_n))
            )))
        prev_n, prev_v = point["n_observations"], v
    return None


def analyse(pop, s, trials, rng):
    weights = zipf_weights(pop["num_lines"], s, rng)

    by_size = defaultdict(list)
    for i, g in enumerate(pop["gram_sets"]):
        by_size[len(g)].append(i)

    # Uninformed prior: document frequency in the public dictionary, i.e. a
    # uniform prior over candidate lines.
    gram_df = Counter()
    for g in pop["gram_sets"]:
        gram_df.update(g)

    # Informed prior: knows the victim's line frequencies, so can predict each
    # n-gram's expected observation share exactly.
    informed_prior = defaultdict(float)
    for i, w in enumerate(weights):
        for g in pop["gram_sets"][i]:
            informed_prior[g] += w

    out = {}
    for informed in (False, True):
        prior = informed_prior if informed else gram_df
        curve = []
        for n_obs in N_GRID:
            acc = Counter()
            for _ in range(trials):
                for k, v in run_trial(
                    pop, weights, n_obs, rng, prior, by_size
                ).items():
                    acc[k] += v
            distinct = acc["distinct_observed"] or 1
            obs_total = acc["obs_total"] or 1
            curve.append({
                "n_observations": n_obs,
                "mean_distinct_lines_seen": round(acc["distinct_observed"] / trials, 2),
                "identified_distinct_pct": round(
                    100.0 * acc["distinct_identified"] / distinct, 4),
                "identified_traffic_pct": round(
                    100.0 * acc["obs_identified"] / obs_total, 4),
                "token_map_accuracy_pct": round(
                    100.0 * acc["token_map_accuracy"] / trials, 4),
                "token_map_accuracy_weighted_pct": round(
                    100.0 * acc["token_map_accuracy_weighted"] / trials, 4),
            })
        out["informed" if informed else "uninformed"] = {
            "curve": curve,
            "observations_for_50pct_traffic": crossing(curve, "identified_traffic_pct", 50.0),
            "observations_for_90pct_traffic": crossing(curve, "identified_traffic_pct", 90.0),
            "observations_for_50pct_distinct": crossing(curve, "identified_distinct_pct", 50.0),
            "observations_for_90pct_distinct": crossing(curve, "identified_distinct_pct", 90.0),
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-corpus", required=True, type=Path)
    ap.add_argument("--trials", type=int, default=TRIALS)
    ap.add_argument("--zipf", type=float, nargs="+", default=[1.0])
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    lines, tests = load_atomic_red_team(args.input_corpus)
    result = {
        "input_corpus": str(args.input_corpus),
        "input_lines": len(lines),
        "input_tests": tests,
        "trials_per_point": args.trials,
        "seed": SEED,
        "frequency_model": "SYNTHETIC Zipf over command lines; no public corpus "
                           "carries real execution frequencies",
        "by_n": {},
    }

    for n in (3, 4, 5):
        pop = build_population(lines, n, random.Random(SEED + n))
        entry = {
            "distinct_lines": pop["num_lines"],
            "ngram_vocabulary": pop["vocab"],
            "indistinguishable_classes": pop["num_classes"],
            "lines_collapsed_by_identical_ngram_sets": pop["collapsed"],
            "ceiling_pct": round(100.0 * pop["num_classes"] / pop["num_lines"], 4),
            "size_fingerprint": size_fingerprint(pop),
            "zipf": {},
        }
        for s in args.zipf:
            entry["zipf"][str(s)] = analyse(pop, s, args.trials, random.Random(SEED + n))
        result["by_n"][str(n)] = entry

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
