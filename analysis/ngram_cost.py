#!/usr/bin/env python3
"""Test 7: can substring search be expressed as a set operation?

Substring matching dominates the process_creation and network slices measured
in Test 5, and it is the hardest case for any encrypted-lookup approach. The
standard way to turn it into a set operation is n-gram tokenisation: index the
set of n-grams of each field, and answer a substring query by testing whether
the query's n-gram set is contained in the field's.

That transformation is *complete but not sound*. If P is a substring of S then
every n-gram of P is an n-gram of S, so the filter never misses a true match.
The converse does not hold, so the filter admits false positives and needs an
exact re-check on whatever it lets through. This module measures the four costs
that decides whether the trade is worth making:

  1. inflation      - n-grams stored per field, at n = 3, 4, 5
  2. inexpressible  - patterns shorter than n, which cannot be queried at all
  3. skew           - the frequency distribution of distinct n-grams; this is
                      the leakage measure and the reason to care
  4. false positives- how often the set test passes without a real substring

Patterns come from the Sigma corpus (Test 5 parser, reused). Input comes from
a public command-line corpus; see --input-corpus.

No cryptography is involved. This measures the tokenisation, not a scheme.
"""

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

sys.path.insert(0, str(Path(__file__).resolve().parent))
from op_distribution import (  # noqa: E402
    COMBINATOR_MODS,
    REGEX_FLAG_MODS,
    TRANSFORM_MODS,
    collect,
    split_field,
)

SUPPORTED_DIRS = [
    "rules", "rules-compliance", "rules-dfir", "rules-emerging-threats",
    "rules-threat-hunting",
]

# Anchored modifiers are reported separately from unanchored `contains`:
# an anchored match can be expressed more cheaply than a free substring by
# position-tagging the n-grams at each end, so pooling them would overstate
# the cost of the anchored case and understate it for `contains`.
UNANCHORED_MODS = {"contains"}
ANCHORED_MODS = {"startswith", "endswith"}

PLACEHOLDER_RE = re.compile(r"#\{([^}]+)\}")
CMDLINE_FIELD_RE = re.compile(r"commandline|cmdline", re.I)


# ---------------------------------------------------------------- patterns

def extract_patterns(corpus, slices=("process_creation", "network")):
    """Pull every substring literal out of the requested Test 5 slices."""
    corpus = Path(corpus)
    records, errors = collect(corpus, SUPPORTED_DIRS)
    wanted = set(slices)
    out = []
    for rec in records:
        if not wanted.intersection(rec["slices"]):
            continue
        path = Path(corpus) / rec["path"]
        try:
            docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
        except Exception:  # noqa: BLE001
            continue
        detection = (docs[0] or {}).get("detection") or {}
        if not isinstance(detection, dict):
            continue
        for key, value in detection.items():
            if key in ("condition", "timeframe"):
                continue
            _walk(key, value, rec, out)
    return out, errors


def _walk(key, node, rec, out):
    if isinstance(node, dict):
        for k, v in node.items():
            _walk(k, v, rec, out)
        return
    if isinstance(node, list):
        for item in node:
            if isinstance(item, dict):
                _walk(key, item, rec, out)
            else:
                _emit(key, item, rec, out)
        return
    _emit(key, node, rec, out)


def _emit(key, value, rec, out):
    if not isinstance(value, str) or not value:
        return
    field, mods = split_field(key)
    # `expand` values are placeholder names resolved at deploy time, not
    # literals; they are not patterns and would pollute every length metric.
    if "expand" in mods:
        return
    effective = [
        m for m in mods
        if m not in TRANSFORM_MODS
        and m not in COMBINATOR_MODS
        and m not in REGEX_FLAG_MODS
    ]
    kind = None
    for m in effective:
        if m in UNANCHORED_MODS:
            kind = "contains"
        elif m in ANCHORED_MODS:
            kind = m
    if kind is None:
        return
    out.append({
        "pattern": value,
        "kind": kind,
        "field": field,
        "slices": rec["slices"],
        "cmdline_field": bool(CMDLINE_FIELD_RE.search(field)),
    })


# ------------------------------------------------------------ input corpus

def load_atomic_red_team(root):
    """Command lines from Atomic Red Team, with input defaults substituted.

    Each executor command block is split into lines, because a process
    CommandLine field holds one line, not a whole script.
    """
    lines, tests = [], 0
    for path in sorted(Path(root).glob("atomics/T*/T*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        for test in (doc or {}).get("atomic_tests") or []:
            executor = test.get("executor") or {}
            command = executor.get("command")
            if not command:
                continue
            tests += 1
            args = test.get("input_arguments") or {}
            defaults = {
                k: str((v or {}).get("default", ""))
                for k, v in args.items() if isinstance(v, dict)
            }
            resolved = PLACEHOLDER_RE.sub(
                lambda m: defaults.get(m.group(1), m.group(0)), command
            )
            for line in resolved.splitlines():
                line = line.strip()
                if line:
                    lines.append(line)
    return lines, tests


# ----------------------------------------------------------------- n-grams

def ngrams(s, n):
    return [s[i:i + n] for i in range(len(s) - n + 1)]


def _stats(values):
    if not values:
        return None
    vs = sorted(values)
    k = len(vs)
    return {
        "count": k,
        "mean": round(sum(vs) / k, 4),
        "median": vs[k // 2],
        "p95": vs[min(k - 1, int(0.95 * k))],
        "max": vs[-1],
        "total": sum(vs),
    }


def skew(counter, top=100):
    """Frequency distribution of distinct n-grams. The leakage measure."""
    if not counter:
        return None
    counts = sorted(counter.values(), reverse=True)
    total = sum(counts)
    distinct = len(counts)

    def covering(fraction):
        acc, k = 0, 0
        target = fraction * total
        for c in counts:
            acc += c
            k += 1
            if acc >= target:
                return k
        return distinct

    entropy = -sum((c / total) * math.log2(c / total) for c in counts)
    return {
        "distinct": distinct,
        "total_occurrences": total,
        "top100_occurrences": sum(counts[:top]),
        "top100_share_pct": round(100.0 * sum(counts[:top]) / total, 4),
        "top100_share_of_distinct_pct": round(100.0 * min(top, distinct) / distinct, 4),
        "ngrams_covering_50pct": covering(0.50),
        "ngrams_covering_90pct": covering(0.90),
        "hapax": sum(1 for c in counts if c == 1),
        "hapax_share_pct": round(100.0 * sum(1 for c in counts if c == 1) / distinct, 4),
        "entropy_bits": round(entropy, 4),
        "max_entropy_bits": round(math.log2(distinct), 4),
        "normalised_entropy": round(entropy / math.log2(distinct), 4) if distinct > 1 else None,
        "max_count": counts[0],
    }


# ----------------------------------------------------------- false positives

def false_positives(patterns, inputs, n):
    """Exact false-positive rate of the n-gram set filter.

    The filter admits input S for pattern P iff ngrams(P) is a subset of
    ngrams(S). Because that is exactly an intersection of posting lists, the
    inverted index computes the filter-positive set directly rather than
    testing each pair.
    """
    lowered = [s.lower() for s in inputs]
    index = defaultdict(set)
    for i, s in enumerate(lowered):
        for g in set(ngrams(s, n)):
            index[g].add(i)

    tp = fp = 0
    positives = 0
    per_pattern = []
    by_kind = defaultdict(lambda: {"positives": 0, "tp": 0, "fp": 0})
    for rec in patterns:
        p = rec["pattern"].lower()
        grams = set(ngrams(p, n))
        if not grams:
            continue  # shorter than n: inexpressible, counted separately
        posting = sorted((index.get(g, set()) for g in grams), key=len)
        if not posting[0]:
            continue
        candidates = set(posting[0])
        for pl in posting[1:]:
            candidates &= pl
            if not candidates:
                break
        if not candidates:
            continue
        p_tp = p_fp = 0
        for i in candidates:
            s = lowered[i]
            if rec["kind"] == "contains":
                hit = p in s
            elif rec["kind"] == "startswith":
                hit = s.startswith(p)
            else:
                hit = s.endswith(p)
            if hit:
                p_tp += 1
            else:
                p_fp += 1
        tp += p_tp
        fp += p_fp
        positives += len(candidates)
        k = by_kind["contains" if rec["kind"] == "contains" else "anchored"]
        k["positives"] += len(candidates)
        k["tp"] += p_tp
        k["fp"] += p_fp
        if p_fp:
            per_pattern.append((rec["pattern"], rec["kind"], p_tp, p_fp))

    for stats in by_kind.values():
        stats["precision_pct"] = (
            round(100.0 * stats["tp"] / stats["positives"], 4)
            if stats["positives"] else None
        )

    return {
        "filter_positives": positives,
        "true_positives": tp,
        "false_positives": fp,
        "precision_pct": round(100.0 * tp / positives, 4) if positives else None,
        "fp_share_of_positives_pct": round(100.0 * fp / positives, 4) if positives else None,
        "patterns_with_any_fp": len(per_pattern),
        "by_kind": dict(by_kind),
        "worst_patterns": sorted(per_pattern, key=lambda r: -r[3])[:10],
    }


# -------------------------------------------------------------------- main

def analyse(patterns, inputs, n):
    expressible = [p for p in patterns if len(p["pattern"]) >= n]
    too_short = [p for p in patterns if len(p["pattern"]) < n]

    pattern_grams = Counter()
    for rec in expressible:
        pattern_grams.update(set(ngrams(rec["pattern"].lower(), n)))

    input_grams = Counter()
    per_input_distinct, per_input_positions = [], []
    for s in inputs:
        g = ngrams(s.lower(), n)
        if not g:
            continue
        input_grams.update(g)
        per_input_positions.append(len(g))
        per_input_distinct.append(len(set(g)))

    cmdline = [p for p in expressible if p["cmdline_field"]]

    return {
        "n": n,
        "patterns_total": len(patterns),
        "patterns_expressible": len(expressible),
        "patterns_too_short": len(too_short),
        "patterns_too_short_pct": round(100.0 * len(too_short) / len(patterns), 4) if patterns else None,
        "too_short_by_kind": dict(Counter(p["kind"] for p in too_short)),
        "inflation_per_pattern": _stats([
            len(p["pattern"]) - n + 1 for p in expressible
        ]),
        "inflation_per_input_field_positions": _stats(per_input_positions),
        "inflation_per_input_field_distinct": _stats(per_input_distinct),
        "skew_input_corpus": skew(input_grams),
        "skew_pattern_set": skew(pattern_grams),
        "false_positives_cmdline_patterns": false_positives(cmdline, inputs, n),
        "false_positives_all_patterns": false_positives(expressible, inputs, n),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, type=Path,
                    help="path to a SigmaHQ/sigma checkout")
    ap.add_argument("--input-corpus", required=True, type=Path,
                    help="path to a redcanaryco/atomic-red-team checkout")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    patterns, _ = extract_patterns(args.corpus)
    inputs, tests = load_atomic_red_team(args.input_corpus)
    if not inputs:
        sys.exit("no input command lines found; check --input-corpus")

    by_kind = Counter(p["kind"] for p in patterns)
    distinct_by_kind = defaultdict(set)
    for p in patterns:
        distinct_by_kind[p["kind"]].add(p["pattern"])

    # Deduplicate: the same literal appears in many rules, and counting it
    # once per rule would inflate every distribution below.
    seen, unique = set(), []
    for p in patterns:
        keyed = (p["pattern"], p["kind"])
        if keyed not in seen:
            seen.add(keyed)
            unique.append(p)

    result = {
        "sigma_corpus": str(args.corpus),
        "input_corpus": str(args.input_corpus),
        "input_corpus_kind": "atomic-red-team",
        "input_lines": len(inputs),
        "input_tests": tests,
        "patterns_occurrences": len(patterns),
        "patterns_unique": len(unique),
        "occurrences_by_kind": dict(by_kind),
        "unique_by_kind": {k: len(v) for k, v in distinct_by_kind.items()},
        "unique_cmdline_field": sum(1 for p in unique if p["cmdline_field"]),
        "by_n": {},
    }
    for n in (3, 4, 5):
        result["by_n"][str(n)] = analyse(unique, inputs, n)

    print(json.dumps(result, indent=2, default=str))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")


if __name__ == "__main__":
    main()
