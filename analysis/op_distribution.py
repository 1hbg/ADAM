#!/usr/bin/env python3
"""Test 5: operation distribution in detection content.

Classifies every atomic operation in a Sigma rule corpus as either a
join/lookup (matching) or a numeric computation. The question this answers for
ADAM is how much of real detection work an arithmetic-friendly primitive could
cover at all: MORSE HSS is cheap for addition and linear work and expensive for
matching, so the ratio bounds what the primitive can serve.

This is a static analysis of rule definitions. It counts the operations a rule
*declares*, not operations executed at runtime against an event stream. No
execution frequency data is used and none is implied.

Usage:
    python3 analysis/op_distribution.py --corpus /path/to/sigma
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

MATCH = "match"
NUMERIC = "numeric"
OTHER = "other"

# Sigma value modifiers, grouped by what they do to an operation's semantics.
# Reference: sigma/documentation and the sigma-specification repository.
TRANSFORM_MODS = {
    "base64", "base64offset", "wide", "utf16", "utf16le", "utf16be", "expand",
}
NUMERIC_MODS = {"gt", "gte", "lt", "lte"}
MATCH_MODS = {
    "contains", "startswith", "endswith", "re", "cidr", "fieldref", "exists",
    "cased",
}
# Modifiers that change how a value list combines or expands, but leave the
# operation a match: they do not add an operation of their own.
COMBINATOR_MODS = {"all", "windash"}
REGEX_FLAG_MODS = {"i", "m", "s"}

AGG_FUNC_RE = re.compile(r"\b(count|min|max|avg|sum)\s*\(", re.I)
AGG_BY_RE = re.compile(r"\bby\s+([A-Za-z_][\w.]*)", re.I)
THRESHOLD_RE = re.compile(r"(?:[<>]=?|==?|!=)\s*\d+")
NEAR_RE = re.compile(r"\bnear\b", re.I)
BOOL_RE = re.compile(r"\b(and|or|not)\b", re.I)
QUANTIFIER_RE = re.compile(r"\b(\d+|all)\s+of\b", re.I)

CLOUD_PRODUCTS = {
    "aws", "azure", "gcp", "m365", "okta", "onelogin", "alibabacloud", "oci",
    "kubernetes", "github", "bitbucket", "google_workspace", "salesforce",
}
NETWORK_CATEGORIES = {
    "network_connection", "dns_query", "dns", "firewall", "proxy", "webserver",
    "netflow", "zeek",
}


def split_field(key):
    """Return (field_name, [modifiers]) for a Sigma detection map key."""
    parts = str(key).split("|")
    return parts[0], [p.lower() for p in parts[1:]]


def classify_predicate(key, value):
    """Classify one field predicate into a list of (bucket, subtype) ops.

    One field predicate is one operation regardless of how many values its
    value list holds: a set-membership test against ten IOCs is one lookup.
    Encoding modifiers add a separate decode operation, because decoding is
    genuinely separate work from the comparison that follows it.
    """
    field, mods = split_field(key)
    ops = []

    for mod in mods:
        if mod in TRANSFORM_MODS:
            ops.append((OTHER, f"decode/{mod}"))

    effective = [
        m for m in mods
        if m not in TRANSFORM_MODS
        and m not in COMBINATOR_MODS
        and m not in REGEX_FLAG_MODS
    ]

    numeric_mods = [m for m in effective if m in NUMERIC_MODS]
    match_mods = [m for m in effective if m in MATCH_MODS]
    unknown = [m for m in effective if m not in NUMERIC_MODS and m not in MATCH_MODS]

    if numeric_mods:
        ops.append((NUMERIC, f"compare/{numeric_mods[0]}"))
    elif match_mods:
        ops.append((MATCH, f"match/{match_mods[0]}"))
    elif unknown:
        ops.append((OTHER, f"unknown_modifier/{unknown[0]}"))
    else:
        # Bare `field: value` is an equality match. Track numeric-valued
        # equality separately: it is a lookup on a numeric field, not
        # arithmetic, but it is the one call a reader may want to audit.
        numeric_valued = _is_numeric_value(value)
        subtype = "match/equality_numeric_value" if numeric_valued else "match/equality"
        ops.append((MATCH, subtype))

    return ops


def _is_numeric_value(value):
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, list) and value:
        return all(
            isinstance(v, (int, float)) and not isinstance(v, bool) for v in value
        )
    return False


def classify_search(node, ops):
    """Walk one search identifier's value and collect its operations."""
    if isinstance(node, dict):
        for key, value in node.items():
            ops.extend(classify_predicate(key, value))
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, dict):
                classify_search(item, ops)
            else:
                # A bare keyword list is a full-text search over the event:
                # one unstructured lookup, not one per keyword.
                ops.append((MATCH, "match/keyword"))
                return
    elif node is not None:
        ops.append((MATCH, "match/keyword"))


def classify_condition(condition, ops):
    """Collect operations declared by a condition expression."""
    if isinstance(condition, list):
        for item in condition:
            classify_condition(item, ops)
        return
    if not isinstance(condition, str):
        return

    search_part, _, agg_part = condition.partition("|")

    for _ in BOOL_RE.findall(search_part):
        ops.append((OTHER, "boolean_logic"))
    for _ in QUANTIFIER_RE.findall(search_part):
        ops.append((OTHER, "boolean_quantifier"))

    if not agg_part:
        return

    for func in AGG_FUNC_RE.findall(agg_part):
        ops.append((NUMERIC, f"aggregate/{func.lower()}"))
    for _ in AGG_BY_RE.findall(agg_part):
        # A group-by key is a join: events are grouped on a shared value.
        ops.append((MATCH, "join/group_by"))
    for _ in THRESHOLD_RE.findall(agg_part):
        ops.append((NUMERIC, "aggregate/threshold"))
    for _ in NEAR_RE.findall(agg_part):
        ops.append((MATCH, "join/temporal_correlation"))


def slice_of(logsource, path):
    """Assign a rule to the reported slices. A rule may match none."""
    category = (logsource.get("category") or "").lower()
    product = (logsource.get("product") or "").lower()
    service = (logsource.get("service") or "").lower()
    parts = {p.lower() for p in path.parts}

    slices = []
    if category == "process_creation":
        slices.append("process_creation")
    if category in NETWORK_CATEGORIES or "network" in parts:
        slices.append("network")
    if product in CLOUD_PRODUCTS or "cloud" in parts or service in CLOUD_PRODUCTS:
        slices.append("cloud")
    return slices


def analyse_rule(path):
    try:
        docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
    except Exception as exc:  # noqa: BLE001 - corpus files are third-party
        return None, f"{path}: {exc}"

    if not docs:
        return None, f"{path}: empty"

    rule = docs[0]
    if not isinstance(rule, dict) or "detection" not in rule:
        return None, f"{path}: no detection section"

    detection = rule["detection"]
    if not isinstance(detection, dict):
        return None, f"{path}: detection is not a map"

    ops = []
    for key, value in detection.items():
        if key == "condition":
            continue
        if key == "timeframe":
            # A time window is the aggregation's numeric bound.
            ops.append((NUMERIC, "aggregate/timeframe"))
            continue
        classify_search(value, ops)

    classify_condition(detection.get("condition"), ops)

    # Sensitivity denominator: count every literal value rather than every
    # predicate, to show the result does not depend on that choice.
    value_ops = count_value_level(detection)

    logsource = rule.get("logsource") or {}
    if not isinstance(logsource, dict):
        logsource = {}

    return {
        "path": str(path),
        "ops": ops,
        "value_level": value_ops,
        "slices": slice_of(logsource, path),
    }, None


def count_value_level(detection):
    """Per-literal-value counts, used only as a sensitivity check."""
    counts = Counter()
    for key, value in detection.items():
        if key in ("condition", "timeframe"):
            continue
        for bucket, n in _walk_values(key, value):
            counts[bucket] += n
    return dict(counts)


def _walk_values(key, node):
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            out.extend(_walk_values(k, v))
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, dict):
                out.extend(_walk_values(key, item))
            else:
                out.append((_bucket_for(key, item), 1))
    else:
        out.append((_bucket_for(key, node), 1))
    return out


def _bucket_for(key, value):
    ops = classify_predicate(key, value)
    for bucket, _ in ops:
        if bucket != OTHER:
            return bucket
    return OTHER


def summarise(records):
    buckets = Counter()
    subtypes = Counter()
    value_level = Counter()
    for rec in records:
        for bucket, subtype in rec["ops"]:
            buckets[bucket] += 1
            subtypes[subtype] += 1
        for bucket, n in rec["value_level"].items():
            value_level[bucket] += n

    classified = buckets[MATCH] + buckets[NUMERIC]
    return {
        "rules": len(records),
        "operations_total": sum(buckets.values()),
        "match": buckets[MATCH],
        "numeric": buckets[NUMERIC],
        "other": buckets[OTHER],
        "classified_denominator": classified,
        "match_pct": _pct(buckets[MATCH], classified),
        "numeric_pct": _pct(buckets[NUMERIC], classified),
        "subtypes": dict(subtypes.most_common()),
        "value_level": {
            "match": value_level[MATCH],
            "numeric": value_level[NUMERIC],
            "other": value_level[OTHER],
            "match_pct": _pct(value_level[MATCH], value_level[MATCH] + value_level[NUMERIC]),
            "numeric_pct": _pct(value_level[NUMERIC], value_level[MATCH] + value_level[NUMERIC]),
        },
    }


def _pct(n, denominator):
    return round(100.0 * n / denominator, 4) if denominator else None


def _slice_summaries(records):
    """Summarise the reported slices over one corpus."""
    by_slice = defaultdict(list)
    for rec in records:
        for name in rec["slices"]:
            by_slice[name].append(rec)
    return {
        name: summarise(by_slice.get(name, []))
        for name in ("process_creation", "network", "cloud")
    }


def collect(corpus, dirs):
    records, errors = [], []
    for d in dirs:
        root = corpus / d
        if not root.is_dir():
            errors.append(f"missing corpus directory: {root}")
            continue
        for path in sorted(root.rglob("*.yml")):
            rec, err = analyse_rule(path)
            if err:
                errors.append(err)
            else:
                rec["path"] = str(path.relative_to(corpus))
                records.append(rec)
    return records, errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, type=Path,
                    help="path to a SigmaHQ/sigma checkout")
    ap.add_argument("--json", type=Path, help="write the full result as JSON")
    args = ap.parse_args()

    supported_dirs = [
        "rules", "rules-compliance", "rules-dfir", "rules-emerging-threats",
        "rules-threat-hunting",
    ]

    supported, errors = collect(args.corpus, supported_dirs)
    unsupported, unsup_errors = collect(args.corpus, ["unsupported"])

    result = {
        "corpus": str(args.corpus),
        "supported": summarise(supported),
        "unsupported": summarise(unsupported),
        "slices": _slice_summaries(supported),
        "unsupported_slices": _slice_summaries(unsupported),
        "errors": errors + unsup_errors,
    }

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
