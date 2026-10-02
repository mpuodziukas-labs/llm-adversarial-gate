"""
evaluate.py — Run the adversarial corpus through the gate and report metrics.

Usage:
    python3 evaluate.py                         # default corpus
    python3 evaluate.py --corpus path/to.jsonl  # custom corpus
    python3 evaluate.py --verbose               # show per-record results
    python3 evaluate.py --category jailbreak    # filter to one category

Output: confusion matrix, block/FP/FN rates, per-category breakdown.
Exit 0 only if there is no unexpected false negative or false positive;
records marked known_gap are reported but do not fail the run.

Definitions:
    True Positive  (TP): adversarial prompt correctly BLOCKED
    True Negative  (TN): benign prompt correctly ALLOWED
    False Negative (FN): adversarial prompt incorrectly ALLOWED  ← most dangerous
    False Positive (FP): benign prompt incorrectly BLOCKED

Deterministic: no randomness, no external calls. Results are reproducible.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Optional

from gate import evaluate as gate_evaluate, Verdict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_corpus(path: pathlib.Path, category_filter: Optional[str] = None) -> list[dict]:
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if category_filter and rec["category"] != category_filter:
                continue
            records.append(rec)
    return records


def classify(record: dict) -> tuple[str, object]:
    """
    Returns (outcome, gate_result) where outcome is one of:
        TP, TN, FP, FN
    """
    result = gate_evaluate(record["prompt"])
    label = record["label"]  # "adversarial" | "benign"
    blocked = result.blocked

    if label == "adversarial" and blocked:
        outcome = "TP"
    elif label == "benign" and not blocked:
        outcome = "TN"
    elif label == "adversarial" and not blocked:
        outcome = "FN"
    else:  # label == "benign" and blocked
        outcome = "FP"

    return outcome, result


# ---------------------------------------------------------------------------
# Confusion matrix / stats
# ---------------------------------------------------------------------------

def compute_metrics(counts: dict[str, int]) -> dict[str, float]:
    tp = counts.get("TP", 0)
    tn = counts.get("TN", 0)
    fp = counts.get("FP", 0)
    fn = counts.get("FN", 0)
    total = tp + tn + fp + fn
    adversarial_total = tp + fn
    benign_total = tn + fp

    metrics = {
        "total": total,
        "adversarial_total": adversarial_total,
        "benign_total": benign_total,
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "block_rate":         round(tp / adversarial_total, 4) if adversarial_total else 0.0,
        "false_negative_rate": round(fn / adversarial_total, 4) if adversarial_total else 0.0,
        "false_positive_rate": round(fp / benign_total, 4)      if benign_total      else 0.0,
        "accuracy":           round((tp + tn) / total, 4)       if total             else 0.0,
        "precision":          round(tp / (tp + fp), 4)          if (tp + fp)         else 0.0,
        "recall":             round(tp / (tp + fn), 4)          if (tp + fn)         else 0.0,
    }
    if metrics["precision"] + metrics["recall"] > 0:
        metrics["f1"] = round(
            2 * metrics["precision"] * metrics["recall"]
            / (metrics["precision"] + metrics["recall"]), 4
        )
    else:
        metrics["f1"] = 0.0
    return metrics


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

SEPARATOR = "=" * 70

def print_confusion_matrix(counts: dict[str, int]):
    tp = counts.get("TP", 0)
    tn = counts.get("TN", 0)
    fp = counts.get("FP", 0)
    fn = counts.get("FN", 0)
    print()
    print("Confusion Matrix:")
    print("                   Predicted BLOCK   Predicted ALLOW")
    print(f"  Actual Adversarial    TP={tp:<6}        FN={fn:<6}   (↑ FN = miss)")
    print(f"  Actual Benign         FP={fp:<6}        TN={tn:<6}   (↑ FP = false alarm)")
    print()


def print_metrics(m: dict[str, float], label: str = "Overall"):
    print(f"{label} Metrics  (adversarial={m['adversarial_total']}, benign={m['benign_total']}, total={m['total']})")
    print(f"  Block rate (recall):       {m['block_rate']:.1%}   [{m['TP']} / {m['adversarial_total']} adversarial caught]")
    print(f"  False-negative rate:       {m['false_negative_rate']:.1%}   [{m['FN']} adversarial missed]")
    print(f"  False-positive rate:       {m['false_positive_rate']:.1%}   [{m['FP']} benign over-blocked]")
    print(f"  Accuracy:                  {m['accuracy']:.1%}")
    print(f"  Precision:                 {m['precision']:.1%}")
    print(f"  F1:                        {m['f1']:.4f}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Evaluate LLM adversarial gate on corpus")
    parser.add_argument(
        "--corpus",
        default=str(pathlib.Path(__file__).parent / "corpus" / "adversarial.jsonl"),
        help="Path to JSONL corpus file",
    )
    parser.add_argument("--verbose", action="store_true", help="Print per-record results")
    parser.add_argument("--category", default=None, help="Filter to a single category")
    args = parser.parse_args()

    corpus_path = pathlib.Path(args.corpus)
    if not corpus_path.exists():
        print(f"ERROR: corpus not found at {corpus_path}", file=sys.stderr)
        print("Run:  python3 build_corpus.py", file=sys.stderr)
        sys.exit(1)

    records = load_corpus(corpus_path, category_filter=args.category)
    if not records:
        print("No records loaded (check --category filter).", file=sys.stderr)
        sys.exit(1)

    # --- Run gate over corpus ------------------------------------------------
    results = []
    counts: dict[str, int] = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    per_category: dict[str, dict[str, int]] = {}

    for rec in records:
        outcome, gate_result = classify(rec)
        counts[outcome] += 1

        cat = rec["category"]
        if cat not in per_category:
            per_category[cat] = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
        per_category[cat][outcome] += 1

        results.append({
            "id": rec["id"],
            "label": rec["label"],
            "category": cat,
            "outcome": outcome,
            "verdict": gate_result.verdict.value,
            "score": gate_result.score,
            "primary_reason": gate_result.primary_reason,
            "prompt_snippet": rec["prompt"][:80],
        })

    # --- Print report --------------------------------------------------------
    print(SEPARATOR)
    print("LLM ADVERSARIAL GATE — EVALUATION REPORT")
    print(f"Corpus: {corpus_path}")
    print(SEPARATOR)

    print_confusion_matrix(counts)
    overall = compute_metrics(counts)
    print_metrics(overall)

    print()
    print(SEPARATOR)
    print("Per-Category Breakdown:")
    print(SEPARATOR)
    for cat in sorted(per_category.keys()):
        cat_counts = per_category[cat]
        cat_m = compute_metrics(cat_counts)
        print()
        print_metrics(cat_m, label=f"  [{cat}]")

    # --- Verbose: show misses ------------------------------------------------
    fn_records = [r for r in results if r["outcome"] == "FN"]
    fp_records = [r for r in results if r["outcome"] == "FP"]

    if fn_records or fp_records:
        print()
        print(SEPARATOR)
        print("Misclassifications:")
        print(SEPARATOR)

    if fn_records:
        print(f"\nFalse Negatives (adversarial missed — {len(fn_records)} total):")
        for r in fn_records:
            print(f"  [{r['id']}] [{r['category']}] score={r['score']:.3f}")
            print(f"    Prompt: {r['prompt_snippet']!r}")

    if fp_records:
        print(f"\nFalse Positives (benign over-blocked — {len(fp_records)} total):")
        for r in fp_records:
            print(f"  [{r['id']}] [{r['category']}] score={r['score']:.3f}  reason: {r['primary_reason']}")
            print(f"    Prompt: {r['prompt_snippet']!r}")

    if args.verbose:
        print()
        print(SEPARATOR)
        print("All Records:")
        print(SEPARATOR)
        for r in results:
            flag = "" if r["outcome"] in ("TP", "TN") else " *** MISS ***"
            print(
                f"  {r['id']:8s} {r['outcome']:2s} {r['verdict']:5s} "
                f"score={r['score']:.3f} [{r['category']}]{flag}"
            )
            if r["primary_reason"]:
                print(f"           reason: {r['primary_reason']}")

    # --- Exit code ------------------------------------------------------------
    # Records marked known_gap are documented limitations: they stay in the
    # headline numbers above, but do not fail the run. A known_gap record the
    # gate now handles correctly is STALE and fails the run, so the label (and
    # the README Limitations entry) cannot outlive the gap.
    gap_ids = {r["id"] for r in records if r.get("known_gap")}
    fn_new = [r for r in fn_records if r["id"] not in gap_ids]
    fp_new = [r for r in fp_records if r["id"] not in gap_ids]
    fn_gap = [r for r in fn_records if r["id"] in gap_ids]
    fp_gap = [r for r in fp_records if r["id"] in gap_ids]
    stale = [r for r in results if r["id"] in gap_ids and r["outcome"] in ("TP", "TN")]

    print()
    print(SEPARATOR)
    print(f"Known gaps (documented, counted above): {len(fn_gap)} missed attacks, "
          f"{len(fp_gap)} false positives")
    for r in fn_gap + fp_gap:
        print(f"  [{r['id']}] {r['outcome']} {r['prompt_snippet']!r}")
    if stale:
        print(f"STALE known_gap labels ({len(stale)}): gate now handles these correctly; "
              "remove the label and update the README Limitations")
        for r in stale:
            print(f"  [{r['id']}] {r['prompt_snippet']!r}")
    print(SEPARATOR)
    ok = not fn_new and not fp_new and not stale
    if ok:
        print("RESULT: PASS - no unexpected false negatives or false positives "
              f"({len(fn_gap) + len(fp_gap)} documented known gaps)")
    else:
        print(f"RESULT: FAIL - {len(fn_new)} unexpected miss(es), {len(fp_new)} unexpected "
              f"false positive(s), {len(stale)} stale known_gap label(s)")
    print(SEPARATOR)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
