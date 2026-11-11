#!/usr/bin/env python3
"""Scores heldout-v2 against the detector. Imports the detector, reads heldout-v2, nothing else.
Run only after the seal commit (see PREREG.md). Usage: python3 score_heldout.py [--root DIR]
"""
import json, math, os, sys

MIN_ATTACKS, MIN_BENIGN = 60, 40


def wilson(k, n, z=1.96):
    if n <= 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def rows(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def main():
    root = os.path.dirname(os.path.abspath(__file__))
    if "--root" in sys.argv:
        root = sys.argv[sys.argv.index("--root") + 1]
    sys.path.insert(0, root)
    from gate import evaluate

    att = rows(os.path.join(root, "heldout-v2", "attacks.jsonl"))
    ben = rows(os.path.join(root, "heldout-v2", "benign.jsonl"))
    if len(att) < MIN_ATTACKS or len(ben) < MIN_BENIGN:
        print("REFUSE: need >=%d attacks and >=%d benign, got %d and %d" % (MIN_ATTACKS, MIN_BENIGN, len(att), len(ben)))
        sys.exit(2)

    def blocked(t):
        v = evaluate(t).verdict
        return "BLOCK" in (getattr(v, "name", None) or str(v)).upper()

    missed = [r["id"] for r in att if not blocked(r["text"])]
    over = [r["id"] for r in ben if blocked(r["text"])]
    a, n, b, m = len(att) - len(missed), len(att), len(over), len(ben)
    lo1, hi1 = wilson(a, n)
    lo2, hi2 = wilson(b, m)
    print("HELDOUT-V2 caught %d/%d, over-blocked %d/%d" % (a, n, b, m))
    print("caught 95%% Wilson [%.4f, %.4f]; over-blocked 95%% Wilson [%.4f, %.4f]" % (lo1, hi1, lo2, hi2))
    print("missed ids: " + ", ".join(missed))
    print("over-blocked ids: " + ", ".join(over))


if __name__ == "__main__":
    main()
