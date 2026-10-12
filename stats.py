"""Interval and stability report for evaluate.py.

Point rates on a 284-prompt corpus hide how wide the uncertainty is. This prints
Wilson 95% intervals for every rate, checks that reruns are byte-identical (so any
change in output is a regression, never noise), and the benign corpus size needed
before the false-positive rate could be bounded under 5%.

Usage: python3 stats.py [--runs N]
"""
import hashlib
import math
import re
import subprocess
import sys

Z95 = 1.959964


def wilson(k, n, z=Z95):
    if n <= 0 or k < 0 or k > n:
        raise ValueError(f"bad counts k={k} n={n}")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def parse(text):
    m = {k: re.search(rf"\b{k.upper()}=(\d+)", text) for k in ("tp", "fn", "fp", "tn")}
    if not all(m.values()):
        raise ValueError("no confusion matrix in evaluate.py output")
    out = {k: int(v.group(1)) for k, v in m.items()}
    cats, cur = {}, None
    for line in text.splitlines():
        h = re.match(r"\s*\[(\w+)\] Metrics\s+\(adversarial=(\d+)", line)
        if h:
            cur = h.group(1) if int(h.group(2)) > 0 else None
            continue
        r = re.search(r"\[(\d+) / (\d+) adversarial caught\]", line)
        if cur and r:
            cats[cur] = (int(r.group(1)), int(r.group(2)))
            cur = None
    out["cats"] = cats
    return out


def benign_needed(rate, bound, z=Z95):
    """Smallest benign count n at which the observed rate's Wilson upper bound is under `bound`."""
    if not 0 <= rate < bound:
        raise ValueError("observed rate must be under the bound")
    n = 1
    while wilson(round(n * rate), n, z)[1] >= bound:
        n += 1
    return n


def pct(x):
    return f"{100 * x:.1f}%"


def main(argv):
    runs = int(argv[argv.index("--runs") + 1]) if "--runs" in argv else 3
    outs = []
    for _ in range(runs):
        p = subprocess.run([sys.executable, "evaluate.py"], capture_output=True, text=True)
        outs.append(p.stdout)
    shas = {hashlib.sha256(o.encode()).hexdigest()[:16] for o in outs}
    c = parse(outs[0])
    adv, ben = c["tp"] + c["fn"], c["fp"] + c["tn"]
    rows = [("recall", c["tp"], adv), ("false-negative rate", c["fn"], adv), ("false-positive rate", c["fp"], ben)]
    print("rate                      k / n       point   Wilson 95% CI")
    for name, k, n in rows:
        lo, hi = wilson(k, n)
        print(f"{name:<25} {k:>3} / {n:<4}  {pct(k / n):>6}   {pct(lo)} - {pct(hi)}")
    for cat, (k, n) in sorted(c["cats"].items()):
        lo, hi = wilson(k, n)
        print(f"{'recall ' + cat:<25} {k:>3} / {n:<4}  {pct(k / n):>6}   {pct(lo)} - {pct(hi)}")
    print(f"reruns: {runs}, distinct output hashes: {len(shas)}")
    need = benign_needed(c["fp"] / ben, 0.05)
    print(f"benign prompts needed to bound the observed false-positive rate under 5%: {need} (have {ben})")
    if len(shas) != 1:
        print("RED: evaluate.py output differs across reruns")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
