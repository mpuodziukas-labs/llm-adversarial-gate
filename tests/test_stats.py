"""stats.py: interval math is checked against known values; the report parser against a fixed evaluate.py excerpt."""
import stats

REPORT = """Confusion Matrix:
  Actual Adversarial    TP=171           FN=6        (x)
  Actual Benign         FP=4             TN=103      (x)
  [benign] Metrics  (adversarial=0, benign=107, total=107)
  False-positive rate:       3.7%   [4 benign over-blocked]
  [jailbreak] Metrics  (adversarial=41, benign=0, total=41)
  Block rate (recall):       100.0%   [41 / 41 adversarial caught]
"""


def test_wilson_known_values():
    lo, hi = stats.wilson(171, 177)
    assert (round(lo, 4), round(hi, 4)) == (0.928, 0.9844)
    lo, hi = stats.wilson(0, 10)
    assert lo == 0.0 and round(hi, 4) == 0.2775


def test_wilson_rejects_bad_counts():
    for k, n in [(-1, 5), (6, 5), (1, 0)]:
        try:
            stats.wilson(k, n)
        except ValueError:
            continue
        raise AssertionError(f"wilson({k},{n}) accepted")


def test_parse_confusion_and_categories():
    c = stats.parse(REPORT)
    assert (c["tp"], c["fn"], c["fp"], c["tn"]) == (171, 6, 4, 103)
    assert c["cats"] == {"jailbreak": (41, 41)}


def test_parse_refuses_missing_matrix():
    try:
        stats.parse("no matrix here")
    except ValueError:
        return
    raise AssertionError("parse accepted a report with no confusion matrix")


def test_benign_needed_bounds_fpr():
    n = stats.benign_needed(4 / 107, 0.05)
    assert stats.wilson(round(n * 4 / 107), n)[1] < 0.05
    assert n > 107
