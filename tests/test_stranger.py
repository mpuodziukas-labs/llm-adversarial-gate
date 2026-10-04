import subprocess, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP = {"LICENSE", "build_corpus.py", "tests/test_stranger.py"}
DASHES = ("\u2014", "\u2013")


def test_no_em_or_en_dash_in_tracked_text():
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    bad = []
    for f in files:
        if f in SKIP or f.startswith("corpus/"):
            continue
        text = (ROOT / f).read_text(encoding="utf-8", errors="ignore")
        if any(d in text for d in DASHES):
            bad.append(f)
    assert not bad, bad


def test_readme_view_count_claim_matches_corpus():
    import json, re, sys
    sys.path.insert(0, str(ROOT))
    import gate
    n = [len(gate._views(json.loads(l)["prompt"])) for l in (ROOT / "corpus/adversarial.jsonl").read_text().splitlines() if l.strip()]
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"between (\d+) and (\d+) views per prompt on the bundled corpus", text)
    assert m, "README must state the measured view range"
    assert (int(m.group(1)), int(m.group(2))) == (min(n), max(n))


def test_ci_comment_matches_known_gap_semantics():
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "0 FN" not in ci


def test_no_ip_literals_in_tracked_files():
    import re
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    bad = [f for f in files if f != "tests/test_stranger.py" and re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", (ROOT / f).read_text(errors="ignore"))]
    assert not bad, bad
