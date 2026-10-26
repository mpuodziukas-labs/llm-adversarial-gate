"""Mutation check: remove each defense in a scratch copy, the matching tests must go RED.
A control copy must pass first. A mutant that hangs past 8 s counts as killed.
Usage: python3 mutants.py [repo_dir]   (default: the directory holding this file)"""
import pathlib, shutil, subprocess, sys, tempfile
ROOT = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parent
T = "tests/test_gate.py"
H = "tests/test_hostile.py"
R = "tests/test_redteam.py"
S = "tests/test_stats.py"
G = "gate.py"
# (name, file, text to remove, text to put in, test file that must fail)
MUTANTS = [
    ("threshold: the block score raised tenfold", G, "BLOCK_THRESHOLD = 1.0", "BLOCK_THRESHOLD = 10.0", T),
    ("threshold: a score equal to the threshold passes", G, "total_score >= BLOCK_THRESHOLD", "total_score > BLOCK_THRESHOLD", T),
    ("fail closed: a non-string input is scored", G, "    if not isinstance(prompt, str):", "    if False:", H),
    ("fail closed: oversize input is scored", G, "    if len(prompt) > MAX_INPUT_CHARS:", "    if False:", H),
    ("fail closed: the size cap raised tenfold", G, "MAX_INPUT_CHARS = 100_000", "MAX_INPUT_CHARS = 1_000_000", H),
    ("fail closed: the error verdict is ALLOW", G, "        verdict=Verdict.BLOCK,\n        score=BLOCK_THRESHOLD,", "        verdict=Verdict.ALLOW,\n        score=BLOCK_THRESHOLD,", H),
    ("fold: look-alike letters are not mapped", G, "_HOMOGLYPHS.update(_build_confusables())", "pass", H),
    ("fold: compatibility forms are not normalised", G, 't = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", text))', "t = text", R),
    ("fold: invisible fillers do not split words", G, 'elif c in _FILLERS_CH or cat == "Cf":', "elif False:", H),
    ("fold: combining marks are kept", G, "        elif cat in _DROP_CATEGORIES:\n            continue", "        elif False:\n            continue", R),
    ("decode: percent encoding is not undone", G, '    if "%" in norm:', "    if False:", R),
    ("decode: HTML entities are not undone", G, '    if "&" in norm:', "    if False:", H),
    ("decode: base64 is not decoded", G, "    out.extend(_b64_variants(norm))", "    pass", H),
    ("decode: rot13 is not tried", G, '    out.append(codecs.encode(norm, "rot13"))', '    out.append("")', R),
    ("decode: reversed text is not tried", G, "    out.append(norm[::-1])", '    out.append("")', R),
    ("decode: hidden tag characters are ignored", G, "    if tags:", "    if False:", R),
    ("rule: filler words after ignore are not matched", G, r"(?:\w+\s+){0,5}?(?:previous|prior", r"(?:\w+\s+){0,0}?(?:previous|prior", T),
    ("rule: asking for the system prompt is not flagged", G, r'r"\b(show|print|reveal|output|tell\s+me|repeat|display)\s+"', r'r"\b(show|print)\s+"', R),
    ("cli: a blocked prompt exits 0", G, "sys.exit(0 if result.verdict == Verdict.ALLOW else 1)", "sys.exit(0)", R),
    ("cli: a missing prompt exits 0", G, "        sys.exit(2)", "        sys.exit(0)", R),
    ("stats: impossible counts are accepted", "stats.py", "    if n <= 0 or k < 0 or k > n:", "    if False:", S),
    ("stats: a missing confusion matrix is accepted", "stats.py", "    if not all(m.values()):", "    if False:", S),
    ("stats: the interval width is cut", "stats.py", "Z95 = 1.959964", "Z95 = 1.0", S),
]


def pytest_rc(tree, test):
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", test],
                           cwd=tree, capture_output=True, timeout=8,
                           env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"})
    except subprocess.TimeoutExpired:
        return 124                                      # a mutant that hangs the tests is caught
    return r.returncode


def fresh(tmp, name):
    dst = pathlib.Path(tmp) / name
    shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    return dst


def main():
    killed = 0
    tests = sorted({m[4] for m in MUTANTS})
    with tempfile.TemporaryDirectory() as tmp:
        for t in tests:
            if pytest_rc(fresh(tmp, "control-" + pathlib.Path(t).stem), t) != 0:
                print(f"control FAIL {t}"); return 1
        print(f"control {len(tests)}/{len(tests)} test files pass unmodified")
        for i, (name, f, old, new, test) in enumerate(MUTANTS):
            tree = fresh(tmp, f"m{i}")
            src = (tree / f).read_text()
            if src.count(old) != 1:
                print(f"mutant {name}: pattern matched {src.count(old)} times, want 1"); return 1
            (tree / f).write_text(src.replace(old, new))
            red = pytest_rc(tree, test) != 0
            killed += red
            print(f"{'RED ' if red else 'LIVE'} {name}")
    print(f"mutants killed {killed}/{len(MUTANTS)}")
    return 0 if killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
