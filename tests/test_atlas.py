import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _categories():
    rows = [json.loads(l) for l in (ROOT / "corpus/adversarial.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    return {r["category"] for r in rows if r["label"] == "adversarial"}


def _mapping():
    out = {}
    for line in (ROOT / "ATLAS.md").read_text(encoding="utf-8").splitlines():
        m = re.match(r"\|\s*`([a-z_]+)`\s*\|\s*([^|]+?)\s*\|", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def test_every_corpus_category_is_mapped():
    cats = _categories()
    assert cats, "corpus has no adversarial categories"
    mapping = _mapping()
    assert not (cats - set(mapping)), sorted(cats - set(mapping))


def test_mapping_values_are_atlas_ids_or_explicit_none():
    for cat, value in _mapping().items():
        ids = [v.strip() for v in value.split(",")]
        assert all(re.fullmatch(r"AML\.T\d{4}(\.\d{3})?", i) for i in ids) or value == "no direct ATLAS technique", (cat, value)
