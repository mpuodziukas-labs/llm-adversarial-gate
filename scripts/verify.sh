#!/usr/bin/env bash
# Runs evaluate.py and asserts the published numbers appear in its output.
# Usage: bash scripts/verify.sh [--selftest]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Published numbers (README, Results on Bundled Corpus).
EXPECTED=(
  "total=284"
  "TP=171"
  "FN=6"
  "FP=4"
  "TN=103"
  "[171 / 177 adversarial caught]"
  "[6 adversarial missed]"
  "[4 benign over-blocked]"
  "RESULT: PASS"
)

# check_root DIR: prints GREEN or RED with each mismatch; returns 0 or 1.
check_root() {
  local dir="$1" out rc=0 bad=0 want
  out="$(cd "$dir" && python3 evaluate.py 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "RED: evaluate.py exited $rc"
    bad=1
  fi
  if [ -z "$out" ]; then
    echo "RED: evaluate.py produced no output"
    return 1
  fi
  for want in "${EXPECTED[@]}"; do
    if ! grep -qF -- "$want" <<<"$out"; then
      echo "RED: expected '$want' not found in evaluate.py output"
      bad=1
    fi
  done
  if [ "$bad" -ne 0 ]; then
    return 1
  fi
  echo "GREEN: ${#EXPECTED[@]}/${#EXPECTED[@]} published values match"
  return 0
}

TMP_DIR=""

selftest() {
  local pass=0 total=3 rc d tmp
  tmp="$(mktemp -d)"
  TMP_DIR="$tmp"
  trap 'rm -rf "${TMP_DIR:?}"' EXIT

  for d in clean label gate; do
    mkdir "$tmp/$d"
    (cd "$ROOT" && tar --exclude=.git --exclude=__pycache__ --exclude=.pytest_cache -cf - .) | (cd "$tmp/$d" && tar -xf -)
  done

  # Defect 1: flip one adversarial label to benign in the corpus.
  awk '!done && sub(/"label": "adversarial"/, "\"label\": \"benign\"") { done = 1 } { print }' "$tmp/clean/corpus/adversarial.jsonl" >"$tmp/label/corpus/adversarial.jsonl"
  if cmp -s "$tmp/clean/corpus/adversarial.jsonl" "$tmp/label/corpus/adversarial.jsonl"; then
    echo "selftest: label defect was not planted" >&2
    return 1
  fi

  # Defect 2: raise the block threshold so nothing blocks.
  sed 's/^BLOCK_THRESHOLD = 1\.0$/BLOCK_THRESHOLD = 99.0/' "$tmp/clean/gate.py" >"$tmp/gate/gate.py"
  if cmp -s "$tmp/clean/gate.py" "$tmp/gate/gate.py"; then
    echo "selftest: gate defect was not planted" >&2
    return 1
  fi

  rc=0; check_root "$tmp/label" >/dev/null || rc=$?
  if [ "$rc" -eq 1 ]; then pass=$((pass + 1)); echo "ok 1 flipped label is RED"; else echo "not ok 1 flipped label (rc=$rc)"; fi

  rc=0; check_root "$tmp/gate" >/dev/null || rc=$?
  if [ "$rc" -eq 1 ]; then pass=$((pass + 1)); echo "ok 2 weakened gate is RED"; else echo "not ok 2 weakened gate (rc=$rc)"; fi

  rc=0; check_root "$tmp/clean" >/dev/null || rc=$?
  if [ "$rc" -eq 0 ]; then pass=$((pass + 1)); echo "ok 3 clean copy is GREEN"; else echo "not ok 3 clean copy (rc=$rc)"; fi

  echo "selftest $pass/$total"
  [ "$pass" -eq "$total" ]
}

case "${1:-}" in
  "") check_root "$ROOT" ;;
  --selftest) selftest ;;
  *) echo "usage: bash scripts/verify.sh [--selftest]" >&2; exit 2 ;;
esac
