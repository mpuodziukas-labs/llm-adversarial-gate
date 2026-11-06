#!/usr/bin/env bash
# Verifies the TypeScript port end to end: npm ci, typecheck, unit tests (including
# parity with the Python gate), then Playwright API tests against a real server on an
# ephemeral port.
# Usage: bash scripts/verify-ts.sh [--selftest]
#   --selftest  plants defects in a temp copy and requires each one to fail the checks.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SERVER_PID=""
TMP_DIR=""

cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
  if [ -n "$TMP_DIR" ]; then
    rm -rf "${TMP_DIR:?}"
  fi
}
trap cleanup EXIT

# run_checks TSDIR LOG: typecheck, unit tests, build, API tests. Returns nonzero on the
# first failure. Writes a one-line summary to $LOG.summary on success.
run_checks() {
  local ts="$1" log="$2" port="" unit api parity
  (cd "$ts" && npx --no-install tsc --noEmit) >"$log.tsc" 2>&1 || { echo "FAIL: tsc"; return 1; }
  (cd "$ts" && npx --no-install vitest run --silent=false) >"$log.unit" 2>&1 || { echo "FAIL: unit tests"; return 1; }
  (cd "$ts" && npx --no-install tsc -p tsconfig.build.json) >"$log.build" 2>&1 || { echo "FAIL: build"; return 1; }

  (cd "$ts" && PORT=0 HOST=localhost node dist/main.js) >"$log.server" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 100); do
    port="$(sed -n 's/^LISTENING localhost:\([0-9][0-9]*\)$/\1/p' "$log.server" | head -n 1)"
    [ -n "$port" ] && break
    kill -0 "$SERVER_PID" 2>/dev/null || { echo "FAIL: server exited at start"; return 1; }
    sleep 0.1
  done
  if [ -z "$port" ]; then
    echo "FAIL: server never reported a port"
    return 1
  fi

  local rc=0
  (cd "$ts" && API_BASE_URL="http://localhost:$port" npx --no-install playwright test) >"$log.api" 2>&1 || rc=$?
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
  [ "$rc" -eq 0 ] || { echo "FAIL: API tests"; return 1; }

  unit="$(sed -n 's/^ *Tests  *\([0-9][0-9]*\) passed.*/\1/p' "$log.unit" | head -n 1)"
  api="$(sed -n 's/^ *\([0-9][0-9]*\) passed.*/\1/p' "$log.api" | tail -n 1)"
  parity="$(grep -h '^PARITY ' "$log.unit" | sed 's/^PARITY //' | paste -sd ';' - | sed 's/;/; /g')"
  if [ -z "$unit" ] || [ -z "$api" ] || [ -z "$parity" ]; then
    echo "FAIL: could not read test counts (unit='$unit' api='$api' parity='$parity')"
    return 1
  fi
  printf '%s unit tests, %s API tests; %s\n' "$unit" "$api" "$parity" >"$log.summary"
  return 0
}

install_deps() {
  (cd "$ROOT/ts" && npm ci --no-audit --no-fund) >/dev/null
}

selftest() {
  local pass=0 total=0 rc tmp
  tmp="$(mktemp -d)"
  TMP_DIR="$tmp"
  [ -d "$ROOT/ts/node_modules" ] || install_deps

  # mutate NAME FILE OLD NEW: copy the repo, replace OLD with NEW in FILE (it must be
  # present exactly once), and require the checks to fail.
  mutate() {
    local label="$1" file="$2" old="$3" new="$4" dir="$tmp/$1"
    mkdir "$dir"
    (cd "$ROOT" && tar --exclude=.git --exclude=__pycache__ --exclude=.pytest_cache \
      --exclude=node_modules --exclude=dist -cf - .) | (cd "$dir" && tar -xf -)
    ln -s "$ROOT/ts/node_modules" "$dir/ts/node_modules"
    OLD="$old" NEW="$new" FILE="$dir/ts/$file" python3 - <<'PY'
import os, sys
p, old, new = os.environ["FILE"], os.environ["OLD"], os.environ["NEW"]
s = open(p, encoding="utf-8").read()
if s.count(old) != 1:
    sys.exit("selftest setup error: %r found %d times in %s" % (old, s.count(old), p))
open(p, "w", encoding="utf-8").write(s.replace(old, new))
PY
    total=$((total + 1))
    rc=0
    run_checks "$dir/ts" "$dir/log" >"$dir/out" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
      pass=$((pass + 1))
      echo "caught  $label ($(head -n 1 "$dir/out"))"
    else
      echo "MISSED  $label: checks passed on a planted defect"
    fi
  }

  # Control: an untouched copy must pass, or the "caught" results prove nothing.
  mkdir "$tmp/control"
  (cd "$ROOT" && tar --exclude=.git --exclude=__pycache__ --exclude=.pytest_cache \
    --exclude=node_modules --exclude=dist -cf - .) | (cd "$tmp/control" && tar -xf -)
  ln -s "$ROOT/ts/node_modules" "$tmp/control/ts/node_modules"
  rc=0
  run_checks "$tmp/control/ts" "$tmp/control/log" >"$tmp/control/out" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    cat "$tmp/control/out"
    echo "selftest ABORT: the untouched control copy failed"
    return 1
  fi
  echo "control passes"

  mutate drop-rule src/rules.ts '  rule(
    "PI-001",' '  rule(
    "PI-001-DROPPED-PLACEHOLDER",'
  mutate break-nfkc src/gate.ts 'text.normalize("NFKC").normalize("NFKD")' 'text.normalize("NFD")'
  mutate invert-decision src/gate.ts 'total >= BLOCK_THRESHOLD ? "BLOCK" : "ALLOW"' 'total >= BLOCK_THRESHOLD ? "ALLOW" : "BLOCK"'
  mutate ok-on-bad-json src/server.ts '    return { error: "invalid_json" };
  }
  if (typeof value' '    return { text: "" };
  }
  if (typeof value'
  mutate no-size-cap src/server.ts 'export const MAX_BODY_BYTES = 256 * 1024;' 'export const MAX_BODY_BYTES = 256 * 1024 * 1024;'
  mutate wrong-method-allowed src/server.ts '    if (req.method !== "POST") return send(res, 405, { error: "method_not_allowed" }, { allow: "POST" });' '    if (req.method === "DELETE") return send(res, 405, { error: "method_not_allowed" }, { allow: "POST" });'

  echo "selftest $pass/$total"
  [ "$pass" -eq "$total" ] && [ "$total" -ge 4 ]
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
  exit $?
fi
if [ "$#" -ne 0 ]; then
  echo "usage: bash scripts/verify-ts.sh [--selftest]" >&2
  exit 2
fi

install_deps
TMP_DIR="$(mktemp -d)"
if run_checks "$ROOT/ts" "$TMP_DIR/log"; then
  echo "PASS verify-ts: tsc clean; $(cat "$TMP_DIR/log.summary")"
else
  tail -n 40 "$TMP_DIR"/log.* 2>/dev/null || true
  exit 1
fi
