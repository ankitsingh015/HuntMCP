#!/usr/bin/env bash
# Phase-1 verifier. Runs the parts that exist TODAY (test environment + regression) and
# marks CEM-dependent stages as PENDING until the CEM engine is implemented.
# Safe: the benchmark target binds to 127.0.0.1 only and is torn down by pytest fixtures.
#
# Usage:  bash scripts/verify-phase1.sh
# Output: human summary on stdout; machine-readable phase1-report.json at repo root.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"
REPORT="phase1-report.json"

declare -a NAMES STATUSES DETAILS
add(){ NAMES+=("$1"); STATUSES+=("$2"); DETAILS+=("$3"); }
run_now_failed=0

stage(){ # name  command...   -> PASS/FAIL, records, tracks run-now failure
  local name="$1"; shift
  if "$@" >/tmp/phase1_stage.out 2>&1; then
    add "$name" "PASS" "$(tail -1 /tmp/phase1_stage.out | tr -d '"')"
    echo "  [PASS] $name"
  else
    add "$name" "FAIL" "$(tail -3 /tmp/phase1_stage.out | tr '\n' ' ' | tr -d '"')"
    echo "  [FAIL] $name"; run_now_failed=1
  fi
}

echo "== Phase-1 verification =="
echo "-- run-now stages --"
INTEG='import sys,os; sys.path.insert(0,"tests/fixtures/cem_target"); import integrity; b="tests/fixtures/cem_target"; r=[integrity.verify(os.path.join(b,f)) for f in ("scenarios.py","answer_key.py")]; [print(m) for _,m in r]; sys.exit(0 if all(o for o,_ in r) else 1)'
PHASE1A="tests/test_cem_environment.py tests/test_cem_scenarios_blind.py tests/test_cem_evaluator.py tests/test_cem_harness_security.py"
stage "prereqs"               $PY -c "import pytest, http.server, sqlite3, urllib.request"
stage "integrity_start"       $PY -c "$INTEG"
stage "phase1a_tests"         $PY -m pytest $PHASE1A -q
stage "regression_full_suite" $PY -m pytest tests/ -q
stage "integrity_end"         $PY -c "$INTEG"

echo "-- pending stages (require CEM engine; not yet implemented) --"
for s in cem_unit_tests cem_integration cem_causal_benchmark false_causal_conclusion_rate performance_non_regression; do
  add "$s" "PENDING" "waiting for CEM implementation"; echo "  [PENDING] $s"
done

# machine-readable report
$PY - "$REPORT" "$run_now_failed" <<'PYJSON' "${NAMES[@]}" "|" "${STATUSES[@]}" "|" "${DETAILS[@]}"
import json, sys
report_path, run_now_failed = sys.argv[1], sys.argv[2]
rest = sys.argv[3:]
i = rest.index("|"); names = rest[:i]; rest = rest[i+1:]
j = rest.index("|"); statuses = rest[:j]; details = rest[j+1:]
stages = [{"name": n, "status": s, "detail": d} for n, s, d in zip(names, statuses, details)]
report = {
    "phase": 1,
    "overall": "FAIL" if run_now_failed == "1" else "RUN_NOW_PASS",
    "run_now_failed": run_now_failed == "1",
    "fccr": None,  # computed only once the CEM causal benchmark runs
    "note": "CEM-dependent gates are PENDING; this run verifies only the test environment + regression.",
    "stages": stages,
}
with open(report_path, "w") as f:
    json.dump(report, f, indent=2)
print("\nwrote", report_path)
PYJSON

echo
if [ "$run_now_failed" -eq 0 ]; then
  echo "RESULT: run-now stages PASS. CEM gates PENDING (G2/G3/G4/G5/G7 await CEM implementation)."
  exit 0
else
  echo "RESULT: a run-now stage FAILED. See phase1-report.json."
  exit 1
fi
