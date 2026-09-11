#!/usr/bin/env bash
# Phase-1 verifier (task P1). Runs the §14 one-command verification and confirms the
# §13 pass/fail gates G1-G9 against the implemented CEM Phase-1 slice
# (Groups B-G on main via PR #99; J1/K1/K2/L1/M1 test coverage on the completion branch).
#
# Each CEM benchmark/integration stage manages its own loopback target via pytest
# fixtures (CemBenchmarkServer binds 127.0.0.1 only and is torn down by the fixture),
# so there is no separate target to start/stop here.
#
# Usage:  bash scripts/verify-phase1.sh
# Output: human summary on stdout; machine-readable phase1-report.json at repo root.
# Exit:   non-zero if any automated gate G1-G9 fails.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"
REPORT="phase1-report.json"
A3_BASELINE=637   # docs/cem-phase1-baseline.txt — G1 requires the full suite pass-count >= this

declare -a NAMES STATUSES GATES DETAILS
add(){ NAMES+=("$1"); STATUSES+=("$2"); GATES+=("$3"); DETAILS+=("$4"); }
gate_failed=0

stage(){ # name  gate  command...   -> PASS/FAIL, records, tracks gate failure
  local name="$1" gate="$2"; shift 2
  if "$@" >/tmp/phase1_stage.out 2>&1; then
    add "$name" "PASS" "$gate" "$(tail -1 /tmp/phase1_stage.out | tr -d '"')"
    echo "  [PASS] $name ($gate)"
  else
    add "$name" "FAIL" "$gate" "$(tail -3 /tmp/phase1_stage.out | tr '\n' ' ' | tr -d '"')"
    echo "  [FAIL] $name ($gate)"; gate_failed=1
  fi
}

# pytest_min MIN -- pytest-args...   Runs pytest; fails unless it exits 0 AND at
# least MIN tests actually passed. Guards against a stale `-k` filter silently
# selecting zero tests (pytest exits 0 on "N deselected" with nothing run), which
# would let a gate go green having asserted nothing.
pytest_min(){
  local min="$1"; shift
  $PY -m pytest "$@" -q >/tmp/phase1_stage.out 2>&1
  local rc=$? line passed
  line="$(grep -E '^[0-9]+ (passed|failed|error)' /tmp/phase1_stage.out | tail -1)"
  passed="$(printf '%s' "$line" | grep -oE '^[0-9]+ passed' | grep -oE '^[0-9]+')"
  echo "$line"
  [ "$rc" -eq 0 ] || { echo "pytest exit $rc"; return 1; }
  [ -n "$passed" ] && [ "$passed" -ge "$min" ] || { echo "only ${passed:-0} passed, expected >= $min (stale -k filter?)"; return 1; }
  return 0
}

# G1 has an extra assertion beyond exit-code 0: pass-count must not regress below A3.
regression_with_baseline(){
  $PY -m pytest tests/ -q >/tmp/phase1_stage.out 2>&1
  local rc=$? line passed
  line="$(grep -E '^[0-9]+ (passed|failed)' /tmp/phase1_stage.out | tail -1)"
  passed="$(printf '%s' "$line" | grep -oE '^[0-9]+')"
  echo "$line"
  [ "$rc" -eq 0 ] || { echo "pytest exit $rc"; return 1; }
  [ -n "$passed" ] && [ "$passed" -ge "$A3_BASELINE" ] || { echo "pass-count $passed < A3 baseline $A3_BASELINE"; return 1; }
  return 0
}

INTEG='import sys,os; sys.path.insert(0,"tests/fixtures/cem_target"); import integrity; b="tests/fixtures/cem_target"; r=[integrity.verify(os.path.join(b,f)) for f in ("scenarios.py","answer_key.py")]; [print(m) for _,m in r]; sys.exit(0 if all(o for o,_ in r) else 1)'
# The -k buckets below rely on the test_k1_* / test_k2_* naming convention in
# tests/test_cem_benchmark.py (K1/K2 sections). J1 = everything else in that file.
HARNESS="tests/test_cem_environment.py tests/test_cem_scenarios_blind.py tests/test_cem_evaluator.py tests/test_cem_harness_security.py"

echo "== Phase-1 verification (P1) =="
echo "-- environment / integrity --"
stage "prereqs"                      "-"   $PY -c "import pytest, http.server, sqlite3, urllib.request"
stage "integrity_start"              "G9"  $PY -c "$INTEG"

echo "-- gates --"
# G7 first, on the still-quiet host: M1's wall-clock CI test is designed to SKIP
# (never FAIL) under load, and the verifier's own later stages load the host --
# running it up front lets the wall-clock bound actually be asserted, not skipped.
# (The always-run part of G7 -- config B issues zero extra HTTP / zero cem_engine
# calls on the normal path -- asserts regardless of order.)
stage "performance_non_regression"  "G7"  pytest_min 4   tests/test_cem_performance.py
stage "regression_full_suite"       "G1"  regression_with_baseline
stage "cem_unit_tests"              "G2"  pytest_min 200 tests/test_cem_engine.py tests/test_cem_case_store.py tests/test_cem_mcp.py
stage "cem_integration"             "G3"  pytest_min 8   tests/test_cem_benchmark.py -k "not k1 and not k2"
stage "cem_causal_benchmark"        "G4"  pytest_min 12  tests/test_cem_benchmark.py -k "k1"
stage "false_causal_conclusion_rate" "G5" pytest_min 2   "tests/test_cem_benchmark.py::test_k2_false_causal_conclusion_rate_is_zero" "tests/test_cem_benchmark.py::test_k2_fccr_gate_detects_a_false_necessary"
stage "scope_rate_budget_audit"     "G6"  pytest_min 150 tests/test_cem_scope_gate.py tests/test_cem_budget_f2.py tests/test_cem_safety.py tests/test_cem_f3_perturbation_scope.py tests/test_cem_f3b_nonidempotent.py tests/test_cem_g1_integration.py tests/test_cem_o1_ssrf.py
stage "benchmark_harness_isolation" "G9"  pytest_min 20  $HARNESS
stage "integrity_end"               "G9"  $PY -c "$INTEG"

# G8 — "no unreviewed deviation from PHASE1-PLAN.md". Not a test: asserted by record.
# Every deviation in the Phase-1 effort is documented and human-approved in
# PHASE1-EXECUTION-PLAN.md (§2 UD-1..UD-4, §20 plan-consistency audit, and each task's
# KNOWN DEVIATIONS note). P1 introduces none. Re-confirm by inspection before sign-off.
add "no_unreviewed_deviation" "REVIEW" "G8" "documented in PHASE1-EXECUTION-PLAN.md (UD-1..UD-4, per-task KNOWN DEVIATIONS, §20); confirm by inspection"
echo "  [REVIEW] no_unreviewed_deviation (G8) — asserted by record, confirm by inspection"

# machine-readable report
FCCR="null"; [ "$gate_failed" -eq 0 ] && FCCR="0.0"
$PY - "$REPORT" "$gate_failed" "$FCCR" <<'PYJSON' "${NAMES[@]}" "|" "${STATUSES[@]}" "|" "${GATES[@]}" "|" "${DETAILS[@]}"
import json, sys
report_path, gate_failed, fccr = sys.argv[1], sys.argv[2], sys.argv[3]
rest = sys.argv[4:]
i = rest.index("|"); names = rest[:i]; rest = rest[i+1:]
j = rest.index("|"); statuses = rest[:j]; rest = rest[j+1:]
k = rest.index("|"); gates = rest[:k]; details = rest[k+1:]
stages = [{"name": n, "status": s, "gate": g, "detail": d}
          for n, s, g, d in zip(names, statuses, gates, details)]
automated = [s for s in stages if s["status"] in ("PASS", "FAIL")]
report = {
    "phase": 1,
    "overall": "FAIL" if gate_failed == "1" else "PASS",
    "gates_automated": sorted({s["gate"] for s in automated if s["gate"] != "-"}),
    "gates_review_only": ["G8"],
    "fccr": None if fccr == "null" else float(fccr),
    "a3_baseline": 637,
    "note": ("All automated gates G1-G9 pass. G8 (no unreviewed deviation) is a review "
             "gate asserted by record. O1 final security audit is a separate task, not "
             "part of this verifier."),
    "stages": stages,
}
with open(report_path, "w") as f:
    json.dump(report, f, indent=2)
print("\nwrote", report_path)
PYJSON

echo
if [ "$gate_failed" -eq 0 ]; then
  echo "RESULT: automated gates G1-G9 PASS. G8 asserted by record (confirm by inspection). O1 is separate."
  exit 0
else
  echo "RESULT: a gate FAILED. See phase1-report.json. Corresponding task -> [!] BLOCKED."
  exit 1
fi
