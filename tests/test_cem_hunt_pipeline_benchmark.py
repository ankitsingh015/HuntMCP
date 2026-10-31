"""P3-CEMHUNT acceptance evidence: run_cem_pipeline against the REAL protected
loopback CEM benchmark (tests/fixtures/cem_target/), not a stubbed target.

What this proves (and what it does not):

  * EQUIVALENCE -- the orchestrator adds nothing and changes nothing. For every
    (case, mode) the benchmark covers, the single-call pipeline reports the same
    determinism status, per-condition verdicts, condition errors and minimal sets
    as the tool-by-tool K1 harness (test_cem_benchmark._k1_conclusion), and
    spends the same Tier-2 budget. Where it stops early (non-STABLE baseline) it
    spends strictly less, and the skipped counterfactuals are ones K1 labelled
    `inconclusive` -- i.e. the early stop never hides a `necessary` conclusion.
  * FCCR == 0 -- the pipeline's own conclusions, joined through the protected
    independent evaluator exactly as K2 does, give a zero false-causal-conclusion
    rate with the same non-vacuous denominator (4), and the gate demonstrably
    fails on a planted false `necessary`.

It does NOT change the benchmark: no answer_key / scenarios / evaluator / lock
file is touched, the pipeline's inputs come only from the BLIND scenario manifest
(via the K1 harness's own _translate), and the answer key is read only at this
test layer, as in K1/K2. FCCR == 0 is, as everywhere in Phase 1, a claim about
this constructed benchmark only -- not about real targets.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "cem_target"))

import test_cem_benchmark as K  # noqa: E402  reuse the K1/K2 harness verbatim
from cem_benchmark_app import CemBenchmarkServer  # noqa: E402

_K = 5


def _calls(workdir) -> int:
    """Tier-2 requests the senders actually charged, from the run's own ledger."""
    with open(os.path.join(workdir, "budget.json")) as f:
        return json.load(f)["calls"]


def _pipeline_conclusion(case_id, mode, workdir):
    """Run one (case, mode) through run_cem_pipeline against the real benchmark and
    return (CaseConclusion, observed). Mirrors K._k1_conclusion's isolation and
    name mapping so the two are directly comparable."""
    server = CemBenchmarkServer(mode=mode).start()
    saved = {k: os.environ.get(k) for k in K._ENV_FILES}
    try:
        for env_key, fname in K._ENV_FILES.items():
            os.environ[env_key] = os.path.join(workdir, fname)

        base_request, sig, conditions, name_map = K._translate(server, case_id)
        cem_to_scenario = {v: k for k, v in name_map.items()}
        fid = K._confirmed_finding()
        out = json.loads(K.srv.run_cem_pipeline(
            fid, base_request["url"], json.dumps(base_request), json.dumps(sig),
            json.dumps(conditions), k=_K,
        ))

        verdicts = {cem_to_scenario[n]: v for n, v in out["verdicts"].items()}
        errors = {cem_to_scenario[n]: e for n, e in out["condition_errors"].items()}
        sets = (out["minimal_condition_sets"] or {}).get("minimal_sets") or []
        minimal_sets = tuple(tuple(sorted(cem_to_scenario.get(n, n) for n in s)) for s in sets)
        hits = (out["evidence_bundle"] or {}).get("baseline_replication_results", {}).get("hits") or []

        concl = K._EV.CaseConclusion(
            verdicts=dict(verdicts),
            determinism_status=out["determinism_status"],
            minimal_sets=minimal_sets,
            finding_reproduced=any(hits),
        )
        observed = {
            "verdicts": verdicts, "errors": errors, "stopped_at": out["stopped_at"],
            "determinism_status": out["determinism_status"], "minimal_sets": minimal_sets,
            "untested": [cem_to_scenario.get(n, n) for n in out["untested"]],
            "incomplete": out["incomplete"], "server_requests": len(server.requests()),
        }
        return concl, observed
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        server.stop()


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    """Every (case, mode) run ONCE through the pipeline and ONCE tool-by-tool, each
    in its own isolated workdir. key -> {"pipe": (concl, obs), "k1": (concl, obs),
    "pipe_calls": int, "k1_calls": int}."""
    out = {}
    for case_id, mode in K._K1_ALL:
        wd_p = tmp_path_factory.mktemp(f"pipe_{case_id}_{mode}")
        wd_k = tmp_path_factory.mktemp(f"k1ref_{case_id}_{mode}")
        pipe = _pipeline_conclusion(case_id, mode, str(wd_p))
        k1 = K._k1_conclusion(case_id, mode, str(wd_k))
        out[(case_id, mode)] = {
            "pipe": pipe, "k1": k1,
            "pipe_calls": _calls(wd_p), "k1_calls": _calls(wd_k),
        }
    return out


_IDS = [pytest.param(*k, id=f"{k[0]}-{k[1]}") for k in K._K1_ALL]


@pytest.mark.parametrize(("case_id", "mode"), _IDS)
def test_pipeline_matches_tool_by_tool_or_stops_early_without_hiding_a_conclusion(runs, case_id, mode):
    r = runs[(case_id, mode)]
    p_concl, p_obs = r["pipe"]
    k_concl, k_obs = r["k1"]

    # The baseline the pipeline saw is the baseline K1 saw -- including whether the
    # finding reproduced at all, which the evaluator's capability_absent branch
    # (case_07-patched) reads. The pipeline derives it from the evidence bundle,
    # K1 from the gate hits, so they must be pinned equal rather than assumed.
    assert p_obs["determinism_status"] == k_obs["determinism_status"]
    assert p_concl.finding_reproduced == k_concl.finding_reproduced

    if p_obs["stopped_at"] is None:
        # Ran to completion: indistinguishable from calling the tools one by one.
        assert p_obs["verdicts"] == k_obs["verdicts"]
        assert set(p_obs["errors"]) == set(k_obs["errors"])
        assert p_obs["minimal_sets"] == k_obs["minimal_sets"]
        assert r["pipe_calls"] == r["k1_calls"]
        assert p_obs["server_requests"] == r["pipe_calls"]  # ledger == what the target saw
    else:
        # Early stop is only ever the determinism gate on a non-STABLE baseline, it
        # spends strictly less, and everything it skipped is something K1 could only
        # call `inconclusive` -- never a `necessary` the pipeline failed to report.
        assert p_obs["stopped_at"] == "determinism_gate"
        assert p_obs["determinism_status"] != "STABLE"
        assert not p_obs["incomplete"]
        assert p_obs["verdicts"] == {}
        assert sorted(p_obs["untested"]) == sorted(
            set(k_obs["verdicts"]) | set(k_obs["errors"]))
        assert "necessary" not in k_obs["verdicts"].values()
        assert r["pipe_calls"] < r["k1_calls"]
        assert p_obs["server_requests"] == r["pipe_calls"]


def _aggregate(runs_by_key):
    return K._k2_aggregate_fccr({k: v["pipe"] for k, v in runs_by_key.items()})


def test_pipeline_false_causal_conclusion_rate_is_zero(runs):
    fccr, num, den, per_case = _aggregate(runs)

    print(f"\nP3-CEMHUNT pipeline FCCR (real benchmark): {num}/{den} = {fccr}")
    for key, r in runs.items():
        _, obs = r["pipe"]
        print(f"  {key[0]}/{key[1]}: det={obs['determinism_status']} stopped_at={obs['stopped_at']} "
              f"verdicts={obs['verdicts']} requests pipeline={r['pipe_calls']} tool-by-tool={r['k1_calls']}")
    assert num == 0, f"pipeline emitted a FALSE CAUSAL CONCLUSION: {per_case}"
    assert fccr == 0.0
    assert den == 4, f"§9 denominator is {den}, expected 4 (gate must not pass vacuously)"


def test_pipeline_fccr_gate_detects_a_false_necessary(runs):
    """Non-tautology: the same aggregation fails when the pipeline's flaky case is
    poisoned with a false `necessary` (real runs untouched; synthetic copy)."""
    real_c4, _ = runs[("case_04", "vulnerable")]["pipe"]
    assert "necessary" not in real_c4.verdicts.values()
    poisoned = dict(runs)
    poisoned[("case_04", "vulnerable")] = {
        **runs[("case_04", "vulnerable")],
        "pipe": (K._EV.CaseConclusion(
            verdicts={"probe_header": "necessary"},
            determinism_status=real_c4.determinism_status,
            minimal_sets=real_c4.minimal_sets,
            finding_reproduced=real_c4.finding_reproduced,
        ), {}),
    }
    fccr, num, den, _ = _aggregate(poisoned)
    assert num >= 1 and fccr > 0.0 and den == 4


def test_protected_benchmark_artifacts_still_match_their_locks_after_the_runs(runs):
    """Depends on `runs` so it executes AFTER every pipeline/K1 run in this module:
    the answer key and scenario manifest are still byte-identical to their locks."""
    K.test_k1_benchmark_integrity_locks_unchanged()
