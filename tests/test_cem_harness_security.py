"""A4: harness isolation + tamper detection + no-CEM-production guard."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures", "cem_target"))

import integrity  # noqa: E402
from harness import ExternalTargetRefused, http_get  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures", "cem_target")


def test_external_hosts_refused():
    for url in ("http://example.com/", "http://8.8.8.8/", "http://attacker.test/x"):
        with pytest.raises(ExternalTargetRefused):
            http_get(url)


def test_loopback_variants_allowed_shape():
    # guard accepts only loopback; a non-loopback numeric host must be refused
    with pytest.raises(ExternalTargetRefused):
        http_get("http://10.0.0.5/")


def test_integrity_detects_tamper(tmp_path):
    f = tmp_path / "answers.py"
    f.write_text("EXPECTED = 1\n")
    integrity.update(str(f))
    ok, _ = integrity.verify(str(f))
    assert ok
    f.write_text("EXPECTED = 999  # tampered\n")
    ok2, msg = integrity.verify(str(f))
    assert ok2 is False and "INTEGRITY FAILURE" in msg


def test_real_fixture_integrity_holds():
    for name in ("scenarios.py", "answer_key.py"):
        ok, msg = integrity.verify(os.path.join(FIX, name))
        assert ok, msg


def test_no_cem_production_logic_exists():
    # cem_engine.py must not exist yet
    assert not os.path.isfile(os.path.join(ROOT, "mcp-servers", "cem_engine.py"))
    # case-mcp / case_store must carry no CEM symbols yet
    for rel in ("mcp-servers/case-mcp/server.py", "mcp-servers/case_store.py"):
        src = open(os.path.join(ROOT, rel)).read().lower()
        for sym in ("def define_conditions", "def run_counterfactual", "def determinism_gate",
                    "cem_conditions", "cem_trials", "cem_verdicts", "success_signature"):
            assert sym not in src, f"CEM production symbol {sym!r} leaked into {rel}"


def test_benchmark_target_does_not_import_answers():
    import re
    src = open(os.path.join(FIX, "cem_benchmark_app.py")).read()
    imp = re.compile(r"^\s*(from\s+(answer_key|scenarios|ground_truth)\s+import|import\s+(answer_key|scenarios|ground_truth))\b", re.M)
    assert not imp.search(src), "benchmark target imports answers/scenarios/ground_truth"
