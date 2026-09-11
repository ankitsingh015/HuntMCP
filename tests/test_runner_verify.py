"""Tests for the dev-runner verification gate (scripts/runner/verify.py).

Two responsibilities:
* protected-benchmark detection -- a task that would modify evaluator/ground-truth
  assets must be flagged so the runner STOPs for human approval;
* the completion gate -- a task may only become [x] on real evidence, never on a
  bare completion claim.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from runner import verify  # noqa: E402


# --- protected-benchmark detection ---

def test_evaluator_and_ground_truth_assets_are_protected():
    for name in ("scenarios.py", "answer_key.py", "evaluator.py", "integrity.py", "ground_truth.py"):
        assert verify.is_protected_path(f"tests/fixtures/cem_target/{name}") is True


def test_integrity_lock_files_are_protected():
    assert verify.is_protected_path("tests/fixtures/cem_target/ground_truth.sha256.lock") is True
    assert verify.is_protected_path("tests/fixtures/cem_target/answer_key.py.sha256") is True


def test_ordinary_implementation_file_is_not_protected():
    assert verify.is_protected_path("mcp-servers/cem_engine.py") is False
    assert verify.is_protected_path("scripts/runner/state.py") is False


def test_detect_protected_touch_returns_the_offending_files():
    files = ["mcp-servers/cem_engine.py", "tests/fixtures/cem_target/answer_key.py"]
    touched = verify.detect_protected_touch(files)
    assert touched == ["tests/fixtures/cem_target/answer_key.py"]


def test_detect_protected_touch_empty_when_clean():
    assert verify.detect_protected_touch(["mcp-servers/cem_engine.py", "docs/x.md"]) == []


# --- completion gate ---

def _full_evidence(**overrides):
    ev = {
        "tests_pass": True,
        "regression_pass": True,
        "lint_pass": True,
        "protected_unchanged": True,
        "no_unexplained_regression": True,
        "docs_updated": True,
    }
    ev.update(overrides)
    return ev


def test_all_evidence_true_permits_completion():
    res = verify.evaluate_completion(_full_evidence())
    assert res.permitted is True
    assert res.failed == [] and res.missing == []


def test_failing_tests_block_completion():
    res = verify.evaluate_completion(_full_evidence(tests_pass=False))
    assert res.permitted is False
    assert "tests_pass" in res.failed


def test_regression_failure_blocks_completion():
    res = verify.evaluate_completion(_full_evidence(regression_pass=False))
    assert res.permitted is False
    assert "regression_pass" in res.failed


def test_protected_change_blocks_completion():
    res = verify.evaluate_completion(_full_evidence(protected_unchanged=False))
    assert res.permitted is False
    assert "protected_unchanged" in res.failed


def test_missing_evidence_key_blocks_completion():
    ev = _full_evidence()
    del ev["lint_pass"]
    res = verify.evaluate_completion(ev)
    assert res.permitted is False
    assert "lint_pass" in res.missing


def test_bare_claim_with_no_evidence_never_permits():
    # A completion "claim" carries no measured evidence at all.
    res = verify.evaluate_completion({})
    assert res.permitted is False
    assert set(res.missing) == set(verify.REQUIRED_EVIDENCE)


# --- evidence collection (thin orchestration with an injected runner) ---

def test_run_verification_builds_evidence_from_command_results():
    calls = []

    def fake_run(cmd, cwd=None):
        calls.append(cmd)
        # every injected command "succeeds" (rc 0)
        return 0, "ok"

    ev = verify.run_verification(
        repo_dir="/repo",
        changed_files=["mcp-servers/cem_engine.py"],
        run=fake_run,
    )
    assert ev["tests_pass"] is True
    assert ev["regression_pass"] is True
    assert ev["lint_pass"] is True
    assert ev["protected_unchanged"] is True  # no protected file in changed_files
    assert calls, "verification should have invoked at least one command"


def test_run_verification_marks_protected_touch():
    def fake_run(cmd, cwd=None):
        return 0, "ok"

    ev = verify.run_verification(
        repo_dir="/repo",
        changed_files=["tests/fixtures/cem_target/evaluator.py"],
        run=fake_run,
    )
    assert ev["protected_unchanged"] is False


def test_run_verification_propagates_command_failure():
    def fake_run(cmd, cwd=None):
        # pretend the regression suite fails
        if "pytest" in " ".join(cmd):
            return 1, "1 failed"
        return 0, "ok"

    ev = verify.run_verification(
        repo_dir="/repo",
        changed_files=[],
        run=fake_run,
    )
    assert ev["regression_pass"] is False
