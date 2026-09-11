"""Tests for the dev-runner CLI + checkpoint (scripts/runner/cli.py, checkpoint.py).

The CLI orchestrates the state reader, resolver, worktree gate, protected-asset
gate, context generator, and decision gate. It is read-only except for the
explicit `checkpoint` command, which writes a runner-owned JSON cache (never the
plan). Tests drive `main()` with fixture plans and temp repos; no real project
state or git history is touched.
"""
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from runner import checkpoint, cli  # noqa: E402

PLAN_NEXT_C6 = (
    "# Plan\n"
    "- [x] **A4** — extract http_probe. | none | http_probe.py | verify: pytest | accept: green. **DONE.**\n"
    "- [x] **C5** — ddmin one set. | A4 | cem_engine.py | verify: pytest | accept: recovers set. **DONE.**\n"
    "- [ ] **C6** — alternates + interaction. | C5 | cem_engine.py | verify: pytest | accept: >=2 sets when planted.\n"
)

PLAN_PROTECTED_NEXT = (
    "# Plan\n"
    "- [x] **A1** — done. | none | f | verify: pytest | accept: ok. **DONE.**\n"
    "- [ ] **X1** — rescore benchmark. | A1 | tests/fixtures/cem_target/evaluator.py | verify: pytest | accept: ok.\n"
)

PLAN_INTERRUPTED = (
    "- [x] **C5** — done. | none | cem_engine.py | verify: pytest | accept: ok. **DONE.**\n"
    "- [~] **C6** — interrupted mid-task. | C5 | cem_engine.py | verify: pytest | accept: >=2 sets.\n"
)

PLAN_MULTI_INPROGRESS = (
    "- [~] **A1** — one. | none | f | verify: pytest | accept: ok.\n"
    "- [~] **A2** — two. | none | f | verify: pytest | accept: ok.\n"
)

PLAN_DUP = (
    "- [ ] **A1** — first. | none | f | verify: pytest | accept: ok.\n"
    "- [x] **A1** — dupe. | none | f | verify: pytest | accept: ok. **DONE.**\n"
)


def _write_plan(tmp_path, text, name="PHASE1-EXECUTION-PLAN.md"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def _run_main(argv, capsys, run=None):
    code = cli.main(argv, run=run)
    out = capsys.readouterr().out
    return code, out


# --- status / next ---

def test_status_reports_next_task(tmp_path, capsys):
    plan = _write_plan(tmp_path, PLAN_NEXT_C6)
    code, out = _run_main(["status", "--plan", plan, "--repo", str(tmp_path)], capsys)
    assert code == cli.EXIT_OK
    assert "C6" in out
    assert "execute" in out.lower()


def test_next_json_emits_machine_readable(tmp_path, capsys):
    plan = _write_plan(tmp_path, PLAN_NEXT_C6)
    code, out = _run_main(["next", "--plan", plan, "--repo", str(tmp_path), "--json"], capsys)
    assert code == cli.EXIT_OK
    data = json.loads(out)
    assert data["decision"] == "execute"
    assert data["next_task"] == "C6"


# --- dry-run ---

def test_dry_run_prints_task_context_and_touches_nothing(tmp_path, capsys):
    plan = _write_plan(tmp_path, PLAN_NEXT_C6)
    before = (tmp_path / "PHASE1-EXECUTION-PLAN.md").read_text(encoding="utf-8")
    code, out = _run_main(["dry-run", "--plan", plan, "--repo", str(tmp_path)], capsys)
    assert code == cli.EXIT_OK
    assert "TASK CONTEXT" in out
    assert "C6" in out
    assert "ONE" in out.upper()
    # plan file unchanged
    assert (tmp_path / "PHASE1-EXECUTION-PLAN.md").read_text(encoding="utf-8") == before


def test_dry_run_surfaces_resume_reinspection_warning(tmp_path, capsys):
    plan = _write_plan(tmp_path, PLAN_INTERRUPTED)
    code, out = _run_main(["dry-run", "--plan", plan, "--repo", str(tmp_path)], capsys)
    assert code == cli.EXIT_OK
    assert "resume" in out.lower()
    assert "re-inspect" in out.lower() or "re-verify" in out.lower()


def test_next_surfaces_resume_reinspection_warning(tmp_path, capsys):
    plan = _write_plan(tmp_path, PLAN_INTERRUPTED)
    code, out = _run_main(["next", "--plan", plan, "--repo", str(tmp_path)], capsys)
    assert code == cli.EXIT_OK
    assert "re-inspect" in out.lower() or "re-verify" in out.lower()


def test_dry_run_stops_for_protected_benchmark_touch(tmp_path, capsys):
    plan = _write_plan(tmp_path, PLAN_PROTECTED_NEXT)
    code, out = _run_main(["dry-run", "--plan", plan, "--repo", str(tmp_path)], capsys)
    assert code == cli.EXIT_STOP
    assert "DECISION REQUIRED" in out.upper()
    assert "protected" in out.lower()
    assert "evaluator.py" in out


def test_dry_run_stops_on_multiple_in_progress(tmp_path, capsys):
    plan = _write_plan(tmp_path, PLAN_MULTI_INPROGRESS)
    code, out = _run_main(["dry-run", "--plan", plan, "--repo", str(tmp_path)], capsys)
    assert code == cli.EXIT_STOP
    assert "MULTIPLE_IN_PROGRESS" in out


def test_dry_run_stops_on_duplicate_ids(tmp_path, capsys):
    plan = _write_plan(tmp_path, PLAN_DUP)
    code, out = _run_main(["dry-run", "--plan", plan, "--repo", str(tmp_path)], capsys)
    assert code == cli.EXIT_STOP
    assert "DUPLICATE_TASK_IDS" in out


# --- plan-not-found is a BLOCKED stop, never a crash ---

def test_missing_plan_stops_cleanly(tmp_path, capsys):
    missing = str(tmp_path / "nope.md")
    code, out = _run_main(["status", "--plan", missing, "--repo", str(tmp_path)], capsys)
    assert code == cli.EXIT_STOP
    assert "PLAN_NOT_FOUND" in out


# --- worktree mismatch STOP (integration with a temp git repo) ---

def _make_repo(path):
    path.mkdir(parents=True, exist_ok=True)
    for cmd in (
        ["git", "init", "-b", "work"],
        ["git", "config", "user.email", "t@example.com"],
        ["git", "config", "user.name", "Tester"],
    ):
        subprocess.run(cmd, cwd=path, check=True, capture_output=True, text=True)
    (path / "a.txt").write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True, capture_output=True, text=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=path, check=True, capture_output=True, text=True)
    return path


def test_dry_run_stops_on_branch_mismatch(tmp_path, capsys):
    repo = _make_repo(tmp_path / "repo")
    plan = _write_plan(tmp_path, PLAN_NEXT_C6)
    code, out = _run_main(
        ["dry-run", "--plan", plan, "--repo", str(repo), "--expected-branch", "phase1-cem"],
        capsys,
    )
    assert code == cli.EXIT_STOP
    assert "WORKTREE_BRANCH_MISMATCH" in out


def test_check_reports_branch(tmp_path, capsys):
    repo = _make_repo(tmp_path / "repo")
    code, out = _run_main(["check", "--repo", str(repo)], capsys)
    assert code == cli.EXIT_OK
    assert "work" in out


# --- verify (mechanical evidence) with an injected runner ---

def test_verify_reports_evidence_and_gate(tmp_path, capsys):
    plan = _write_plan(tmp_path, PLAN_NEXT_C6)

    def fake_run(cmd, cwd=None):
        return 0, "all good"

    code, out = _run_main(
        ["verify", "--plan", plan, "--repo", str(tmp_path)], capsys, run=fake_run
    )
    # verify never auto-permits [x] (judgement criteria remain unconfirmed) -> STOP
    assert code == cli.EXIT_STOP
    assert "tests_pass" in out
    assert "not permitted" in out.lower() or "NOT permitted" in out


# --- checkpoint: resumable, survives a fresh process ---

def test_checkpoint_writes_and_reads_back(tmp_path, capsys):
    plan = _write_plan(tmp_path, PLAN_NEXT_C6)
    state_file = str(tmp_path / "runner-state.json")
    code, out = _run_main(
        ["checkpoint", "--plan", plan, "--repo", str(tmp_path), "--state-file", state_file], capsys
    )
    assert code == cli.EXIT_OK
    data = checkpoint.read_checkpoint(state_file)
    assert data["next_task"] == "C6"
    assert data["decision"] == "execute"
    assert data["plan_source"] == plan


def test_state_survives_fresh_process(tmp_path, capsys):
    plan = _write_plan(tmp_path, PLAN_NEXT_C6)
    state_file = str(tmp_path / "runner-state.json")
    _run_main(["checkpoint", "--plan", plan, "--repo", str(tmp_path), "--state-file", state_file], capsys)
    # A completely fresh interpreter reads the checkpoint back.
    script = (
        "import sys; sys.path.insert(0, %r);"
        "from runner import checkpoint;"
        "d = checkpoint.read_checkpoint(%r);"
        "print(d['next_task'])"
    ) % (os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"), state_file)
    res = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert res.returncode == 0
    assert res.stdout.strip() == "C6"


def test_checkpoint_does_not_modify_plan(tmp_path, capsys):
    plan = _write_plan(tmp_path, PLAN_NEXT_C6)
    before = (tmp_path / "PHASE1-EXECUTION-PLAN.md").read_text(encoding="utf-8")
    state_file = str(tmp_path / "runner-state.json")
    _run_main(["checkpoint", "--plan", plan, "--repo", str(tmp_path), "--state-file", state_file], capsys)
    assert (tmp_path / "PHASE1-EXECUTION-PLAN.md").read_text(encoding="utf-8") == before


def test_unknown_command_is_usage_error(tmp_path, capsys):
    with pytest.raises(SystemExit):
        cli.main(["bogus"])
