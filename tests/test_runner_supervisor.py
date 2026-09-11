"""Tests for the autonomous session supervisor (scripts/runner/supervisor.py).

The supervisor drives the cross-session lifecycle: read persisted state -> select
a coherent task group -> run a FRESH session -> independently re-verify + checkpoint
-> decide -> run the next fresh session. These tests never invoke real Claude:

* SpyAdapter -- records calls, does no work (used for gate/guard/dry-run tests).
* ScriptedSubprocessAdapter -- launches a REAL python subprocess that reads the
  persisted plan file and applies a scripted transition, then exits. This proves
  an actual separate-process session lifecycle recovering state from disk.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from runner import session, supervisor  # noqa: E402

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")

# A fake "Claude session": reads the persisted plan, applies a transition, exits.
_FAKE_SESSION_SCRIPT = r"""
import sys
from runner import state
plan_path, action = sys.argv[1], sys.argv[2]
ids = sys.argv[3:]
if action == "fail":
    sys.exit(1)
if action == "noop":
    print("noop"); sys.exit(0)
txt = open(plan_path, encoding="utf-8").read()
if action == "complete":
    for tid in ids:
        txt = state.set_task_status(txt, tid, "x")
elif action == "partial":
    if ids:
        txt = state.set_task_status(txt, ids[0], "~")
elif action == "human":
    if ids:
        txt = state.set_task_status(txt, ids[0], "!")
open(plan_path, "w", encoding="utf-8").write(txt)
print("ok")
"""


class SpyAdapter:
    def __init__(self, result=None):
        self.calls = []
        self.result = result or session.SessionResult(
            session_id="spy", exit_code=0, exit_reason="completed", is_error=False
        )

    def run_session(self, prompt, repo, session_id=None, timeout=None, base_env=None, group_ids=None):
        self.calls.append({"prompt": prompt, "repo": repo, "group_ids": list(group_ids or [])})
        return self.result


class ScriptedSubprocessAdapter:
    """Runs each session as a real separate python process against the plan file."""

    def __init__(self, plan_path, steps=None):
        self.plan_path = plan_path
        self.steps = list(steps or [])
        self.calls = []
        self._i = 0

    def run_session(self, prompt, repo, session_id=None, timeout=None, base_env=None, group_ids=None):
        action = self.steps[self._i] if self._i < len(self.steps) else "complete"
        self._i += 1
        self.calls.append({"action": action, "group_ids": list(group_ids or []), "prompt_len": len(prompt)})
        env = dict(base_env or os.environ)
        env["PYTHONPATH"] = SCRIPTS_DIR + os.pathsep + env.get("PYTHONPATH", "")
        argv = [sys.executable, "-c", _FAKE_SESSION_SCRIPT, self.plan_path, action, *(group_ids or [])]
        proc = subprocess.run(argv, cwd=repo, env=env, capture_output=True, text=True, timeout=30, check=False)
        return session.SessionResult(
            session_id=f"fake-{self._i}",
            exit_code=proc.returncode,
            exit_reason="completed" if proc.returncode == 0 else "process_error",
            is_error=proc.returncode != 0,
            output_tail=proc.stdout[-200:],
        )


def _ok_verifier(repo, changed_files, plan_path):
    return True, {"tests_pass": True, "regression_pass": True, "lint_pass": True, "protected_unchanged": True}


def _fail_verifier(repo, changed_files, plan_path):
    return False, {"tests_pass": False, "regression_pass": False, "lint_pass": True, "protected_unchanged": True}


def _write(tmp_path, text, name="PHASE1-EXECUTION-PLAN.md"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def _cfg(tmp_path, plan, **kw):
    return supervisor.SupervisorConfig(
        repo=str(tmp_path),
        plan_path=plan,
        state_file=str(tmp_path / ".runner-state.json"),
        log_path=str(tmp_path / "autopilot-log.jsonl"),
        **kw,
    )


TWO_GROUPS = (
    "- [x] **C5** — done. | none | cem_engine.py | verify: pytest | accept: ok. **DONE.**\n"
    "- [ ] **C6** — a. | C5 | cem_engine.py | verify: pytest | accept: ok.\n"
    "- [ ] **C7** — b. | C6 | cem_engine.py | verify: pytest | accept: ok.\n"
    "- [ ] **D1** — c. | C7 | cem_engine.py | verify: pytest | accept: ok.\n"
    "- [ ] **D2** — d. | D1 | cem_engine.py | verify: pytest | accept: ok.\n"
)


# 1. supervisor starts a session
def test_supervisor_starts_a_session(tmp_path):
    plan = _write(tmp_path, TWO_GROUPS)
    spy = SpyAdapter()
    supervisor.run_autopilot(_cfg(tmp_path, plan, max_sessions=1), adapter=spy, verifier=_ok_verifier, env={})
    assert len(spy.calls) == 1
    assert spy.calls[0]["group_ids"]  # a group was assigned


# 2. successful task completion causes checkpoint
def test_successful_completion_writes_checkpoint(tmp_path):
    plan = _write(tmp_path, TWO_GROUPS)
    adapter = ScriptedSubprocessAdapter(plan, steps=["complete"])
    supervisor.run_autopilot(_cfg(tmp_path, plan, max_sessions=1, max_group_size=2), adapter=adapter, verifier=_ok_verifier, env={})
    assert (tmp_path / ".runner-state.json").exists()


# 3 + 7. supervisor starts a fresh session afterward / multiple iterations
def test_multiple_fresh_sessions_until_done(tmp_path):
    plan = _write(tmp_path, TWO_GROUPS)
    adapter = ScriptedSubprocessAdapter(plan, steps=["complete", "complete"])
    report = supervisor.run_autopilot(
        _cfg(tmp_path, plan, max_sessions=5, max_group_size=2), adapter=adapter, verifier=_ok_verifier, env={}
    )
    assert len(adapter.calls) == 2       # two fresh sessions
    assert report.outcome == "done"


# 4 + 5. fresh session resumes from persistent state; no conversation context
def test_second_session_group_is_computed_from_persisted_file(tmp_path):
    plan = _write(tmp_path, TWO_GROUPS)
    adapter = ScriptedSubprocessAdapter(plan, steps=["complete", "complete"])
    supervisor.run_autopilot(
        _cfg(tmp_path, plan, max_sessions=5, max_group_size=2), adapter=adapter, verifier=_ok_verifier, env={}
    )
    # session 1 took C6,C7; session 2's group was derived from the updated FILE
    assert adapter.calls[0]["group_ids"] == ["C6", "C7"]
    assert adapter.calls[1]["group_ids"] == ["D1", "D2"]


# 6. session failure is recoverable (no crash; recorded; stall-stops cleanly)
def test_session_failure_is_recoverable(tmp_path):
    plan = _write(tmp_path, TWO_GROUPS)
    adapter = ScriptedSubprocessAdapter(plan, steps=["fail", "fail"])
    report = supervisor.run_autopilot(
        _cfg(tmp_path, plan, max_sessions=5, max_stall=2, max_group_size=2), adapter=adapter, verifier=_ok_verifier, env={}
    )
    assert report.outcome == "no_progress"
    assert any(it.exit_reason == "process_error" for it in report.iterations)


# 8. human decision causes STOP
def test_human_decision_stops(tmp_path):
    plan = _write(tmp_path, TWO_GROUPS)
    # session 1 marks the lead task blocked ([!]) -> the only path is blocked
    adapter = ScriptedSubprocessAdapter(plan, steps=["human"])
    report = supervisor.run_autopilot(
        _cfg(tmp_path, plan, max_sessions=5, max_group_size=1), adapter=adapter, verifier=_ok_verifier, env={}
    )
    assert report.outcome == "human_decision"
    assert report.decision_request is not None
    # no further sessions launched after the STOP
    assert len(adapter.calls) == 1


# 9. worktree mismatch causes STOP (before any session)
def test_worktree_mismatch_stops_before_session(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    for cmd in (["git", "init", "-b", "here"], ["git", "config", "user.email", "t@e.com"], ["git", "config", "user.name", "T"]):
        subprocess.run(cmd, cwd=repo, check=True, capture_output=True, text=True)
    (repo / "a").write_text("x", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "commit", "-m", "i"], cwd=repo, check=True, capture_output=True, text=True)
    plan = _write(tmp_path, TWO_GROUPS)
    spy = SpyAdapter()
    cfg = supervisor.SupervisorConfig(
        repo=str(repo), plan_path=plan, state_file=str(tmp_path / "s.json"),
        expected_branch="somewhere-else",
    )
    report = supervisor.run_autopilot(cfg, adapter=spy, verifier=_ok_verifier, env={})
    assert report.outcome == "worktree_stop"
    assert spy.calls == []


# 10. protected benchmark modification causes STOP
def test_protected_benchmark_task_stops(tmp_path):
    plan = _write(
        tmp_path,
        "- [x] **A1** — done. | none | f | verify: pytest | accept: ok. **DONE.**\n"
        "- [ ] **X1** — rescore. | A1 | tests/fixtures/cem_target/evaluator.py | verify: pytest | accept: ok.\n",
    )
    spy = SpyAdapter()
    report = supervisor.run_autopilot(_cfg(tmp_path, plan), adapter=spy, verifier=_ok_verifier, env={})
    assert report.outcome == "protected_stop"
    assert spy.calls == []


# 11. no destructive git operation is automatically performed
def test_no_destructive_git_operations(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    for cmd in (["git", "init", "-b", "work"], ["git", "config", "user.email", "t@e.com"], ["git", "config", "user.name", "T"]):
        subprocess.run(cmd, cwd=repo, check=True, capture_output=True, text=True)
    (repo / "PHASE1-EXECUTION-PLAN.md").write_text(TWO_GROUPS, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "commit", "-m", "i"], cwd=repo, check=True, capture_output=True, text=True)

    def head(r):
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, capture_output=True, text=True).stdout.strip()

    def commits(r):
        return subprocess.run(["git", "rev-list", "--count", "HEAD"], cwd=r, capture_output=True, text=True).stdout.strip()

    head_before, commits_before = head(repo), commits(repo)
    plan = str(repo / "PHASE1-EXECUTION-PLAN.md")
    adapter = ScriptedSubprocessAdapter(plan, steps=["complete", "complete"])
    cfg = supervisor.SupervisorConfig(repo=str(repo), plan_path=plan, state_file=str(tmp_path / "s.json"), max_sessions=5, max_group_size=2)
    supervisor.run_autopilot(cfg, adapter=adapter, verifier=_ok_verifier, env={})
    assert head(repo) == head_before          # HEAD unchanged
    assert commits(repo) == commits_before     # no auto-commit
    stash = subprocess.run(["git", "stash", "list"], cwd=repo, capture_output=True, text=True).stdout
    assert stash.strip() == ""                 # no auto-stash


# 12. supervisor cannot accidentally recurse/spawn itself
def test_recursion_guard_refuses_when_inside_a_session(tmp_path):
    plan = _write(tmp_path, TWO_GROUPS)
    spy = SpyAdapter()
    report = supervisor.run_autopilot(
        _cfg(tmp_path, plan), adapter=spy, verifier=_ok_verifier,
        env={session.RECURSION_GUARD_ENV: "1"},
    )
    assert report.outcome == "recursion_guard"
    assert spy.calls == []


# 13. maximum session/task safety limit exists
def test_max_sessions_cap_stops(tmp_path):
    plan = _write(tmp_path, TWO_GROUPS)
    adapter = ScriptedSubprocessAdapter(plan, steps=["complete", "complete", "complete"])
    report = supervisor.run_autopilot(
        _cfg(tmp_path, plan, max_sessions=1, max_group_size=1), adapter=adapter, verifier=_ok_verifier, env={}
    )
    assert report.outcome == "max_sessions"
    assert len(adapter.calls) == 1


# 14. clean termination when all tasks are complete
def test_all_complete_terminates_without_session(tmp_path):
    plan = _write(
        tmp_path,
        "- [x] **A1** — done. | none | f | verify: pytest | accept: ok. **DONE.**\n"
        "- [x] **A2** — done. | A1 | f | verify: pytest | accept: ok. **DONE.**\n",
    )
    spy = SpyAdapter()
    report = supervisor.run_autopilot(_cfg(tmp_path, plan), adapter=spy, verifier=_ok_verifier, env={})
    assert report.outcome == "done"
    assert spy.calls == []


# 15. dry-run performs no Claude execution
def test_dry_run_performs_no_session_execution(tmp_path):
    plan = _write(tmp_path, TWO_GROUPS)
    spy = SpyAdapter()
    report = supervisor.run_autopilot(_cfg(tmp_path, plan, dry_run=True), adapter=spy, verifier=_ok_verifier, env={})
    assert report.outcome == "dry_run"
    assert spy.calls == []
    assert report.iterations and report.iterations[0].group  # it planned a group
    # dry-run is a pure preview: it writes NOTHING to disk (no log/checkpoint).
    assert not (tmp_path / "autopilot-log.jsonl").exists()
    assert not (tmp_path / ".runner-state.json").exists()
    assert not (tmp_path / "autopilot-task.md").exists()


# extra: unverified completion claim is NOT trusted
def test_unverified_completion_claim_stops(tmp_path):
    plan = _write(tmp_path, TWO_GROUPS)
    adapter = ScriptedSubprocessAdapter(plan, steps=["complete"])
    report = supervisor.run_autopilot(
        _cfg(tmp_path, plan, max_sessions=3, max_group_size=2), adapter=adapter, verifier=_fail_verifier, env={}
    )
    assert report.outcome == "verification_failed"


# extra: no-progress (adapter does nothing) trips loop protection
def test_no_progress_loop_protection(tmp_path):
    plan = _write(tmp_path, TWO_GROUPS)
    adapter = ScriptedSubprocessAdapter(plan, steps=["noop", "noop", "noop"])
    report = supervisor.run_autopilot(
        _cfg(tmp_path, plan, max_sessions=10, max_stall=2, max_group_size=2), adapter=adapter, verifier=_ok_verifier, env={}
    )
    assert report.outcome == "no_progress"
    assert len(adapter.calls) <= 2   # stops at the stall cap, not max_sessions


# model / effort wiring
def test_default_adapter_uses_sonnet_at_high_effort():
    # The default adapter is interactive (see test_default_mode_is_interactive);
    # exact argv for both modes is asserted in test_runner_session.py. Here we
    # just pin the model/effort defaults regardless of adapter type.
    args = supervisor.build_parser().parse_args([])
    ad = supervisor.build_adapter(args)
    assert ad.model == "sonnet"
    assert ad.effort == "high"


def test_headless_mode_exact_argv_for_sonnet_high():
    args = supervisor.build_parser().parse_args(["--mode", "headless"])
    ad = supervisor.build_adapter(args)
    argv = ad.build_argv(prompt="do C6", repo="/repo")
    assert argv == [
        "claude", "-p", "do C6",
        "--output-format", "json",
        "--add-dir", "/repo",
        "--model", "sonnet",
        "--effort", "high",
    ]


def test_default_mode_is_interactive():
    args = supervisor.build_parser().parse_args([])
    ad = supervisor.build_adapter(args)
    assert isinstance(ad, session.InteractiveClaudeSessionAdapter)
    assert ad.model == "sonnet" and ad.effort == "high"
    # interactive argv is NOT the headless -p form
    argv = ad.build_argv(prompt="seed", repo="/repo", session_id="s")
    assert "-p" not in argv and "--output-format" not in argv


def test_headless_mode_selectable():
    args = supervisor.build_parser().parse_args(["--mode", "headless"])
    ad = supervisor.build_adapter(args)
    assert isinstance(ad, session.ClaudeCliSessionAdapter)
    assert "-p" in ad.build_argv(prompt="p", repo="/repo")


def test_help_documents_mode_option():
    help_text = supervisor.build_parser().format_help()
    assert "--mode" in help_text
    assert "interactive" in help_text and "headless" in help_text


def test_stop_sentinel_halts_loop_cleanly(tmp_path):
    plan = _write(tmp_path, TWO_GROUPS)
    sentinel = tmp_path / "autopilot-stop"
    sentinel.write_text("", encoding="utf-8")
    spy = SpyAdapter()
    cfg = _cfg(tmp_path, plan)
    cfg.stop_sentinel = str(sentinel)
    report = supervisor.run_autopilot(cfg, adapter=spy, verifier=_ok_verifier, env={})
    assert report.outcome == "stopped_by_user"
    assert spy.calls == []


def test_task_brief_is_persisted_for_the_fresh_session(tmp_path):
    plan = _write(tmp_path, TWO_GROUPS)
    adapter = ScriptedSubprocessAdapter(plan, steps=["complete"])
    cfg = _cfg(tmp_path, plan, max_sessions=1, max_group_size=2)
    supervisor.run_autopilot(cfg, adapter=adapter, verifier=_ok_verifier, env={})
    brief = tmp_path / "autopilot-task.md"   # next to the state file
    assert brief.exists()
    assert "C6" in brief.read_text(encoding="utf-8")


def test_operator_can_override_model_and_effort():
    args = supervisor.build_parser().parse_args(["--model", "opus", "--effort", "max"])
    ad = supervisor.build_adapter(args)
    assert ad.model == "opus"
    assert ad.effort == "max"


def test_default_adapter_never_bypasses_permissions():
    args = supervisor.build_parser().parse_args([])   # default = interactive
    argv = supervisor.build_adapter(args).build_argv(prompt="p", repo="/repo", session_id="s")
    assert "--dangerously-skip-permissions" not in argv
    assert "--allow-dangerously-skip-permissions" not in argv


def test_invalid_effort_is_rejected_by_parser():
    import pytest as _pytest
    with _pytest.raises(SystemExit):
        supervisor.build_parser().parse_args(["--effort", "turbo"])


def test_help_documents_model_and_effort_options():
    help_text = supervisor.build_parser().format_help()
    assert "--model" in help_text
    assert "--effort" in help_text
    # the valid effort choices are surfaced in help
    assert "high" in help_text and "max" in help_text


# extra: missing plan is a clean STOP, not a crash
def test_missing_plan_stops(tmp_path):
    spy = SpyAdapter()
    report = supervisor.run_autopilot(
        _cfg(tmp_path, str(tmp_path / "nope.md")), adapter=spy, verifier=_ok_verifier, env={}
    )
    assert report.outcome == "stopped"
    assert report.decision_request is not None
    assert spy.calls == []


# extra: observability log records session id / group / exit reason, no secrets
def test_log_records_iterations_without_secrets(tmp_path):
    plan = _write(tmp_path, TWO_GROUPS)
    adapter = ScriptedSubprocessAdapter(plan, steps=["complete", "complete"])
    supervisor.run_autopilot(
        _cfg(tmp_path, plan, max_sessions=5, max_group_size=2), adapter=adapter, verifier=_ok_verifier, env={}
    )
    log = (tmp_path / "autopilot-log.jsonl").read_text(encoding="utf-8")
    assert "fake-" in log            # session id recorded
    assert "C6" in log               # group recorded
    for secret in ("ANTHROPIC_API_KEY", "sk-ant", "OAUTH", "password"):
        assert secret not in log
