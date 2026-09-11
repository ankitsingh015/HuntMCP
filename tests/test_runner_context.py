"""Tests for the dev-runner task-context generator (scripts/runner/context.py).

The generator builds the minimum context to execute ONE task safely, derived
purely from persistent state (the parsed plan + repo rule files) -- never from
conversation memory.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from runner import context, state  # noqa: E402

PLAN = (
    "- [x] **A4** — extract http_probe. | none | http_probe.py | verify: pytest | accept: green. **DONE.**\n"
    "- [x] **C5** — ddmin one set. | A4 | cem_engine.py | verify: pytest | accept: recovers set. **DONE.**\n"
    "- [ ] **C6** — alternates + interaction. | C5 | cem_engine.py, test_cem_engine.py | verify: pytest | accept: >=2 sets when planted.\n"
)


def _ctx(**kw):
    plan = state.parse_plan(PLAN)
    task = plan.get("C6")
    return context.build_context(task=task, plan=plan, **kw)


def test_context_names_the_single_task_and_boundary():
    ctx = _ctx()
    assert ctx.task_id == "C6"
    text = context.render(ctx)
    assert "C6" in text
    assert "ONE" in text.upper() and "C6" in text
    # boundary must forbid running dependents / future tasks
    assert "do not" in text.lower()


def test_dependencies_are_shown_with_their_statuses_from_the_plan():
    ctx = _ctx()
    # C6 depends on C5, which the plan marks complete -- derived from state, not memory.
    assert ("C5", "complete") in ctx.dependencies


def test_rules_always_include_claude_md_and_all_rule_files():
    ctx = _ctx()
    joined = " ".join(ctx.rules_to_consult)
    assert "CLAUDE.md" in joined
    for rule in (
        "autonomous-execution.md",
        "testing.md",
        "security.md",
        "benchmarks.md",
        "git-worktrees.md",
    ):
        assert rule in joined


def test_scoped_claude_md_derived_from_task_files():
    ctx = _ctx()
    joined = " ".join(ctx.rules_to_consult)
    # C6 touches mcp-servers/cem_engine.py and tests/... -> both scoped rules listed
    assert "mcp-servers/CLAUDE.md" in joined
    assert "tests/CLAUDE.md" in joined


def test_verification_requirements_include_task_verify_and_accept():
    ctx = _ctx()
    text = context.render(ctx)
    assert "pytest" in text            # task.verify
    assert "sets when planted" in text  # task.accept


def test_render_includes_untrusted_data_reminder():
    text = context.render(_ctx())
    assert "untrusted" in text.lower() or "data, not instructions" in text.lower()


def test_current_phase_taken_from_project_state_when_provided():
    ctx = _ctx(project_state={"CURRENT PHASE": "Phase 1 — CEM vertical slice"})
    assert "Phase 1" in ctx.current_phase


def test_current_phase_unknown_when_no_project_state():
    ctx = _ctx()
    assert ctx.current_phase.lower() in ("unknown", "(unknown)")


def test_approval_flag_and_reason_surface_in_render():
    ctx = _ctx(require_approval=True, approval_reasons=["touches protected benchmark asset"])
    assert ctx.require_approval is True
    text = context.render(ctx)
    assert "approval" in text.lower()
    assert "protected benchmark" in text.lower()


def test_context_is_pure_function_of_inputs():
    # Same persistent inputs -> identical rendered context across calls (no memory).
    a = context.render(_ctx())
    b = context.render(_ctx())
    assert a == b
