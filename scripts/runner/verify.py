"""Verification gate + protected-benchmark detection for the HuntMCP dev-runner.

A task may only be marked ``[x]`` when *measured evidence* says every completion
criterion holds. A bare "I finished it" claim carries no evidence and therefore
never permits completion. Separately, any change that would touch a protected
benchmark / evaluator / ground-truth asset is flagged so the runner STOPs for
explicit human approval instead of silently editing research assets.
"""
from __future__ import annotations

import fnmatch
import os
from collections.abc import Callable
from dataclasses import dataclass, field

# Protected research assets (benchmark methodology, ground truth, evaluator,
# integrity locks). Matched by basename glob OR path substring. Editing any of
# these requires explicit human approval per .claude/rules/benchmarks.md.
PROTECTED_BASENAMES = (
    "scenarios.py",
    "answer_key.py",
    "evaluator.py",
    "integrity.py",
    "ground_truth.py",
)
PROTECTED_GLOBS = (
    "*.sha256",
    "*.sha256.lock",
)
# Anything under this directory that is a lock/ground-truth artifact is protected.
PROTECTED_PATH_SUBSTRINGS = (
    "tests/fixtures/cem_target/ground_truth",
    "tests/fixtures/cem_target/answer_key",
    "tests/fixtures/cem_target/scenarios",
    "tests/fixtures/cem_target/evaluator",
    "tests/fixtures/cem_target/integrity",
)

# Evidence keys that must all be present AND True for [x] to be permitted.
REQUIRED_EVIDENCE = (
    "tests_pass",
    "regression_pass",
    "lint_pass",
    "protected_unchanged",
    "no_unexplained_regression",
    "docs_updated",
)


def is_protected_path(path: str) -> bool:
    norm = path.replace("\\", "/").strip()
    base = os.path.basename(norm)
    if base in PROTECTED_BASENAMES:
        return True
    for g in PROTECTED_GLOBS:
        if fnmatch.fnmatch(base, g):
            return True
    for sub in PROTECTED_PATH_SUBSTRINGS:
        if sub in norm:
            return True
    return False


def detect_protected_touch(files: list[str]) -> list[str]:
    """Return the subset of ``files`` that touch a protected asset (order-preserving)."""
    return [f for f in files if is_protected_path(f)]


@dataclass
class GateResult:
    permitted: bool
    missing: list[str] = field(default_factory=list)   # required evidence not supplied
    failed: list[str] = field(default_factory=list)     # supplied but False
    reason: str = ""


def evaluate_completion(evidence: dict) -> GateResult:
    """Decide whether ``[x]`` is permitted, purely from measured evidence."""
    missing = [k for k in REQUIRED_EVIDENCE if k not in evidence]
    failed = [k for k in REQUIRED_EVIDENCE if k in evidence and not evidence[k]]
    permitted = not missing and not failed
    if permitted:
        reason = "All completion criteria satisfied by measured evidence."
    else:
        bits = []
        if failed:
            bits.append("failed: " + ", ".join(failed))
        if missing:
            bits.append("no evidence for: " + ", ".join(missing))
        reason = "Completion NOT permitted (" + "; ".join(bits) + ")."
    return GateResult(permitted=permitted, missing=missing, failed=failed, reason=reason)


# --- thin evidence collector -------------------------------------------------

# A command runner: takes (argv, cwd) and returns (returncode, output).
Runner = Callable[..., tuple]


def _default_runner(cmd: list[str], cwd: str | None = None) -> tuple:
    import subprocess

    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    return proc.returncode, (proc.stdout + proc.stderr)


def run_verification(
    repo_dir: str,
    changed_files: list[str],
    python: str = "python3",
    run: Runner | None = None,
    test_target: str = "tests/",
    lint_target: str = "mcp-servers/",
) -> dict:
    """Run the mechanical checks and return an evidence dict.

    Only the mechanical, unambiguous checks are auto-filled here (tests,
    regression, lint, protected-file detection). Human-judgement criteria
    (``docs_updated``, ``no_unexplained_regression``) default to ``False`` so the
    gate never permits ``[x]`` until they are explicitly confirmed.
    """
    run = run or _default_runner

    rc_tests, _ = run([python, "-m", "pytest", test_target, "-q"], cwd=repo_dir)
    rc_lint, _ = run([python, "-m", "ruff", "check", lint_target], cwd=repo_dir)

    protected = detect_protected_touch(changed_files)

    return {
        "tests_pass": rc_tests == 0,
        # a single mechanical suite covers both task tests and regression here;
        # callers may split these if they run a narrower task-test command.
        "regression_pass": rc_tests == 0,
        "lint_pass": rc_lint == 0,
        "protected_unchanged": not protected,
        "protected_touched": protected,
        # judgement criteria -- must be confirmed explicitly, not assumed.
        "no_unexplained_regression": False,
        "docs_updated": False,
    }
