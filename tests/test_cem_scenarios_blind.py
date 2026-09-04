"""A1/A4: the CEM-facing scenario manifest is BLIND, and no production path can read the
answer key or the retired combined structure.
"""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures", "cem_target"))

import scenarios  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORBIDDEN = scenarios.FORBIDDEN_ANSWER_FIELDS


def _walk_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict) or hasattr(obj, "items"):
        for k, v in obj.items():
            yield from _walk_strings(k)
            yield from _walk_strings(v)
    elif isinstance(obj, (list, tuple)):
        for x in obj:
            yield from _walk_strings(x)


def test_manifest_contains_no_answer_key_fields():
    blob = " ".join(_walk_strings(scenarios.SCENARIOS)).lower()
    leaked = [w for w in FORBIDDEN if w in blob]
    assert not leaked, f"scenario manifest leaks answer-key terms: {leaked}"


def test_manifest_case_ids_are_neutral():
    for cid in scenarios.SCENARIOS:
        assert re.fullmatch(r"case_\d+", cid), f"non-neutral case id leaks meaning: {cid!r}"


def test_manifest_cases_only_expose_legitimate_inputs():
    allowed = {"endpoint", "oracle", "conditions"}
    for cid, case in scenarios.SCENARIOS.items():
        assert set(case.keys()) <= allowed, f"{cid} exposes non-input fields: {set(case) - allowed}"


def test_manifest_endpoints_are_relative_loopback_safe():
    # No scheme/host in any endpoint -> a scenario cannot redirect CEM to an external target.
    for cid, case in scenarios.SCENARIOS.items():
        ep = case["endpoint"]
        assert ep.startswith("/") and "://" not in ep, f"{cid} endpoint not relative: {ep!r}"


def test_scenarios_does_not_import_answer_key():
    src = open(os.path.join(ROOT, "tests", "fixtures", "cem_target", "scenarios.py")).read()
    # real import statements only (anchored) -- a docstring mentioning the words is fine
    imp = re.compile(r"^\s*(from\s+(answer_key|evaluator|ground_truth)\s+import|import\s+(answer_key|evaluator|ground_truth))\b", re.M)
    assert not imp.search(src), "scenarios.py imports the answer key/evaluator"


def test_retired_ground_truth_is_a_tripwire():
    import importlib
    with pytest.raises(ImportError):
        importlib.import_module("ground_truth")


def test_no_production_code_imports_answer_key_or_evaluator():
    # Scan production trees (NOT tests/) for any import of the fixture answer/evaluator/retired modules.
    patterns = re.compile(r"^\s*(import|from)\s+(answer_key|evaluator|ground_truth)\b", re.M)
    offenders = []
    for sub in ("mcp-servers", ".opencode", "scripts"):
        base = os.path.join(ROOT, sub)
        for dirpath, _dirs, files in os.walk(base):
            if "__pycache__" in dirpath:
                continue
            for fn in files:
                if fn.endswith((".py", ".md", ".sh")):
                    p = os.path.join(dirpath, fn)
                    try:
                        if patterns.search(open(p, errors="replace").read()):
                            offenders.append(os.path.relpath(p, ROOT))
                    except OSError:
                        pass
    assert not offenders, f"production code reaches the answer key/evaluator: {offenders}"
