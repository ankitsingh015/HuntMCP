"""Regression test for secrets-mcp's public-build-env-var noise filtering.

Bug found live (2026-08-31, coderabbit.ai engagement): gitleaks flagged 17
VITE_-prefixed Vite build-time env vars as "secrets" in a crawled JS bundle
-- all 17 were intentionally public (feature flags / allowlisted IDs),
0 real leaks. gitleaks has no framework awareness of this, so scan_directory
now labels (never drops) matches that look like a public build-time env var,
sorting them after anything that still needs real investigation.
"""
import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "secrets-mcp"))  # server.py imports sibling js_endpoints
_spec = importlib.util.spec_from_file_location(
    "secrets_server", os.path.join(ROOT, "mcp-servers", "secrets-mcp", "server.py"),
)
secrets_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(secrets_server)


def _fake_run_tool_factory(findings):
    """Returns a run_tool stand-in that, instead of actually invoking
    gitleaks, writes `findings` to whatever --report-path was requested --
    same contract the real gitleaks binary fulfills."""
    def _fake_run_tool(name, args, retry_on_rate_limit=False, timeout=None):
        report_path = args[args.index("--report-path") + 1]
        with open(report_path, "w") as f:
            json.dump(findings, f)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")
    return _fake_run_tool


def test_public_build_env_vars_are_labeled_not_dropped(tmp_path, monkeypatch):
    findings = [
        {
            "RuleID": "generic-api-key",
            "File": "bundle.js",
            "StartLine": 42,
            "Match": "VITE_SECURITY_ALLOWLIST_ORG_IDS=org_123,org_456",
        },
        {
            "RuleID": "aws-access-token",
            "File": "bundle.js",
            "StartLine": 100,
            "Match": "AKIAABCDEFGHIJKLMNOP",
        },
    ]
    monkeypatch.setattr(secrets_server, "run_tool", _fake_run_tool_factory(findings))

    target_dir = str(tmp_path)
    output = secrets_server.scan_directory(target_dir, redact=False)

    assert "2 potential secret(s) found" in output
    assert "1 to actually investigate" in output
    assert "AKIAABCDEFGHIJKLMNOP" in output
    assert "1 likely PUBLIC build-time env var" in output
    assert "VITE_SECURITY_ALLOWLIST_ORG_IDS" in output
    # The real finding must not be buried inside the public-env section.
    real_idx = output.index("AKIAABCDEFGHIJKLMNOP")
    public_header_idx = output.index("likely PUBLIC build-time env var")
    assert real_idx < public_header_idx


def test_all_public_env_vars_still_reported_just_relabeled(tmp_path, monkeypatch):
    findings = [
        {"RuleID": "generic-api-key", "File": "a.js", "StartLine": 1, "Match": "NEXT_PUBLIC_FEATURE_FLAG=true"},
    ]
    monkeypatch.setattr(secrets_server, "run_tool", _fake_run_tool_factory(findings))

    output = secrets_server.scan_directory(str(tmp_path), redact=False)

    assert "NEXT_PUBLIC_FEATURE_FLAG" in output
    assert "likely PUBLIC build-time env var" in output
    assert "to actually investigate" not in output


def test_no_findings_still_reports_cleanly(tmp_path, monkeypatch):
    monkeypatch.setattr(secrets_server, "run_tool", _fake_run_tool_factory([]))
    output = secrets_server.scan_directory(str(tmp_path), redact=False)
    assert "No secrets found" in output
