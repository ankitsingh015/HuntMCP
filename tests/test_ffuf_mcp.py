import importlib.util
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "ffuf_mcp_server", os.path.join(ROOT, "mcp-servers", "ffuf-mcp", "server.py")
)
ffuf_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ffuf_server)


FFUF_JSON = '{"results": [{"input": {"FUZZ": "admin"}, "status": 200, "length": 512, "words": 40}]}'


def test_format_results_reports_no_results_message_on_empty_stdout():
    out = ffuf_server._format_results("https://target.com", "", 0, "banner text only", "nothing here", "path")
    assert out == "nothing here"


def test_format_results_surfaces_real_failure_not_stderr_banner():
    # ffuf always writes a progress banner to stderr even on a clean,
    # zero-match run -- returncode is the real success/failure signal.
    out = ffuf_server._format_results("https://target.com", "", 1, "boom", "nothing here", "path")
    assert "ffuf failed" in out
    assert "boom" in out


def test_format_results_lists_matches_with_path_field():
    out = ffuf_server._format_results("https://target.com", FFUF_JSON, 0, "", "nothing here", "path")
    assert "ffuf found 1 path(s) on https://target.com:" in out
    assert "/admin" in out


def test_format_results_lists_matches_with_fuzz_field():
    out = ffuf_server._format_results(None, FFUF_JSON, 0, "", "nothing here", "fuzz")
    assert "ffuf found 1 result(s):" in out
    assert "FUZZ=admin" in out


# ---------------------------------------------------------------------------
# _resolve_wordlist -- security boundary added after a real vulnerability
# was found in review: `wordlist` is an agent-facing MCP tool parameter
# whose value can be influenced by content the agent read off a hostile
# target (prompt injection). Before this validation existed, an arbitrary
# absolute path (e.g. "/home/<user>/.ssh/id_rsa") was accepted completely
# unchecked -- under S5 sandboxing that path would then need to be
# bind-mounted read-write into the sandbox to work at all, letting a
# prompt-injected agent get a sensitive host file's contents read (and its
# host permissions permanently widened by the sandbox's own mount-fixup)
# with no container escape required. Restricting to the two specific,
# reviewed, non-credential wordlist directories closes this at its source.
# ---------------------------------------------------------------------------

def test_resolve_wordlist_accepts_a_path_under_the_project_wordlist_dir(tmp_path, monkeypatch):
    # Regression test for a real, DEMONSTRATED data-loss bug: an earlier
    # version of this test created its fixture file directly inside the
    # real (unmocked) PROJECT_WORDLIST_DIR -- i.e. the actual git-tracked
    # knowledge/wordlists/ directory -- using a name ("directories.txt")
    # that collides with a real project file, then unconditionally
    # os.unlink()'d it in `finally` regardless of whether the test created
    # it. Every full test-suite run silently deleted the real file. Isolate
    # PROJECT_WORDLIST_DIR to a tmp_path so this test can never touch real
    # project content.
    monkeypatch.setattr(ffuf_server, "PROJECT_WORDLIST_DIR", str(tmp_path))
    # _APPROVED_WORDLIST_ROOTS is resolved once at import time from
    # PROJECT_WORDLIST_DIR/SYSTEM_WORDLIST_DIR -- patching PROJECT_WORDLIST_DIR
    # alone doesn't change what _resolve_wordlist actually validates against.
    monkeypatch.setattr(
        ffuf_server, "_APPROVED_WORDLIST_ROOTS",
        (os.path.realpath(str(tmp_path)), os.path.realpath(ffuf_server.SYSTEM_WORDLIST_DIR)),
    )
    approved = os.path.join(ffuf_server.PROJECT_WORDLIST_DIR, "directories.txt")
    open(approved, "a").close()
    resolved = ffuf_server._resolve_wordlist(approved)
    assert resolved == os.path.realpath(approved)


def test_resolve_wordlist_rejects_a_path_outside_approved_roots():
    with pytest.raises(ffuf_server.WordlistNotApproved):
        ffuf_server._resolve_wordlist(os.path.expanduser("~/.ssh/id_rsa"))


def test_resolve_wordlist_rejects_a_prompt_injection_style_absolute_path():
    """The exact scenario found in review: an agent steered into passing
    an absolute path to a sensitive file it was never meant to reference."""
    with pytest.raises(ffuf_server.WordlistNotApproved):
        ffuf_server._resolve_wordlist("/etc/shadow")


def test_resolve_wordlist_rejects_a_traversal_out_of_the_project_dir():
    with pytest.raises(ffuf_server.WordlistNotApproved):
        ffuf_server._resolve_wordlist(
            os.path.join(ffuf_server.PROJECT_WORDLIST_DIR, "..", "..", "..", "etc", "shadow")
        )


def test_fuzz_directory_reports_a_clean_error_for_a_rejected_wordlist():
    out = ffuf_server.fuzz_directory("https://target.com", wordlist="/etc/shadow")
    assert "Error:" in out
    assert "not approved" not in out  # message names the actual class-name text below
    assert "approved wordlist directories" in out


def test_fuzz_with_data_reports_a_clean_error_for_a_rejected_wordlist():
    out = ffuf_server.fuzz_with_data("https://target.com", wordlist="/etc/shadow")
    assert "Error:" in out
    assert "approved wordlist directories" in out


def test_start_declares_the_wordlist_path_as_an_explicit_mount(monkeypatch):
    captured = {}

    def _fake_start_job(tool_name, args, timeout, jobs, extra_mounts=None):
        captured["extra_mounts"] = extra_mounts
        return {"job_id": "job-1", "status": "running", "tool": tool_name}

    monkeypatch.setattr(ffuf_server.job_runtime, "start_job", _fake_start_job)
    ffuf_server.fuzz_directory("https://target.com", wordlist="")
    assert captured["extra_mounts"] is not None
    assert len(captured["extra_mounts"]) == 1


def test_format_results_url_with_braces_does_not_crash():
    # Regression: url used to be spliced into a stored header template
    # later run through .format(n=...) -- a url containing a literal
    # "{"/"}" collided with the {n} placeholder and raised KeyError.
    out = ffuf_server._format_results(
        "https://target.com/api/{id}", FFUF_JSON, 0, "", "nothing here", "path",
    )
    assert "{id}" in out


def test_fuzz_directory_with_braces_in_url_does_not_crash_check_scan(monkeypatch):
    # End-to-end regression for the same bug via the real fuzz_directory()/
    # check_scan() path, not just _format_results() directly.
    monkeypatch.setattr(
        ffuf_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-ffuf-braces", "status": "running", "tool": "ffuf"},
    )
    ffuf_server.fuzz_directory("https://target.com/api/{id}")

    monkeypatch.setattr(
        ffuf_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": FFUF_JSON, "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = ffuf_server.check_scan("job-ffuf-braces")  # must not raise
    assert "{id}" in out


def test_check_scan_surfaces_rate_limit_block_instead_of_silent_no_results(monkeypatch):
    # job_runtime.poll_job() classifies a rate-limit/WAF block and returns
    # it as result["block"] specifically so a blocked run isn't
    # indistinguishable from a genuine "nothing found" -- confirm
    # check_scan() actually surfaces it instead of discarding it.
    monkeypatch.setattr(
        ffuf_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-blocked", "status": "running", "tool": "ffuf"},
    )
    ffuf_server.fuzz_directory("https://target.com")

    monkeypatch.setattr(
        ffuf_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "429 too many requests", "elapsed_s": 5.0, "block": "rate_limit",
        },
    )
    out = ffuf_server.check_scan("job-blocked")
    assert "RATE_LIMIT" in out
    assert "BLOCK DETECTED" in out


def test_check_scan_after_timeout_still_cleans_up_meta(monkeypatch):
    monkeypatch.setattr(
        ffuf_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-ffuf-to", "status": "running", "tool": "ffuf"},
    )
    ffuf_server.fuzz_directory("https://target.com")
    assert "job-ffuf-to" in ffuf_server._meta

    monkeypatch.setattr(
        ffuf_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "timeout", "job_id": job_id,
            "error": "ffuf timed out after 180s and was killed -- partial output below, if any",
            "stdout": "", "stderr": "", "elapsed_s": 180.0,
        },
    )
    out = ffuf_server.check_scan("job-ffuf-to")
    assert "timed out" in out
    assert "job-ffuf-to" not in ffuf_server._meta
