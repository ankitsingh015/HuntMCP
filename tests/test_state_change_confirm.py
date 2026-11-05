"""P3-VALAUTHZ: a state-changing replay step needs a HUMAN's tty-confirmed, single-use,
host+methods-bound token (scripts/confirm-state-change.sh) -- not an approval object the
calling agent writes itself. Same mechanism and honest limits as rce_confirm (S4)."""
import io
import json
import os
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

import state_change_confirm as scc  # noqa: E402


class _FakeTTY(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def token(tmp_path, monkeypatch):
    path = str(tmp_path / "state-change-confirm.json")
    monkeypatch.setenv("HUNTMCP_STATE_CHANGE_CONFIRM_PATH", path)
    return path


def _confirm(host, methods, typed=None, tty=True):
    phrase = typed if typed is not None else scc.target_string(host, methods)
    stdin = _FakeTTY(phrase + "\n") if tty else io.StringIO(phrase + "\n")
    return scc.request_confirmation(host, methods, stdin=stdin, stdout=io.StringIO())


def test_target_string_is_canonical_in_host_case_and_method_order():
    assert scc.target_string("API.Example.com:8443", ["post", "DELETE"]) == "api.example.com:8443|DELETE,POST"


def test_a_piped_or_mistyped_confirmation_writes_no_token(token):
    assert _confirm("t.example.com", ["POST"], tty=False) is False
    assert _confirm("t.example.com", ["POST"], typed="yes") is False
    assert not os.path.exists(token)


def test_a_human_confirmation_yields_a_single_use_approval_object(token):
    assert _confirm("t.example.com", ["POST"]) is True
    approval = scc.consume_approval("t.example.com", ["POST"])
    assert approval and approval["methods"] == ["POST"] and approval["authorized_by"] and approval["reason"]
    assert scc.consume_approval("t.example.com", ["POST"]) is None  # consumed


def test_the_token_is_bound_to_the_host_and_the_exact_methods(token):
    _confirm("t.example.com", ["POST"])
    assert scc.consume_approval("other.example.com", ["POST"]) is None
    assert scc.consume_approval("t.example.com", ["POST", "DELETE"]) is None
    assert scc.consume_approval("t.example.com", ["POST"]) is not None  # a wrong attempt did not burn it


def test_an_expired_token_is_refused(token):
    _confirm("t.example.com", ["POST"])
    data = json.load(open(token))
    data["expires_at"] = time.time() - 1
    json.dump(data, open(token, "w"))
    assert scc.consume_approval("t.example.com", ["POST"]) is None


def test_only_approvable_methods_can_be_confirmed(token):
    assert _confirm("t.example.com", ["TRACE"]) is False
    assert _confirm("t.example.com", ["GET"]) is False
    assert _confirm("t.example.com", []) is False


def test_the_cli_refuses_without_a_real_terminal(token):
    proc = subprocess.run([sys.executable, os.path.join(ROOT, "mcp-servers", "state_change_confirm.py"),
                           "t.example.com", "POST"], input="t.example.com|POST\n", capture_output=True,
                          text=True, env=dict(os.environ, HUNTMCP_STATE_CHANGE_CONFIRM_PATH=token), timeout=30)
    assert proc.returncode != 0 and not os.path.exists(token)


def test_the_wrapper_script_is_valid_shell():
    assert subprocess.run(["bash", "-n", os.path.join(ROOT, "scripts", "confirm-state-change.sh")]).returncode == 0


def test_approvable_methods_stay_in_sync_with_cem_engine():
    import cem_engine
    assert scc.APPROVABLE_METHODS == cem_engine.CEM_APPROVABLE_METHODS


def test_the_default_token_dir_is_private_and_owned_by_the_current_user(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTMCP_STATE_CHANGE_CONFIRM_PATH", raising=False)
    monkeypatch.setattr(scc, "LEGACY_DIR", str(tmp_path / "legacy"))
    monkeypatch.setattr(scc, "_engagement_slug_dir", lambda: None)  # no active engagement
    path = scc.token_path()
    st = os.lstat(os.path.dirname(path))
    assert st.st_uid == os.getuid() and (st.st_mode & 0o077) == 0


def test_a_foreign_or_group_writable_token_dir_is_refused(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTMCP_STATE_CHANGE_CONFIRM_PATH", raising=False)
    legacy = tmp_path / "legacy"
    legacy.mkdir(mode=0o777)
    os.chmod(legacy, 0o777)
    monkeypatch.setattr(scc, "LEGACY_DIR", str(legacy))
    monkeypatch.setattr(scc, "_engagement_slug_dir", lambda: None)
    with pytest.raises(RuntimeError):
        scc.token_path()
    assert scc.consume_approval("t.example.com", ["POST"]) is None  # fails closed, no exception


def test_a_token_dir_owned_by_someone_else_is_refused(tmp_path, monkeypatch):
    """Mutant guard for the ownership check (a private, 0700 dir that is not ours)."""
    monkeypatch.delenv("HUNTMCP_STATE_CHANGE_CONFIRM_PATH", raising=False)
    mine = tmp_path / "legacy"
    mine.mkdir(mode=0o700)
    monkeypatch.setattr(scc, "LEGACY_DIR", str(mine))
    monkeypatch.setattr(scc, "_engagement_slug_dir", lambda: None)
    monkeypatch.setattr(scc.os, "getuid", lambda: os.stat(str(mine)).st_uid + 1)
    with pytest.raises(RuntimeError):
        scc.token_path()


FP = "0123456789abcdef0123456789abcdef"
FP_OTHER = "fedcba9876543210fedcba9876543210"


def _confirm_fp(host, methods, fp):
    phrase = scc.target_string(host, methods, fp)
    return scc.request_confirmation(host, methods, fp, stdin=_FakeTTY(phrase + "\n"), stdout=io.StringIO())


def test_the_fingerprint_is_part_of_the_bound_target(token):
    assert scc.target_string("T.example.com", ["post"], FP) == "t.example.com|POST|" + FP
    assert _confirm_fp("t.example.com", ["POST"], FP)
    assert scc.consume_approval("t.example.com", ["POST"], FP_OTHER) is None
    assert scc.consume_approval("t.example.com", ["POST"]) is None            # no fingerprint = different target
    assert scc.consume_approval("t.example.com", ["POST"], FP) is not None


def test_a_malformed_fingerprint_is_refused(token):
    for bad in ("zz", "ab12", FP.upper(), FP + "; ls", "x" * 40, FP[:12], FP + "0"):
        assert _confirm_fp("t.example.com", ["POST"], bad) is False
    assert not os.path.exists(token)


# --- the human sees what the tool will send (pending-request file written by the tool) -----------

def test_the_confirm_prompt_shows_the_summary_the_tool_wrote_for_that_fingerprint(token):
    scc.write_pending("t.example.com", ["POST"], FP, "step 1: POST https://t.example.com/drafts (body 17 bytes sha256:ab)")
    out = io.StringIO()
    phrase = scc.target_string("t.example.com", ["POST"], FP)
    assert scc.request_confirmation("t.example.com", ["POST"], FP, stdin=_FakeTTY(phrase + "\n"), stdout=out)
    assert "POST https://t.example.com/drafts" in out.getvalue()


def test_terminal_control_characters_in_the_summary_are_neutralized(token):
    scc.write_pending("t.example.com", ["POST"], FP, "step 1\x1b[2J\x1b[Hfake prompt\r\nsecond line")
    out = io.StringIO()
    phrase = scc.target_string("t.example.com", ["POST"], FP)
    scc.request_confirmation("t.example.com", ["POST"], FP, stdin=_FakeTTY(phrase + "\n"), stdout=out)
    shown = out.getvalue()
    assert "\x1b" not in shown and "\r" not in shown and "fake prompt" in shown


def test_without_a_pending_file_the_human_is_warned_but_can_still_confirm(token):
    out = io.StringIO()
    phrase = scc.target_string("t.example.com", ["POST"], FP)
    assert scc.request_confirmation("t.example.com", ["POST"], FP, stdin=_FakeTTY(phrase + "\n"), stdout=out)
    assert "cannot show" in out.getvalue().lower()


def test_a_pending_file_for_another_host_or_methods_is_not_trusted_for_display(token):
    scc.write_pending("other.example.com", ["POST"], FP, "step 1: POST https://other.example.com/x")
    out = io.StringIO()
    phrase = scc.target_string("t.example.com", ["POST"], FP)
    scc.request_confirmation("t.example.com", ["POST"], FP, stdin=_FakeTTY(phrase + "\n"), stdout=out)
    assert "other.example.com/x" not in out.getvalue() and "cannot show" in out.getvalue().lower()


def test_write_pending_ignores_a_malformed_fingerprint_so_no_path_can_be_forged(token, tmp_path):
    scc.write_pending("t.example.com", ["POST"], "../../etc/evil", "x")
    scc.write_pending("t.example.com", ["POST"], "zz", "x")
    assert not [p for p in os.listdir(tmp_path) if p.startswith("state-change-pending")]


# --- final review: pending files do not pile up ----------------------------------------------

def test_consuming_the_approval_removes_its_pending_file(token, tmp_path):
    scc.write_pending("t.example.com", ["POST"], FP, "step 1: POST https://t.example.com/x")
    pending = [p for p in os.listdir(tmp_path) if p.startswith("state-change-pending-")]
    assert len(pending) == 1
    assert _confirm_fp("t.example.com", ["POST"], FP)
    assert scc.consume_approval("t.example.com", ["POST"], FP) is not None
    assert not [p for p in os.listdir(tmp_path) if p.startswith("state-change-pending-")]


def test_stale_pending_files_older_than_the_token_ttl_are_pruned(token, tmp_path):
    scc.write_pending("t.example.com", ["POST"], FP_OTHER, "old")
    old = [p for p in os.listdir(tmp_path) if p.startswith("state-change-pending-")][0]
    long_ago = time.time() - 10 * 3600
    os.utime(tmp_path / old, (long_ago, long_ago))
    scc.write_pending("t.example.com", ["POST"], FP, "fresh")
    names = [p for p in os.listdir(tmp_path) if p.startswith("state-change-pending-")]
    assert names == [f"state-change-pending-{FP}.json"]


def test_a_summary_longer_than_the_prompt_limit_is_never_cut_silently(token):
    scc.write_pending("t.example.com", ["POST"], FP, "step 1: POST http://t.example.com/" + "a" * 3000)
    out = io.StringIO()
    phrase = scc.target_string("t.example.com", ["POST"], FP)
    scc.request_confirmation("t.example.com", ["POST"], FP, stdin=_FakeTTY(phrase + "\n"), stdout=out)
    assert "DO NOT CONFIRM" in out.getvalue()


def test_a_summary_within_the_limit_is_shown_in_full_without_a_warning(token):
    text = "DELETE+POST on t.example.com; owner id 1a2b3c4d, other id 5e6f7a8b; step 1: POST http://t.example.com/" + "a" * 900
    scc.write_pending("t.example.com", ["POST"], FP, text)
    out = io.StringIO()
    phrase = scc.target_string("t.example.com", ["POST"], FP)
    scc.request_confirmation("t.example.com", ["POST"], FP, stdin=_FakeTTY(phrase + "\n"), stdout=out)
    assert text in out.getvalue() and "DO NOT CONFIRM" not in out.getvalue()
