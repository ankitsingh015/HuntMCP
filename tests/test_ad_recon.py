import importlib.util
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "ad_recon_server", os.path.join(ROOT, "mcp-servers", "ad-recon-mcp", "server.py"),
)
ad_recon = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ad_recon)


# Realistic canned output matching Impacket's own documented format --
# hashcat-crackable Kerberoast hashes are prefixed $krb5tgs$23$, one per
# discovered SPN account.
KERBEROAST_SAMPLE_OUTPUT = """Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName  Name        MemberOf  PasswordLastSet             LastLogon  Delegation
--------------------  ----------  --------  --------------------------  ---------  ----------
MSSQLSvc/db01.corp.local:1433  svc-sql             2025-01-01 00:00:00.000000


$krb5tgs$23$*svc-sql$CORP.LOCAL$corp.local/svc-sql*$a1b2c3d4e5f6...deadbeef
"""

ASREPROAST_SAMPLE_OUTPUT = """Impacket v0.11.0 - Copyright 2023 Fortra

$krb5asrep$23$svc-legacy@CORP.LOCAL:1122334455667788...cafebabe
"""

NO_HASHES_OUTPUT = "Impacket v0.11.0 - Copyright 2023 Fortra\n\n[-] No entries found!\n"


class _FakeResult:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# ---------------------------------------------------------------------------
# _find_binary
# ---------------------------------------------------------------------------

def test_find_binary_returns_first_match(monkeypatch):
    monkeypatch.setattr(ad_recon.shutil, "which", lambda name: "/usr/bin/" + name if name == "GetUserSPNs.py" else None)
    assert ad_recon._find_binary(ad_recon.KERBEROAST_CANDIDATES) == "GetUserSPNs.py"


def test_find_binary_returns_none_when_nothing_found(monkeypatch):
    monkeypatch.setattr(ad_recon.shutil, "which", lambda name: None)
    assert ad_recon._find_binary(ad_recon.KERBEROAST_CANDIDATES) is None


def test_find_binary_prefers_earlier_candidate(monkeypatch):
    # both impacket-getuserspns AND GetUserSPNs.py "exist" -- earlier
    # candidate in the list wins.
    monkeypatch.setattr(ad_recon.shutil, "which", lambda name: "/usr/bin/" + name)
    assert ad_recon._find_binary(ad_recon.KERBEROAST_CANDIDATES) == "impacket-getuserspns"


# ---------------------------------------------------------------------------
# _build_target -- the argv-vs-stdin credential-handling logic
# ---------------------------------------------------------------------------

def test_build_target_with_password_omits_it_from_target_string():
    target, stdin_input = ad_recon._build_target("corp.local", "alice", "S3cret!", None)
    assert "S3cret!" not in target
    assert target == "corp.local/alice"
    assert stdin_input == "S3cret!\n"


def test_build_target_with_ntlm_hash_no_stdin_needed():
    target, stdin_input = ad_recon._build_target("corp.local", "alice", None, "aad3b435b51404eeaad3b435b51404ee")
    assert target == "corp.local/alice"
    assert stdin_input is None


def test_build_target_with_no_credentials_at_all():
    target, stdin_input = ad_recon._build_target("corp.local", "", None, None)
    assert target == "corp.local/:"
    assert stdin_input is None


# ---------------------------------------------------------------------------
# kerberoast
# ---------------------------------------------------------------------------

def test_kerberoast_extracts_crackable_hash(monkeypatch):
    monkeypatch.setattr(ad_recon.shutil, "which", lambda name: "/usr/bin/" + name if name == "impacket-getuserspns" else None)
    monkeypatch.setattr(ad_recon, "run_tool", lambda *a, **k: _FakeResult(0, KERBEROAST_SAMPLE_OUTPUT, ""))

    result = ad_recon.kerberoast("corp.local", "alice", "10.0.0.1", password="S3cret!")
    assert result["crackable_hash_count"] == 1
    assert result["crackable_hashes"][0].startswith("$krb5tgs$23$")


def test_kerberoast_no_hashes_found(monkeypatch):
    monkeypatch.setattr(ad_recon.shutil, "which", lambda name: "/usr/bin/" + name if name == "impacket-getuserspns" else None)
    monkeypatch.setattr(ad_recon, "run_tool", lambda *a, **k: _FakeResult(0, NO_HASHES_OUTPUT, ""))

    result = ad_recon.kerberoast("corp.local", "alice", "10.0.0.1", password="S3cret!")
    assert result["crackable_hash_count"] == 0
    assert result["crackable_hashes"] == []


def test_kerberoast_reports_error_when_binary_missing(monkeypatch):
    monkeypatch.setattr(ad_recon.shutil, "which", lambda name: None)
    result = ad_recon.kerberoast("corp.local", "alice", "10.0.0.1", password="S3cret!")
    assert "error" in result
    assert "pip install impacket" in result["error"]


def test_kerberoast_pipes_password_via_stdin_not_argv(monkeypatch):
    captured = {}
    monkeypatch.setattr(ad_recon.shutil, "which", lambda name: "/usr/bin/" + name if name == "impacket-getuserspns" else None)

    def fake_run_tool(binary, args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _FakeResult(0, NO_HASHES_OUTPUT, "")

    monkeypatch.setattr(ad_recon, "run_tool", fake_run_tool)
    ad_recon.kerberoast("corp.local", "alice", "10.0.0.1", password="S3cretPassword!")

    assert not any("S3cretPassword!" in a for a in captured["args"])
    assert captured["kwargs"]["input"] == "S3cretPassword!\n"


def test_kerberoast_uses_hashes_flag_for_ntlm_hash(monkeypatch):
    captured = {}
    monkeypatch.setattr(ad_recon.shutil, "which", lambda name: "/usr/bin/" + name if name == "impacket-getuserspns" else None)

    def fake_run_tool(binary, args, **kwargs):
        captured["args"] = args
        return _FakeResult(0, NO_HASHES_OUTPUT, "")

    monkeypatch.setattr(ad_recon, "run_tool", fake_run_tool)
    ad_recon.kerberoast("corp.local", "alice", "10.0.0.1", ntlm_hash="aad3b435b51404eeaad3b435b51404ee")
    assert "-hashes" in captured["args"]
    assert ":aad3b435b51404eeaad3b435b51404ee" in captured["args"]


def test_kerberoast_handles_timeout(monkeypatch):
    monkeypatch.setattr(ad_recon.shutil, "which", lambda name: "/usr/bin/" + name if name == "impacket-getuserspns" else None)

    def fake_run_tool(*a, **k):
        raise subprocess.TimeoutExpired(cmd="GetUserSPNs.py", timeout=60)

    monkeypatch.setattr(ad_recon, "run_tool", fake_run_tool)
    result = ad_recon.kerberoast("corp.local", "alice", "10.0.0.1", password="x")
    assert "error" in result and "timed out" in result["error"]


# ---------------------------------------------------------------------------
# asreproast
# ---------------------------------------------------------------------------

def test_asreproast_extracts_crackable_hash(monkeypatch):
    monkeypatch.setattr(ad_recon.shutil, "which", lambda name: "/usr/bin/" + name if name == "impacket-getnpusers" else None)
    monkeypatch.setattr(ad_recon, "run_tool", lambda *a, **k: _FakeResult(0, ASREPROAST_SAMPLE_OUTPUT, ""))

    result = ad_recon.asreproast("corp.local", "10.0.0.1", username="svc-legacy")
    assert result["crackable_hash_count"] == 1
    assert result["crackable_hashes"][0].startswith("$krb5asrep$23$")


def test_asreproast_requires_username_or_users_file(monkeypatch):
    monkeypatch.setattr(ad_recon.shutil, "which", lambda name: "/usr/bin/impacket-getnpusers")
    result = ad_recon.asreproast("corp.local", "10.0.0.1")
    assert "error" in result
    assert "username" in result["error"]


def test_asreproast_always_passes_no_pass_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(ad_recon.shutil, "which", lambda name: "/usr/bin/" + name if name == "impacket-getnpusers" else None)

    def fake_run_tool(binary, args, **kwargs):
        captured["args"] = args
        return _FakeResult(0, "", "")

    monkeypatch.setattr(ad_recon, "run_tool", fake_run_tool)
    ad_recon.asreproast("corp.local", "10.0.0.1", username="alice")
    assert "-no-pass" in captured["args"]


def test_asreproast_uses_users_file_when_given(monkeypatch):
    captured = {}
    monkeypatch.setattr(ad_recon.shutil, "which", lambda name: "/usr/bin/" + name if name == "impacket-getnpusers" else None)

    def fake_run_tool(binary, args, **kwargs):
        captured["args"] = args
        return _FakeResult(0, "", "")

    monkeypatch.setattr(ad_recon, "run_tool", fake_run_tool)
    ad_recon.asreproast("corp.local", "10.0.0.1", users_file="/tmp/candidates.txt")
    assert "-usersfile" in captured["args"]
    assert "/tmp/candidates.txt" in captured["args"]


def test_asreproast_reports_error_when_binary_missing(monkeypatch):
    monkeypatch.setattr(ad_recon.shutil, "which", lambda name: None)
    result = ad_recon.asreproast("corp.local", "10.0.0.1", username="alice")
    assert "error" in result
