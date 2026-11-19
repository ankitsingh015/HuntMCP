import json

import pytest

import session_capture


def _write_roster(tmp_path, monkeypatch, text):
    roster = tmp_path / "ids.yaml"
    roster.write_text(text)
    monkeypatch.setenv("HUNTMCP_TEST_IDENTITIES", str(roster))
    return roster


def test_list_identities_hides_secrets(tmp_path, monkeypatch):
    _write_roster(
        tmp_path,
        monkeypatch,
        "identities:\n"
        "  22bcs:\n"
        "    note: work-email\n"
        "    profile_dir: /x/22bcs\n"
        "    mailbox:\n"
        "      imap_host: imap.gmail.com\n"
        "      username: a@b.com\n"
        "      password_env: HUNTMCP_MAIL_22BCS\n",
    )
    out = session_capture.list_identities()
    assert out == [{"label": "22bcs", "note": "work-email", "has_mailbox": True, "disposable": False}]
    # the agent-facing listing must leak no path, host, username, or env-var name
    blob = json.dumps(out)
    for leaked in ("/x/22bcs", "imap.gmail.com", "a@b.com", "HUNTMCP_MAIL_22BCS"):
        assert leaked not in blob


def test_list_identities_no_mailbox_flag_false(tmp_path, monkeypatch):
    _write_roster(
        tmp_path,
        monkeypatch,
        "identities:\n  xyz:\n    note: t1\n    profile_dir: /x/xyz\n",
    )
    assert session_capture.list_identities() == [
        {"label": "xyz", "note": "t1", "has_mailbox": False, "disposable": False}
    ]


def test_load_roster_absent_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_TEST_IDENTITIES", str(tmp_path / "nope.yaml"))
    assert session_capture.load_roster() == {}


def test_roster_entry_unknown_label_raises(tmp_path, monkeypatch):
    _write_roster(
        tmp_path,
        monkeypatch,
        "identities:\n  xyz:\n    note: t\n    profile_dir: /x/xyz\n",
    )
    with pytest.raises(KeyError):
        session_capture.roster_entry("not-a-label")


def test_roster_entry_returns_full_entry(tmp_path, monkeypatch):
    _write_roster(
        tmp_path,
        monkeypatch,
        "identities:\n  xyz:\n    note: t\n    profile_dir: /x/xyz\n",
    )
    e = session_capture.roster_entry("xyz")
    assert e["profile_dir"] == "/x/xyz"
    assert e["note"] == "t"


# ---- #164: disposable identities (only these may run the account-deletion test)
def test_disposable_flag_surfaced(tmp_path, monkeypatch):
    _write_roster(tmp_path, monkeypatch,
                  "identities:\n  throwaway:\n    note: t\n    profile_dir: /x/t\n    disposable: true\n"
                  "  keep:\n    note: k\n    profile_dir: /x/k\n")
    out = {i["label"]: i for i in session_capture.list_identities()}
    assert out["throwaway"]["disposable"] is True
    assert out["keep"]["disposable"] is False
    assert session_capture.is_disposable("throwaway")
    assert not session_capture.is_disposable("keep")
    assert not session_capture.is_disposable("unknown")


def test_disposable_requires_literal_true(tmp_path, monkeypatch):
    _write_roster(tmp_path, monkeypatch,
                  'identities:\n  t:\n    note: t\n    profile_dir: /x/t\n    disposable: "yes"\n')
    assert not session_capture.is_disposable("t")
