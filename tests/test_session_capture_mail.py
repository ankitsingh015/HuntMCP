import asyncio
import json

import pytest

import scope_guard
import session_capture


@pytest.fixture(autouse=True)
def _clear_registry():
    session_capture._live_captures.clear()
    yield
    session_capture._live_captures.clear()


class FakeKeyboard:
    def __init__(self):
        self.typed = []

    async def type(self, text):
        self.typed.append(text)


class FakePage:
    def __init__(self):
        self.keyboard = FakeKeyboard()
        self.goto_urls = []

    async def goto(self, url, **kwargs):
        self.goto_urls.append(url)


class FakeCtx:
    def on(self, event, handler):
        pass


class FakeP:
    async def stop(self):
        pass


def _roster(monkeypatch, tmp_path, with_mailbox=True, password_env="HUNTMCP_MAIL_T", set_pw=True):
    text = (
        "identities:\n  xyz:\n    note: t\n    profile_dir: "
        + str(tmp_path / "prof") + "\n"
    )
    if with_mailbox:
        text += (
            "    mailbox:\n"
            "      imap_host: imap.example.com\n"
            "      username: u@example.com\n"
            f"      password_env: {password_env}\n"
        )
    (tmp_path / "ids.yaml").write_text(text)
    monkeypatch.setenv("HUNTMCP_TEST_IDENTITIES", str(tmp_path / "ids.yaml"))
    if set_pw:
        monkeypatch.setenv(password_env, "app-pass-xyz")
    else:
        monkeypatch.delenv(password_env, raising=False)


def _seed_live_with_page():
    slug = session_capture._slug()
    eng = scope_guard.Engagement(target="target.com", in_scope=["*.target.com", "target.com"])
    page = FakePage()
    live = session_capture._LiveCapture(
        FakeP(), FakeCtx(), page, "fp", {}, eng,
        "https://app.target.com/login", slug, "xyz", 0.0,
    )
    session_capture._live_captures[(slug, "xyz")] = live
    return page


def test_mailbox_password_prefers_cmd():
    # password fetched from a locker command (e.g. `pass show ...`), never a file/env
    assert session_capture._mailbox_password({"password_cmd": "printf s3cr3t"}) == "s3cr3t"


def test_mailbox_password_cmd_takes_first_line():
    assert session_capture._mailbox_password({"password_cmd": "printf 'pw-line1\\nnotes'"}) == "pw-line1"


def test_mailbox_password_env_fallback(monkeypatch):
    monkeypatch.setenv("HUNTMCP_MAIL_T2", "envpass")
    assert session_capture._mailbox_password({"password_env": "HUNTMCP_MAIL_T2"}) == "envpass"


def test_mailbox_password_none_raises():
    with pytest.raises(session_capture.MailError):
        session_capture._mailbox_password({})


def test_mailbox_password_cmd_failure_raises():
    with pytest.raises(session_capture.MailError):
        session_capture._mailbox_password({"password_cmd": "false"})


def test_module_has_no_send_path():
    src = open(session_capture.__file__).read()
    assert "smtplib" not in src
    assert not any("send" in name.lower() for name in dir(session_capture))


def test_apply_pending_otp_types_code_and_never_returns_it(monkeypatch, tmp_path):
    _roster(monkeypatch, tmp_path)
    monkeypatch.setattr(
        session_capture, "_imap_search_bodies",
        lambda mailbox: ["Your login code is 123456. Thanks"],
    )
    page = _seed_live_with_page()
    out = asyncio.run(session_capture.apply_pending_otp("xyz"))
    assert out == {"identity": "xyz", "otp_applied": True}
    assert "123456" not in json.dumps(out)
    assert page.keyboard.typed == ["123456"]


def test_apply_pending_otp_missing_password_env(monkeypatch, tmp_path):
    _roster(monkeypatch, tmp_path, password_env="HUNTMCP_MAIL_MISSING", set_pw=False)
    page = _seed_live_with_page()
    out = asyncio.run(session_capture.apply_pending_otp("xyz"))
    assert out["otp_applied"] is False
    assert "error" in out
    assert page.keyboard.typed == []


def test_apply_pending_otp_no_matching_code(monkeypatch, tmp_path):
    _roster(monkeypatch, tmp_path)
    monkeypatch.setattr(session_capture, "_imap_search_bodies", lambda mailbox: ["no code here"])
    page = _seed_live_with_page()
    out = asyncio.run(session_capture.apply_pending_otp("xyz"))
    assert out["otp_applied"] is False
    assert page.keyboard.typed == []


def test_apply_pending_otp_no_mailbox(monkeypatch, tmp_path):
    _roster(monkeypatch, tmp_path, with_mailbox=False)
    page = _seed_live_with_page()
    out = asyncio.run(session_capture.apply_pending_otp("xyz"))
    assert out["otp_applied"] is False
    assert "mailbox" in out["error"].lower()
    assert page.keyboard.typed == []


def test_open_pending_magic_link_navigates_open_window(monkeypatch, tmp_path):
    _roster(monkeypatch, tmp_path)
    monkeypatch.setattr(
        session_capture, "_imap_search_bodies",
        lambda mailbox: ["Click https://app.target.com/verify?t=abc to verify your email."],
    )
    page = _seed_live_with_page()
    out = asyncio.run(session_capture.open_pending_magic_link("xyz", "app.target.com"))
    assert out["magic_link_opened"] is True
    assert page.goto_urls == ["https://app.target.com/verify?t=abc"]
