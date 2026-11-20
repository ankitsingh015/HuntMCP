"""Browser-assisted identity/session capture (#128).

Turns a HUMAN-driven login in a real visible window into scoped, structured
identity data written to disk, such that no secret (cookie value, bearer
token, storage_state, OTP, mailbox password) ever passes through the agent's
tool inputs or outputs. The human always does the login/captcha/2FA/SSO by
hand; this module automates only the EXTRACTION afterwards.

SECURITY -- the invariants this module is built around (see the design doc
docs/superpowers/specs/2026-11-13-session-capture-design.md):
- Agent-facing return values carry ONLY allow-listed non-secret keys; the
  secret itself lands only in a 0600 file under data/engagements/<slug>/
  secrets/ (wholesale-gitignored).
- Captured output is domain-scoped to the active engagement's in-scope hosts
  -- unrelated cookies (Google/FB/LinkedIn) are never written to the file.
- Mail is read-only: this module never imports an SMTP sending library and
  exposes no send function (a test asserts the literal token is absent from the
  source). Report-sending stays 100% manual (the operator sends, never agent).

This task-1 slice implements the test-identity roster only; the capture flow,
human-gate, mail reader and OAuth capture are added by later tasks.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets as _secrets
import time
from dataclasses import dataclass

import yaml

import capture_confirm
import credential_lifecycle
import engagement_paths
import scope_guard
from audit_log import log_call as _log_call
from injection_boundary import quarantine as _quarantine
from browser_launch import DEFAULT_TIMEOUT_MS
from budget_guard import enforce
from browser_launch import (
    assert_dedicated_profile_dir,
    persistent_context_kwargs,
    resolve_executable_or_raise,
)

DEFAULT_ROSTER_PATH = "~/.config/huntmcp/test-identities.yaml"


def _roster_path(path: str | None = None) -> str:
    """Resolve the roster file path: explicit arg > $HUNTMCP_TEST_IDENTITIES >
    the default under ~/.config/huntmcp/."""
    chosen = path or os.getenv("HUNTMCP_TEST_IDENTITIES") or DEFAULT_ROSTER_PATH
    return os.path.expanduser(chosen)


def load_roster(path: str | None = None) -> dict:
    """Parsed roster YAML (the whole mapping), or {} if the file is absent.

    The roster holds NO secret values -- only labels, human notes, a
    per-label dedicated profile_dir, and an optional mailbox reference whose
    password is named by an ENV VAR (password_env), never stored inline.
    """
    resolved = _roster_path(path)
    if not os.path.isfile(resolved):
        return {}
    with open(resolved) as f:
        data = yaml.safe_load(f) or {}
    return data if isinstance(data, dict) else {}


def list_identities(path: str | None = None) -> list[dict]:
    """Agent-facing roster listing: [{"label", "note", "has_mailbox", "disposable"}] only.

    Deliberately omits profile_dir and the entire mailbox block (host,
    username, password_env) so nothing that could narrow a secret reaches the
    agent's context.
    """
    identities = load_roster(path).get("identities", {}) or {}
    return [
        {
            "label": label,
            "note": (entry or {}).get("note", ""),
            "has_mailbox": bool((entry or {}).get("mailbox")),
            # #164: only an identity the human marked disposable may run the
            # UI-walk teardown's account-deletion test.
            "disposable": (entry or {}).get("disposable") is True,
        }
        for label, entry in identities.items()
    ]


def is_disposable(label: str, path: str | None = None) -> bool:
    """True only if the roster marks this identity `disposable: true` (the
    YAML boolean) -- the gate for the irreversible account-deletion test."""
    entry = (load_roster(path).get("identities", {}) or {}).get(label) or {}
    return isinstance(entry, dict) and entry.get("disposable") is True


def roster_entry(label: str, path: str | None = None) -> dict:
    """Full internal entry for label (profile_dir, optional mailbox). For
    in-process use by capture/mail flows only -- never returned to the agent.
    Raises KeyError for a label not on the roster (allowlist enforcement)."""
    identities = load_roster(path).get("identities", {}) or {}
    if label not in identities:
        raise KeyError(label)
    return identities[label] or {}


# --------------------------------------------------------------- capture core

# Allow-listed keys for every agent-facing return value. _safe_summary() fails
# closed on anything else, so a cookie value / bearer / storage_state / OTP /
# mailbox password can never be returned to the agent (invariant I1).
_ALLOWED_SUMMARY_KEYS = frozenset({
    "identity", "captured", "cookie_count", "has_bearer", "whoami",
    "otp_applied", "magic_link_opened", "captured_params", "callback_host",
    "status", "message", "error",
})

# Playwright cookie attributes carried into identities.json (solves the C2b
# multi-round-trip: SameSite/HttpOnly/Secure/Expires captured once).
_COOKIE_KEYS = ("name", "value", "domain", "path", "httpOnly", "secure", "sameSite", "expires")


@dataclass
class _LiveCapture:
    p: object
    context: object
    page: object
    fingerprint: str
    auth_by_host: dict
    engagement: object
    login_url: str
    slug: str
    label: str
    opened_at: float


# Reservation placeholder + registry of open captures, keyed by (slug, label),
# mirroring browser_confirm._live_interventions' reserve-before-await pattern.
_PENDING = object()
_live_captures: dict = {}


_LABEL_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _safe_label(label: str) -> str:
    """Reject any identity label that is not [A-Za-z0-9_-]{1,64}. Labels flow
    into on-disk paths (identities.json keys, session/oauth/confirm filenames),
    so an unvalidated label is a path-traversal / arbitrary-file-write vector --
    enforced here at the path-building layer, and at every agent entry point
    that names a label, so no caller (even a prompt-injected one) can traverse."""
    if not isinstance(label, str) or not _LABEL_RE.match(label):
        raise ValueError(f"invalid identity label {label!r} -- must match [A-Za-z0-9_-]{{1,64}}")
    return label


def _slug(slug: str | None = None) -> str:
    return slug or engagement_paths.get_active_target() or "default"


def _load_engagement():
    """Indirection so tests can inject a scope_guard.Engagement without an
    on-disk engagement.yaml."""
    return scope_guard.load_engagement()


def _safe_summary(label: str, **facts) -> str | dict:
    out: dict = {"identity": label}
    for key, value in facts.items():
        assert key in _ALLOWED_SUMMARY_KEYS, f"non-allowed summary key: {key!r}"
        out[key] = value
    return out


def _fingerprint(slug: str, label: str, login_url: str, nonce: str) -> str:
    raw = "|".join([slug, label, login_url, nonce])
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _record_auth(auth_by_host: dict, request, engagement) -> None:
    """Request listener: remember the latest in-scope Authorization header per
    host, in process only -- never echoed anywhere the agent can read."""
    try:
        auth = request.headers.get("authorization")
        if not auth:
            return
        host = scope_guard._host_of(request.url)
        if scope_guard.is_in_scope(host, engagement):
            auth_by_host[host] = auth
    except Exception:
        pass


def _pick_authorization(auth_by_host: dict, engagement) -> str | None:
    for host, value in auth_by_host.items():
        if scope_guard.is_in_scope(host, engagement):
            return value
    return None


def _filter_cookies_in_scope(cookies: list[dict], engagement) -> list[dict]:
    """Keep only cookies whose domain is an in-scope host -- drops unrelated
    Google/FB/LinkedIn cookies (invariant I2)."""
    out = []
    for c in cookies:
        if scope_guard.is_in_scope(c.get("domain", ""), engagement):
            out.append({k: c.get(k) for k in _COOKIE_KEYS})
    return out


def _filter_storage_state(storage: dict, engagement) -> dict:
    cookies = [c for c in storage.get("cookies", []) or []
               if scope_guard.is_in_scope(c.get("domain", ""), engagement)]
    origins = [o for o in storage.get("origins", []) or []
               if scope_guard.is_in_scope(o.get("origin", ""), engagement)]
    return {"cookies": cookies, "origins": origins}


# whoami auto-labelling: map a configured identity endpoint's JSON body to the
# three non-secret labels the agent is allowed to see. The token/cookies are
# used to MAKE the call but never appear in the labels or the return value.
_WHOAMI_FIELDS = {
    "user_id": ("user_id", "userId", "id", "sub"),
    "role": ("role", "roles", "userRole"),
    "org": ("org", "organization", "organization_id", "orgId", "tenant"),
}


def _extract_whoami(body: dict) -> dict:
    out: dict = {}
    for label, keys in _WHOAMI_FIELDS.items():
        value = None
        if isinstance(body, dict):
            for k in keys:
                if k in body and body[k] is not None:
                    value = body[k]
                    break
        out[label] = None if value is None else str(value)
    return out


def _whoami_fetch(url: str, cookies: list[dict], authorization: str | None) -> dict:
    """GET the whoami endpoint with the captured identity and return its parsed
    JSON body. Indirection so tests can inject a body without a network call.
    Uses the repo's scoped http_probe primitive; the identity material is used
    only to make the request, never returned."""
    from http_probe import fetch

    headers: dict[str, str] = {}
    cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name"))
    if cookie_header:
        headers["Cookie"] = cookie_header
    if authorization:
        headers["Authorization"] = authorization
    r = fetch(url, "GET", headers, None, 10.0)
    if r.error or not r.body:
        return {}
    try:
        return json.loads(r.body)
    except Exception:
        return {}


def _quarantine_whoami(whoami: dict) -> dict:
    """whoami labels come from the TARGET's own whoami endpoint -- target-
    controlled free text (I7). Frame each non-null value as untrusted data
    before it reaches the agent, so an injected 'role'/'org' string can't be
    read as an instruction. The on-disk entry keeps the raw value (evidence)."""
    return {
        k: (_quarantine(v, source_label="whoami label") if isinstance(v, str) else v)
        for k, v in whoami.items()
    }


def _whoami(cookies: list[dict], authorization: str | None, whoami_url: str, engagement) -> dict:
    if not whoami_url:
        return {}
    if not scope_guard.is_in_scope(whoami_url, engagement):
        return {}
    try:
        return _extract_whoami(_whoami_fetch(whoami_url, cookies, authorization))
    except Exception:
        return {}


def _build_identity_entry(cookies: list[dict], authorization: str | None,
                          login_url: str, whoami: dict | None) -> dict:
    return {
        "cookies": cookies,
        "authorization": authorization,
        "captured_at": time.time(),
        "source_login_url": login_url,
        "whoami": whoami or {},
    }


def _write_private(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(path, 0o600)


def _write_identity(label: str, entry: dict, storage: dict) -> str:
    _safe_label(label)
    ipath = engagement_paths.resolve("secrets/identities.json")
    data = {}
    if os.path.isfile(ipath):
        with open(ipath) as f:
            data = json.load(f) or {}
    data[label] = entry
    _write_private(ipath, json.dumps(data, indent=2))
    spath = engagement_paths.resolve(f"secrets/sessions/{label}.json")
    _write_private(spath, json.dumps(storage))
    return ipath


async def _close_live(live: _LiveCapture) -> None:
    try:
        await live.context.close()
    except Exception:
        pass
    try:
        await live.p.stop()
    except Exception:
        pass


async def _launch_persistent(profile_dir: str, timeout_ms: int = DEFAULT_TIMEOUT_MS):
    """Launch a dedicated, headed persistent-context browser and return
    (p, context, page) WITHOUT navigating. start_capture attaches the request
    listener and only THEN navigates, so an Authorization-bearing request fired
    on the very first (landing) navigation -- the SSO-reuse case, where the
    dedicated profile is already logged in -- is not missed. Isolated for test
    injection. resolve_executable_or_raise() turns a browser-revision drift into
    a clear message (#137)."""
    from playwright.async_api import async_playwright

    resolve_executable_or_raise()
    p = await async_playwright().start()
    context = await p.chromium.launch_persistent_context(**persistent_context_kwargs(profile_dir))
    page = context.pages[0] if context.pages else await context.new_page()
    return p, context, page


# ------------------------------------------- incoming-auth-mail (IMAP, READ-ONLY)
#
# This section reads OTP / verification codes / magic-links for a roster
# identity's OWN test mailbox so the human doesn't copy them out of their inbox
# by hand. It is READ-ONLY by construction: it never imports an SMTP sending
# library and exposes no send function. Report-sending stays 100% manual (the
# operator sends, never the agent). The mailbox password is read from the roster
# (password_env); it is never stored inline, never returned, and the OTP/link is
# applied into the open capture window, not returned to the agent.


class MailError(Exception):
    pass


def _message_text(msg) -> str:
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    parts.append(part.get_payload(decode=True).decode(errors="replace"))
                except Exception:
                    continue
        return "\n".join(parts)
    try:
        payload = msg.get_payload(decode=True)
        return payload.decode(errors="replace") if payload else str(msg.get_payload())
    except Exception:
        return str(msg.get_payload())


def _mailbox_password(mailbox: dict) -> str:
    """Resolve the mailbox password WITHOUT ever storing it. Prefers a locker
    command (`password_cmd`, e.g. `pass show huntmcp/mail/xyz`) so the secret
    lives only in the user's encrypted password manager and is fetched
    just-in-time; falls back to `password_env`. The roster is the user's own
    trusted local file, so running its command is safe (same pattern as
    mbsync PassCmd / git credential helpers). Never logged or returned to the
    agent. Raises MailError if neither is configured or the command fails."""
    cmd = mailbox.get("password_cmd")
    if cmd:
        import shlex
        import subprocess
        try:
            r = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=30)
        except Exception as e:
            raise MailError(f"password_cmd failed to run: {e}") from e
        if r.returncode != 0:
            raise MailError(f"password_cmd exited {r.returncode}")
        lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
        if not lines:
            raise MailError("password_cmd produced no output")
        return lines[0].strip()
    env = mailbox.get("password_env")
    password = os.getenv(env) if env else None
    if not password:
        raise MailError(
            f"no mailbox password: set password_cmd (e.g. a `pass show ...`) or the "
            f"env var named by password_env ({env!r})"
        )
    return password


def _imap_search_bodies(mailbox: dict, limit: int = 10) -> list[str]:
    """Return the text bodies of the most recent inbox messages (newest first),
    over IMAP-SSL, READ-ONLY. Raises MailError on misconfig/connection failure.
    Isolated so tests inject bodies without a network call."""
    import email
    import imaplib
    import ssl

    password = _mailbox_password(mailbox)
    host = mailbox.get("imap_host")
    user = mailbox.get("username")
    if not host or not user:
        raise MailError("mailbox config incomplete (needs imap_host and username)")
    bodies: list[str] = []
    try:
        conn = imaplib.IMAP4_SSL(host, ssl_context=ssl.create_default_context())
    except Exception as e:
        raise MailError(f"IMAP connect failed: {e}") from e
    try:
        conn.login(user, password)
        conn.select("INBOX")
        typ, data = conn.search(None, "ALL")
        ids = data[0].split()[-limit:] if data and data[0] else []
        for mid in reversed(ids):
            typ, msgdata = conn.fetch(mid, "(RFC822)")
            if not msgdata or not msgdata[0]:
                continue
            bodies.append(_message_text(email.message_from_bytes(msgdata[0][1])))
    except Exception as e:
        raise MailError(f"IMAP read failed: {e}") from e
    finally:
        try:
            conn.logout()
        except Exception:
            pass
    return bodies


def _read_latest_code(mailbox: dict, pattern: str) -> str | None:
    import re

    for body in _imap_search_bodies(mailbox):
        m = re.search(pattern, body)
        if m:
            return m.group(0)
    return None


def _read_latest_link(mailbox: dict, link_host: str) -> str | None:
    import re
    from urllib.parse import urlparse

    for body in _imap_search_bodies(mailbox):
        for url in re.findall(r"https?://[^\s\"'<>]+", body):
            if urlparse(url).hostname == link_host:
                return url
    return None


def _live_or_none(identity_label: str, slug: str | None):
    key = (_slug(slug), identity_label)
    live = _live_captures.get(key)
    if live is None or live is _PENDING:
        return None
    return live


async def apply_pending_otp(identity_label: str, slug: str | None = None,
                            pattern: str = r"\b[0-9]{4,8}\b") -> dict:
    """Read the latest OTP/verification code for identity_label's own test
    mailbox (IMAP, read-only) and TYPE it into the open capture window's active
    field. Returns {otp_applied: bool} only -- never the code. The human still
    initiated the login and the OTP send; this only removes the mailbox round
    trip."""
    live = _live_or_none(identity_label, slug)
    if live is None:
        return _safe_summary(identity_label, otp_applied=False,
                             error="no open capture window -- start_capture first")
    try:
        entry = roster_entry(identity_label)
    except KeyError:
        return _safe_summary(identity_label, otp_applied=False,
                             error=f"unknown identity label {identity_label!r}")
    mailbox = entry.get("mailbox")
    if not mailbox:
        return _safe_summary(identity_label, otp_applied=False,
                             error="no mailbox configured for this identity")
    try:
        code = _read_latest_code(mailbox, pattern)
    except MailError as e:
        return _safe_summary(identity_label, otp_applied=False, error=str(e))
    if not code:
        return _safe_summary(identity_label, otp_applied=False)
    try:
        await live.page.keyboard.type(code)
    except Exception as e:
        return _safe_summary(identity_label, otp_applied=False,
                             error=f"could not type into the capture window: {e}")
    _log_call("browser-mcp", ["apply_pending_otp", identity_label], returncode=None,
              duration_ms=0.0, block=None)
    return _safe_summary(identity_label, otp_applied=True)


async def open_pending_magic_link(identity_label: str, link_host: str,
                                  slug: str | None = None) -> dict:
    """Read the latest magic-link for identity_label's own test mailbox (IMAP,
    read-only) whose host is link_host, and navigate the open capture window to
    it. Returns {magic_link_opened: bool} only. link_host is host-validated and
    must be in scope."""
    live = _live_or_none(identity_label, slug)
    if live is None:
        return _safe_summary(identity_label, magic_link_opened=False,
                             error="no open capture window -- start_capture first")
    try:
        entry = roster_entry(identity_label)
    except KeyError:
        return _safe_summary(identity_label, magic_link_opened=False,
                             error=f"unknown identity label {identity_label!r}")
    mailbox = entry.get("mailbox")
    if not mailbox:
        return _safe_summary(identity_label, magic_link_opened=False,
                             error="no mailbox configured for this identity")
    try:
        link = _read_latest_link(mailbox, link_host)
    except MailError as e:
        return _safe_summary(identity_label, magic_link_opened=False, error=str(e))
    if not link:
        return _safe_summary(identity_label, magic_link_opened=False)
    if scope_guard._host_of(link) != link_host or not scope_guard.is_in_scope(link, live.engagement):
        return _safe_summary(identity_label, magic_link_opened=False,
                             error="magic-link host mismatch or out of scope")
    try:
        await live.page.goto(link, wait_until="domcontentloaded")
    except Exception as e:
        return _safe_summary(identity_label, magic_link_opened=False,
                             error=f"could not navigate the capture window: {e}")
    _log_call("browser-mcp", ["open_pending_magic_link", identity_label], returncode=None,
              duration_ms=0.0, block=None)
    return _safe_summary(identity_label, magic_link_opened=True)


# -------------------------------------------------- OAuth redirect capture (#133)
#
# Ruling (vs plan): OAuth redirect-code capture does NOT use the two-phase TTY
# confirmation gate. The whole point (#133/#132) is to grab the provider code
# BEFORE the app consumes it and before it expires -- a gate round trip can
# exceed the code's lifetime. The human action here IS completing the consent in
# the visible window; capture is automatic on navigation to callback_host. The
# return stays non-secret (only a param COUNT), and the code is written 0600 and
# referenced by path, never returned.


def _extract_query_params(callback_url: str) -> dict:
    from urllib.parse import parse_qs, urlparse

    qs = parse_qs(urlparse(callback_url).query)
    return {k: (v[0] if len(v) == 1 else v) for k, v in qs.items()}


def _write_oauth_capture(label: str, callback_host: str, params: dict) -> str:
    _safe_label(label)
    path = engagement_paths.resolve(f"secrets/oauth/{label}-{int(time.time() * 1000)}.json")
    _write_private(path, json.dumps({"callback_host": callback_host, "params": params}))
    return path


async def _capture_callback_url(start_url: str, callback_host: str,
                                timeout_ms: int = 120_000) -> str | None:
    """Launch a FRESH, cookie-less browser (no stored app session), navigate to
    start_url, let the human consent by hand, and return the first URL that
    lands on callback_host. Isolated for test injection."""
    from browser_launch import launch_kwargs
    from playwright.async_api import async_playwright

    resolve_executable_or_raise()
    p = await async_playwright().start()
    browser = await p.chromium.launch(**launch_kwargs(headless=False))
    try:
        context = await browser.new_context()  # cookie-less: no app session
        page = await context.new_page()
        await page.goto(start_url, timeout=timeout_ms, wait_until="domcontentloaded")
        await page.wait_for_url(f"**{callback_host}**", timeout=timeout_ms)
        return page.url
    finally:
        try:
            await browser.close()
        except Exception:
            pass
        try:
            await p.stop()
        except Exception:
            pass


async def capture_oauth_redirect(identity_label: str, start_url: str,
                                 callback_host: str, slug: str | None = None) -> dict:
    """Capture an OAuth provider's redirect parameters (e.g. ?code=...) before
    the application consumes them (#133). Opens a fresh, cookie-less window; the
    human completes consent by hand; the tool extracts the callback query params
    and writes them to a 0600 file under secrets/oauth/. Returns ONLY a param
    count + the callback host -- never the code. Tier-2: scope-gate first."""
    try:
        _safe_label(identity_label)
    except ValueError as e:
        return {"error": str(e)}
    try:
        engagement = _load_engagement()
    except scope_guard.NoEngagementFile as e:
        return {"error": f"no active engagement -- write engagement.yaml (Phase 0) first: {e}"}
    if not scope_guard.is_in_scope(start_url, engagement):
        return {"error": f"start_url host is out of scope for this engagement: {start_url!r}"}
    enforce("browser-mcp")
    try:
        callback_url = await _capture_callback_url(start_url, callback_host)
    except Exception as e:
        return {"error": "could not capture the OAuth callback (needs a real display on the "
                         f"machine running this MCP server): {e}"}
    if not callback_url:
        return _safe_summary(identity_label, captured_params=0, callback_host=callback_host)
    params = _extract_query_params(callback_url)
    _write_oauth_capture(identity_label, callback_host, params)
    _log_call("browser-mcp", ["capture_oauth_redirect", identity_label], returncode=None,
              duration_ms=0.0, block=None)
    return _safe_summary(identity_label, captured_params=len(params), callback_host=callback_host)


async def start_capture(identity_label: str, login_url: str, slug: str | None = None) -> dict:
    """Open a REAL, VISIBLE browser window (dedicated per-identity profile) at
    login_url for the human to log in by hand, and begin recording in-scope
    Authorization headers. Returns a non-secret status + the exact
    scripts/confirm-capture.sh command the HUMAN must run in their own
    terminal; the agent cannot complete the capture itself. Tier-2: scope-gate
    first. Never automates the login/captcha/2FA -- that is always the human."""
    slug = _slug(slug)
    key = (slug, identity_label)
    if key in _live_captures:
        return {"error": f"a capture is already open for {identity_label!r} -- "
                         "run the printed confirm-capture.sh then finish_capture, "
                         "or finish_capture first for a fresh one"}
    try:
        _safe_label(identity_label)
    except ValueError as e:
        return {"error": str(e)}
    try:
        entry = roster_entry(identity_label)
    except KeyError:
        return {"error": f"unknown identity label {identity_label!r} -- not on the "
                         "test-identity roster (allowlist). Add it first."}
    try:
        profile_dir = assert_dedicated_profile_dir(entry.get("profile_dir", ""))
    except ValueError as e:
        return {"error": str(e)}
    try:
        engagement = _load_engagement()
    except scope_guard.NoEngagementFile as e:
        return {"error": f"no active engagement -- write engagement.yaml (Phase 0) first: {e}"}
    if not scope_guard.is_in_scope(login_url, engagement):
        return {"error": f"login_url host is out of scope for this engagement: {login_url!r}"}
    enforce("browser-mcp")
    _live_captures[key] = _PENDING
    auth_by_host: dict = {}
    try:
        p, context, page = await _launch_persistent(profile_dir)
    except Exception as e:
        _live_captures.pop(key, None)
        return {"error": "could not open a capture window (needs a real display on the "
                         f"machine running this MCP server): {e}"}
    # Attach the request listener BEFORE navigating, so an Authorization-bearing
    # request on the very first (landing) navigation -- the SSO-reuse case, where
    # the dedicated profile is already logged in -- is captured, not missed.
    context.on("request", lambda req: _record_auth(auth_by_host, req, engagement))
    try:
        await page.goto(login_url, timeout=DEFAULT_TIMEOUT_MS, wait_until="domcontentloaded")
    except Exception as e:
        _live_captures.pop(key, None)
        await _close_live(_LiveCapture(p, context, page, "", {}, engagement, login_url, slug, identity_label, 0.0))
        return {"error": f"could not navigate the capture window to {login_url!r}: {e}"}
    fingerprint = _fingerprint(slug, identity_label, login_url, _secrets.token_hex(8))
    _live_captures[key] = _LiveCapture(
        p, context, page, fingerprint, auth_by_host, engagement,
        login_url, slug, identity_label, time.monotonic(),
    )
    _log_call("browser-mcp", ["start_capture", identity_label], returncode=None,
              duration_ms=0.0, block=None)
    return {
        "status": "open",
        "message": (
            f"Capture window open for {identity_label!r}. Log in by hand (captcha/2FA/SSO), "
            f"then run in your OWN terminal:\n"
            f"  scripts/confirm-capture.sh {slug} {identity_label} {fingerprint}\n"
            f"then call finish_capture({identity_label!r})."
        ),
    }


async def finish_capture(identity_label: str, slug: str | None = None,
                         whoami_url: str = "") -> dict:
    """After the human has logged in and confirmed via confirm-capture.sh,
    extract the in-scope cookies (full attributes) + the sniffed Authorization
    header, write them to a 0600 identities.json + a domain-scoped session
    file, close the window, and return ONLY a non-secret summary."""
    slug = _slug(slug)
    key = (slug, identity_label)
    live = _live_captures.get(key)
    if live is None or live is _PENDING:
        return {"error": f"no open capture for {identity_label!r} -- call "
                         "start_capture(identity_label, login_url) first"}
    if not capture_confirm.verify_confirmation(live.slug, identity_label, live.fingerprint):
        return {"error": "no fresh human confirmation for this capture -- run "
                         f"scripts/confirm-capture.sh {live.slug} {identity_label} "
                         f"{live.fingerprint} in your OWN terminal first (the agent "
                         "cannot satisfy this gate)."}
    try:
        cookies = await live.context.cookies()
    except Exception as e:
        # don't leave a dangling window/registry entry on a read failure
        await _close_live(live)
        _live_captures.pop(key, None)
        return {"error": f"could not read cookies from the capture window: {e}"}
    in_scope = _filter_cookies_in_scope(cookies, live.engagement)
    authorization = _pick_authorization(live.auth_by_host, live.engagement)
    try:
        storage = await live.context.storage_state()
    except Exception:
        storage = {"cookies": [], "origins": []}
    whoami = _whoami(in_scope, authorization, whoami_url, live.engagement)
    entry = _build_identity_entry(in_scope, authorization, live.login_url, whoami)
    _write_identity(identity_label, entry, _filter_storage_state(storage, live.engagement))
    # metadata only -- record_intake never stores the credential value itself, and
    # writes to its OWN intake-history file (no `path=` -- that param is its storage
    # path override, not the credential's location).
    try:
        credential_lifecycle.record_intake("session", obtained_via="session-capture")
    except Exception:
        pass
    await _close_live(live)
    _live_captures.pop(key, None)
    _log_call("browser-mcp", ["finish_capture", identity_label], returncode=None,
              duration_ms=0.0, block=None)
    return _safe_summary(identity_label, captured=True, cookie_count=len(in_scope),
                         has_bearer=bool(authorization), whoami=_quarantine_whoami(whoami))
