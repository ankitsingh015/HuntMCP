# Session capture — one-time setup (for a real engagement)

This is what you (the human) set up once so `browser-mcp`'s session-capture
tools work during a real authenticated engagement. The agent cannot do these
steps for you: logging in is yours by design, and the mailbox password is yours.

See the spec `docs/superpowers/specs/2026-11-13-session-capture-design.md` for
the why.

## 1. Register your test accounts (the roster / allowlist)

```bash
mkdir -p ~/.config/huntmcp
cp mcp-servers/test-identities.example.yaml ~/.config/huntmcp/test-identities.yaml
# edit it: your labels, notes, and a DEDICATED profile_dir per identity
```

- `profile_dir` must be a dedicated dir (the example uses
  `~/.config/huntmcp/browser-profiles/<label>`), never your real Chrome
  profile. `start_capture` refuses the OS-default profile in code, so your
  personal/company account can never be opened by mistake.
- `start_capture` refuses any label not in this file (allowlist).

## 2. (Optional) Mailbox for OTP / verification / magic-link — READ-ONLY

Only for an identity that needs email codes. Add a `mailbox:` block (see the
example) and set the password as an env var — never in the file:

```bash
# Gmail: create an App Password (IMAP) at https://myaccount.google.com and:
export HUNTMCP_MAIL_22BCS='your-16-char-app-password'
```

This path only ever READS mail (IMAP). It never sends anything; it imports no
SMTP library. Report emails stay manual — you send them.

## 3. Log in to each profile once (captures the session)

For each identity, the agent calls `start_capture(identity_label, login_url)`,
which opens a REAL visible window. You then:

1. Log in by hand in that window (password / captcha / 2FA / SSO — and Google
   SSO once, which the dedicated profile reuses next time).
2. If an OTP/verification email is needed and the mailbox is configured, the
   agent can `apply_pending_otp(label)` / `open_pending_magic_link(label, host)`
   to read it and fill it in for you (read-only; the code is never shown in chat).
3. In your OWN terminal, run the exact command `start_capture` printed:
   ```bash
   scripts/confirm-capture.sh <slug> <label> <fingerprint>
   ```
   (This is the human gate — the agent cannot do this step.)
4. The agent then calls `finish_capture(label)`, which writes the scoped
   identity to `data/engagements/<slug>/secrets/identities.json` (0600) and a
   reusable `session_file`. The agent only ever sees `{captured, cookie_count,
   has_bearer, whoami}` — never a cookie/token value.

## 4. Requirements

- A real display on the machine running the MCP server (the login window is
  visible). On a headless box the capture cannot show a window — run it from
  your own machine's session.
- A system Chrome/Chromium (auto-detected), or set `HUNTMCP_CHROME_PATH` to the
  binary. If Playwright's own browser revision drifts, you get a clear "run
  `playwright install chromium`" message instead of a cryptic failure.
