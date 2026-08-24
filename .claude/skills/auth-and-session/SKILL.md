---
name: auth-and-session
description: Authentication and session-management technique list (brute-force rate-limit bypass, JWT, OAuth/OIDC, SAML/SSO, session fixation, password reset, MFA bypass) plus 2025-26 modern identity attacks (passkey/WebAuthn, OAuth device-code phishing, AiTM relay, ghost logins). Converted from master-pentest-prompt.md Phases 7/7.5. Use on any login, session, SSO, or identity-related flow.
---

# Auth & session -- everything

## When to use

Any login form, session-handling code path, SSO/OAuth integration, or
password-reset flow.

## Core auth & session techniques

- **Brute-force**: rate-limiting bypass by rotating `X-Forwarded-For`,
  `X-Real-IP`, `X-Client-IP`, `True-Client-IP`, spoofed User-Agent, IPv6,
  case variation.
- **JWT**: algorithm confusion (`none`, HS/RS), `kid` injection,
  `jku`/`x5u` external reference, weak-secret brute force, claim tamper
  (role/admin/exp), JWKS confusion.
- **OAuth/OIDC**: `redirect_uri` open redirect, state parameter
  leakage/missing, code swap, token mix-up (SSRF), consent-screen
  phishing.
- **SAML/SSO**: XML signature wrapping, missing signature validation,
  forged XML, replay, login-as via injected attribute.
- **Session**: fixation, predictable token, missing flags
  (`HttpOnly`/`Secure`/`SameSite`), concurrent sessions, session not
  invalidated on logout/password change.
- **Password reset**: token leakage via Referer, predictable token, Host
  header alternate injection (`X-Forwarded-Host`, absolute URL in body).
- **MFA bypass**: OTP replay, race conditions, backup-code enumeration,
  MFA missing on the API path, cache-based bypass, "remember me" device
  cookie forgery. See the expanded MFA bypass list below for the full
  arsenal beyond these basics.
- **Email/SMS**: notification bombing, verification bypass, magic-link
  token brute force.
- **Account takeover chains**: username -> cookie manipulation
  (`Cookie: user=admin`).
- Login CSRF, OAuth CSRF, password-change CSRF.
- Cache poisoning -> session cookie disclosure.

## Modern identity & browser-era attacks (2025-26)

- **Passkey/WebAuthn**: FIDO2 URI intent hijacking (CVE-2024-9956 class),
  passkey downgrade to password, WebAuthn CSRF (add a passkey with the
  victim's email), duplicate passkey login confusion, discovery-order
  preference abuse.
- **OAuth device-code flow**: device-code phishing (the Salesforce-breach
  class), leak of `user_code` via open redirects, polling-timeout window
  abuse.
- Consent phishing / malicious OAuth app approval; state-less OAuth.
- **AiTM / reverse-proxy phishing exposure**: does the app's MFA actually
  stop an adversary-in-the-middle relay session? Reverse-proxy phishing
  kits (Evilginx3, Modlishka, Muraena) clone the login portal and proxy
  every request live, harvesting the session cookie right after the
  victim clears MFA -- since most apps only check MFA at authentication,
  not per-session, the stolen cookie alone is enough afterward. Test by
  replaying a stolen session cookie after MFA completes.
- **ClickFix / FileFix / ConsentFix**: HTML injection or open redirect
  that could be weaponized for browser-native social engineering.
- **Malicious browser-extension vector**: exposed `/manifest.json` or
  update endpoints; extension permission overreach in the supply chain.
- **Ghost logins / SSO coverage gaps**: flows that bypass SSO entirely
  (legacy endpoints, partner portals, API-key fallback) -- enumerate
  unsecured auth paths alongside the SSO path.
- **Session device binding**: can a session cookie be replayed on a
  different device/browser/ASN without a re-prompt?

## Expanded MFA bypass list

Beyond the basics above, these are the specific classes worth checking on
any MFA-protected flow -- distilled from a 2026 red-team/bug-bounty survey
of what's actually working against "unbreakable" MFA in practice:

- **MFA fatigue / push bombing**: repeatedly trigger login attempts with
  already-obtained credentials so the victim's phone gets flooded with
  push approval prompts, betting they'll eventually tap "Approve" just to
  make it stop. Defense signal to check for: number-matching push
  (approve requires typing a code shown on the login screen, not just
  tapping yes/no) or FIDO2 hardware tokens, which this attack can't touch.
- **Legacy authentication protocol bypass**: IMAP/POP3/SMTP/SMB and
  similar legacy protocols often don't enforce MFA at all even when the
  main web login does -- `nmap -p 143,993,110,995,445,<target>` to check
  what's exposed; a valid password alone can grant mailbox/file access
  through the legacy path even with MFA fully configured on the web app.
- **MFA reset via helpdesk social engineering**: call/chat into support
  claiming a lost device, using pretexting (urgency, impersonating a VIP)
  to get MFA reset or removed. Worth probing for during a social-
  engineering-in-scope engagement, and worth flagging as a policy gap
  even when out of scope to test live (does the org require strong
  identity verification and out-of-band confirmation for MFA resets?).
- **Self-enrollment / registration loopholes**: many apps let a user
  register a new MFA factor (phone, authenticator) with minimal
  re-verification, especially right after a "lost device" flow --
  test whether an already-compromised session/account can add an
  attacker-controlled MFA factor and use it for ongoing access.
- **Pass-the-cookie / pass-the-token**: extract a valid session
  cookie/token (via XSS, endpoint malware, or MiTM) and replay it in a
  fresh browser profile or via an automated client -- MFA doesn't
  re-prompt as long as the cookie itself is valid, so this bypasses MFA
  entirely rather than attacking it directly. Check whether the target
  binds sessions to a device fingerprint or IP, since many still don't.
- **SIM swapping / phone number hijacking**: relevant context for
  SMS-based MFA specifically -- if SMS OTP is the only second factor
  offered, that's worth flagging as a weaker option than an
  authenticator app or FIDO2 regardless of whether SIM swapping itself is
  testable in a given engagement (it targets the telco, not the target
  application).
