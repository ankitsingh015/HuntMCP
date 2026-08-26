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

### Brute-force: four-state rate-limit classification

A burst of requests with no `429` does not mean "no rate limiting" -- classify
the actual defense before concluding, by sending ~50 requests and watching
status, latency, and body size together:

| State | Signal | Brute still feasible? |
|-------|--------|------------------------|
| Hard account lockout | Account disabled after N fails; later *correct* creds also fail | No (the lockout itself can be a DoS finding) |
| Soft IP-throttle | `429` / rising latency keyed on source IP only | Yes -- bypass via header/IP rotation |
| CAPTCHA injection | `200` but body switches to a challenge after N attempts | Maybe -- check whether the verify endpoint enforces it server-side |
| Silent shadow-throttle | Every request still returns `200`/`401`, but the genuinely-correct value stops being accepted | Looks unprotected but isn't -- the trap that produces false "no rate limit" conclusions |

- **Shadow-throttle seed-detector**: seed a known-good value (e.g. the real
  OTP for your own test account) at a fixed position inside the brute
  sequence and confirm it still authenticates once the loop reaches it under
  load -- if the correct value stops working mid-burst while status codes
  look unchanged, the endpoint is silently dropping/throttling rather than
  genuinely unprotected.

### OAuth: redirect_uri parser-differential bypass & token-confusion classes

- **`redirect_uri` prefix-match parser differential**: a server-side
  `startswith()` check against a registered prefix is necessary but not
  sufficient -- the WHATWG URL parser used by every modern browser only
  treats `@` as the userinfo delimiter before the first `/` after `://`, so
  the server's check and the browser's actual navigation can disagree:

  | Registered prefix | Attack URL | Server `startswith()` | Browser's actual host | Exploitable? |
  |---|---|---|---|---|
  | `https://acme.example` (no trailing slash) | `https://acme.example@evil.com/cb` | passes | `evil.com` | Yes |
  | `https://acme.example/` (trailing slash) | `https://acme.example/@evil.com/cb` | passes | `acme.example` (`@` now falls inside the path) | No |
  | `https://acme.example` (substring match) | `https://acme.example.evil.com/cb` | passes | `acme.example.evil.com` | Yes |

  Always confirm the real browser navigation (headless test) before writing
  this up as a token-theft chain -- a server-side accept that the browser
  doesn't actually follow cross-origin is not exploitable.
- **nOAuth**: cross-IdP account takeover via an unverified, mutable `email`
  claim -- attacker changes their own IdP-side profile email to the
  victim's address, then logs in via that IdP on a relying party that keys
  accounts by the email claim alone, landing directly in the victim's
  account.
- **Pass-The-Token**: the relying party resolves identity by calling the
  IdP's `/me`-style endpoint with a bearer token but never checks that the
  token's `aud`/`app_id` belongs to that RP -- an attacker who obtains any
  valid access token from the same IdP (issued for a different,
  attacker-controlled client) replays it against the RP's login API and is
  issued a session for whatever identity the token resolves to.

### SAML: XSW1-XSW8 variants

Beyond the classic XSW1 (duplicate-assertion injection), these variants
target specific signature-binding implementations (Fedotkin's 2025
parser-differential research):

| Variant | Technique | Bypasses |
|---------|-----------|----------|
| XSW2 | Move `<ds:Signature>` inside a child element of the evil assertion | Libraries verifying signature position relative to root |
| XSW3 | Split the assertion across XML-comment boundaries in the reference URI | Libraries using URI-fragment matching |
| XSW4 | Inject a second `AssertionIDRef`/`AuthnStatement` inside the signed assertion | Libraries processing all statements, not just the first |
| XSW5 | Reuse the signed reference's `ID`/`xml:id` on the injected assertion | Libraries matching by ID string, not DOM position |
| XSW6 | Namespace-prefix injection -- alias the SAML namespace so the injected assertion uses a different prefix but the same namespace | Libraries keying on prefix string |
| XSW7 | XXE inside the signature-reference URI to poison the digest check | Libraries resolving entities during signature validation |
| XSW8 | XSLT transform injection in `<ds:Transform>` -- transforms the post-signature DOM | Libraries applying transforms after verification |

### Session: refresh-token rotation and DBSC downgrade

- **Refresh-token rotation & reuse-detection (OAuth BCP)**: rotate a
  captured refresh token once via the refresh endpoint, then replay the
  original pre-rotation token -- correct behavior per the OAuth Security
  BCP is to invalidate the entire token family on reuse. If the replayed
  token still mints a new access token, or the freshly-rotated token still
  works after the replay, a single leaked refresh token grants indefinite
  re-authentication that survives a password change.
- **DBSC downgrade**: where responses carry
  `Sec-Session-Registration`/`Sec-Session-Id` (Device Bound Session
  Credentials), strip the device-bound proof and replay the bare session
  cookie alone -- if the server still accepts it, device binding is
  advisory rather than enforced and a stolen cookie defeats DBSC entirely.

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
- **Response manipulation**: submit a wrong OTP, capture the response in
  the proxy, flip `{"success":false}` -> `{"success":true}` (or the HTTP
  status `401` -> `200`) and forward it -- if the app proceeds to the
  post-MFA state anyway, the check is client-side only and MFA is
  decorative.
- **SSO/`amr`-claim bypass**: SP-initiated SSO can skip MFA even when the
  IdP normally enforces it, if the SP trusts the assertion/token without
  checking that MFA actually happened for *this* session. Decode the
  issued SAML `AuthnContextClassRef` or the OIDC ID token's `amr` claim:
  ```bash
  for t in captured_tokens.txt; do
    echo "$t" | cut -d. -f2 | base64 -d | jq '.amr, .acr, .auth_time'
  done
  ```
  If the SP grants access without an `"mfa"`/expected AuthnContext value
  present, strip the MFA params from an SP-initiated request and forward
  the resulting assertion/token directly to confirm the SP never actually
  re-checks it.
- **Biometric MFA replay**: where a biometric match result (a signed
  token, or a bare `"biometric_verified": true` boolean) is sent to the
  server rather than verified server-side against a fresh challenge,
  capture that result and replay it in a new session/device -- if it's
  accepted without a nonce/timestamp/device-binding check, the "biometric
  verification" is just a replayable static assertion. Check the result
  token's claims for `iat`/`jti`; their absence is the tell.

### Legacy-Protocol Matrix (probe first on any custom-branded login)

Generalizes the WordPress-XMLRPC-bypassing-SSO pattern (an old, unbranded
protocol endpoint that still accepts native credentials with no
MFA/rate-limit/CAPTCHA, even when the branded UI in front of it has all
three) across other platforms -- when a target has a custom-branded login
(`customlogin.aspx`, `/auth/signin`), always probe the platform's legacy
endpoints in parallel with the branded flow:

| Target tech | Legacy endpoint(s) | Native-cred bypass surface |
|---|---|---|
| WordPress | `/xmlrpc.php` (`system.multicall`), `/wp-json/wp/v2/users` | Bypasses SSO/MFA/IP-allow on `/wp-login.php` entirely |
| SharePoint | `/_vti_bin/Authentication.asmx` (`Mode`+`Login` SOAP) | Native Forms-auth cred, FedAuth cookie issued, often no rate limit -- the direct SP equivalent of WP XMLRPC |
| Atlassian (Jira/Confluence) | `/rest/auth/1/session` (basic-auth) | Native creds accepted even when Crowd/Atlassian Access SSO gates the UI |
| Exchange/OWA | `/EWS/Exchange.asmx`, `/Microsoft-Server-ActiveSync` | NTLM/Basic bypassing OWA's MFA/IP-allow wrapper |
| Citrix NetScaler | `/cgi/login`, `/nf/auth/doAuthentication.do` | Native AD creds independent of MFA wrapper |
| Spring Boot | `/actuator/*`, `/api/v1/auth/login` | Actuator endpoints sometimes anonymously enumerable |
| Jenkins | `/script`, `/computer/(master)/script` | API tokens + native auth, bypassing SSO plugin |
| GitLab | `/api/v4/users`, `/api/v4/projects` | PATs with looser scoping than the UI session |
| Apache Tomcat | `/manager/html`, `/host-manager/html` | Native realm creds independent of any front auth |

**How to use**: fingerprint the tech stack, find the matching row, probe
the legacy endpoint anonymously to confirm it's reachable, then confirm
it accepts native credentials with no rate limit/lockout (burst several
attempts, check for uniform timing/status). A reachable, anonymous,
unlimited native-credential endpoint sitting behind an SSO-branded UI is
consistently Critical/High -- it's the same underlying gap every time:
MFA/SSO enforcement applied at one auth surface while a legacy path
retains independent, weaker credential validation.
