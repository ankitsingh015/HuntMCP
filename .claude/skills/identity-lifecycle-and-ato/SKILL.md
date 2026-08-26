---
name: identity-lifecycle-and-ato
description: Account-takeover techniques targeting the full identity lifecycle -- signup/verification bypass, email-change races, OAuth unlink/relink takeover, username collision via unicode/case normalization, role persistence in stale JWTs, orphaned-account reactivation, and session-invalidation gaps after sensitive changes. Converted from master-pentest-prompt.md Phase 26. Use on signup, account-settings, and account-merge/link flows specifically -- these are usually tested less than login itself.
---

# Identity management & user lifecycle ATO

## When to use

Signup flows, account-settings pages (email/phone/password change), and
any account-merge or OAuth-link/unlink feature -- these get far less
adversarial testing than the login form itself, which is exactly why
they're worth deliberate attention.

## Signup and verification

- Signup that auto-logs-in without email verification lets an attacker
  claim any username immediately; test requesting signup with an
  unregistered or *someone else's* email address to see what happens.
- **Email change flow**: request an email change, then replay the old
  session token afterward; test racing an email change against a
  password reset; check whether the old password is required to confirm
  the change at all.
- **Account merge/link**: unlinking an OAuth provider and relinking to an
  attacker-controlled OAuth account can be a full account takeover if the
  merge logic trusts the new provider's claims without re-verifying
  identity. Also test merging two accounts for a user-enumeration signal
  in the error message.
- **Phone change / MFA removal** without OTP re-verification of the
  *current* factor.

## Identity confusion

- **Username collision**: unicode normalization (NFKC) can make visually
  distinct usernames collide (`admin` vs. `admi­n` with an invisible
  soft-hyphen), and case-insensitive database collation (common in MySQL)
  can let a second `ADMIN` account be created with the same effective
  identity as an existing `admin`.
- **Role/privilege via profile update**: mass-assigning a `role`/
  `permissions` field through a profile-update endpoint (see the
  `access-control-and-idor` skill), especially where the role is embedded
  in a JWT that isn't re-checked against the current server-side value on
  every request -- a stale but still-valid token can carry a privilege
  level the server already revoked.
- **Orphan/soft-deleted account reactivation**: whether a "deleted"
  account can be reactivated by an attacker who knows (or brute-forces)
  its identifier.

## PKCE downgrade / bypass chain

PKCE (RFC 7636) protects the authorization-code flow for public clients,
but many implementations only *support* it rather than *enforce* it. Four
named variants, roughly in order of how often they show up:

- **No enforcement at all**: request the auth code without `code_challenge`,
  then exchange it without `code_verifier`. If the server issues a token
  anyway, PKCE is decorative and the flow degrades to the traditional
  authorization-code interception attack it was meant to close.
- **`code_challenge_method=plain` accepted**: the challenge should be a
  SHA-256 hash (`S256`); if `plain` is also accepted, the "hash" is just the
  verifier in cleartext on the authorize request, giving an on-path
  attacker everything needed to complete the exchange.
- **`code_verifier` sent but not actually validated**: the auth request
  carries a real `S256` challenge, but the token endpoint issues a token
  even when the exchange omits `code_verifier` or sends the wrong one --
  the challenge was stored but never checked against the exchange.
- **Authorization code replay after a successful PKCE exchange**: some
  servers expire the code on time but not on use, so the same code +
  verifier pair succeeds a second time.

Test with the auth-code/verifier pair blank, swapped, and mismatched in
turn; the finding is confirmed when a token comes back on a request that
should have been rejected for a missing or wrong verifier.

## Azure AD cross-tenant ATO

Two chained techniques against multi-tenant Azure AD / Entra ID apps:

- **`prompt=none` as an existence oracle**: `GET
  /oauth/authorize?...&prompt=none&login_hint=victim@victim-tenant.com`
  skips the interactive login UI. If the victim has an existing session,
  the app silently receives a code; if not, the authorization server
  returns `error=login_required` rather than a generic failure -- either
  response confirms the email exists in the target tenant, giving a
  silent, unauthenticated user-enumeration oracle with no interaction from
  the victim.
- **Tenant-replay to complete takeover**: register the same `client_id` in
  an attacker-controlled tenant, authenticate as an attacker-owned user
  there to obtain a valid access token, then replay that token against the
  victim tenant's API. If the app validates the token's signature and
  audience but not its `tid` (tenant ID) claim, the token is accepted as
  if it belonged to a victim-tenant user -- completing the takeover once
  the oracle step has confirmed a target account exists.

## Session hygiene across identity changes

Explicitly check whether existing sessions are killed on: email change,
password change, role change, MFA enable/disable, and device removal. A
missing invalidation on any of these means a stolen session survives the
exact security action meant to cut it off.

## Aggregate user enumeration

Cross-check every surface that can leak whether an account exists: the
signup page's error message, the login error, the password-reset
response, an `/api/users`-style existence check, timing differences
between valid/invalid accounts, and differing cookie flags set depending
on account state.
