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
