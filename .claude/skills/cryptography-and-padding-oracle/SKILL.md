---
name: cryptography-and-padding-oracle
description: Weak-crypto testing checklist -- CBC padding oracle attacks, ECB mode detection, predictable/reused IVs, hardcoded keys, weak password hashing, CBC bit-flipping, encrypted-ID-based IDOR, and timing side-channels in token comparison. Converted from master-pentest-prompt.md Phase 24, explicitly flagged in the source as never-skip. Use on any encrypted value the client can see or control -- cookies, ViewState, encrypted IDs, tokens.
---

# Cryptography & padding oracle (weak crypto -- never skip)

## When to use

Any encrypted value that reaches the client: cookies, ASP.NET ViewState,
encrypted IDs used as object references, password-reset tokens,
encrypted SAML assertions. This is a genuinely never-skip class -- weak
crypto is common and often trivially exploitable once found.

## CBC padding oracle

Any encrypted value in a cookie or parameter (ASP.NET ViewState, Java,
.NET, PHP `mcrypt`) is worth testing for a padding oracle -- bit-flipping
attacks can decrypt or modify the value without knowing the key. Tools:
`padbuster`, `python-paddingoracle`. Test whether modifying the last
block's final byte produces a distinguishable "padding error" response
(a 500 vs. 200 vs. a custom error message all count as a usable oracle).

## ECB detection

Encrypt (or observe encryption of) the same block of plaintext twice --
identical ciphertext blocks confirm ECB mode, which leaks plaintext
patterns and allows block reordering/substitution attacks.

## Other crypto weaknesses

- **Weak JWT crypto**: HS256/RS256 confusion, `alg: none` -- see the
  `auth-and-session` skill's JWT section for the full technique list;
  this is the same underlying weakness viewed from the crypto side.
- **Predictable / fixed / reused IV**.
- **Hardcoded crypto material**: AES keys, salts, or pepper values
  embedded in JS or config files -- `secrets-mcp` can catch these during
  the local-file scanning pass.
- **Weak hashing**: MD5/SHA1 used for password storage instead of
  bcrypt/argon2/scrypt, or a correct algorithm used with too low a cost
  factor.
- **CBC bit-flipping on serialized objects**: flipping bits in an
  encrypted serialized blob to change a field (e.g. a privilege level)
  without needing to decrypt it first.
- **Encryption confusion / encrypted IDOR**: client-side "encrypted" IDs
  that turn out to be predictable, derivable from other data, or simply
  replayable across accounts -- encryption isn't authorization, and an ID
  being opaque-looking doesn't mean it's actually protected.
- **Padding oracles beyond cookies**: XML encryption, encrypted SAML
  assertions, and encrypted password-reset tokens can all carry the same
  CBC padding oracle weakness as a cookie.
- **Timing leaks**: a token/secret comparison that isn't constant-time
  can leak the correct value byte-by-byte through response timing.
