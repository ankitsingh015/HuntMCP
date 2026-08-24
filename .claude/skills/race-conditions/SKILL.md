---
name: race-conditions
description: Race-condition / TOCTOU testing methodology -- the single-packet attack (last-byte sync) for minimizing network jitter, classic parallel-request racing, TOCTOU on non-identical request pairs, limit-overrun testing on withdrawals/coupons/OTP attempts, and state-transition races on single-allocation resources. Converted from master-pentest-prompt.md Phase 40 (new -- not in the original 59-phase set, added from research into currently-uncovered high-value bounty classes). Use on any endpoint touching a limited resource -- balance, coupon, inventory, vote, referral bonus, rate-limited action, one-time token.
---

# Race conditions / TOCTOU

## When to use

Any endpoint involving a limited resource: balance, coupon, inventory,
vote, referral bonus, a rate-limited action, or a one-time token.
Distinct from the business-logic checks in the `autonomous-research-loops`
skill's Loop F, which cover the *outcome* patterns (negative price,
coupon abuse) — this skill covers the *mechanism* that makes those
outcomes achievable through concurrency, applicable well beyond just
those examples.

## Single-packet attack (last-byte sync)

Send N identical requests with all but the final byte already
transmitted, then release the final byte for all N connections as close
to simultaneously as possible. This minimizes network jitter between
requests far more effectively than naive parallel `curl`/threading, and
is the current state-of-the-art technique for reliably triggering true
race windows — see PortSwigger's race-condition research for the
reference implementation via Burp's Turbo Intruder. Reach for this when
naive parallel requests fail to reproduce a suspected race.

## Classic parallel-request race

20-50 concurrent identical requests against the same endpoint — coupon
redemption, balance transfer, vote/like, referral-bonus claim,
password-reset-token consumption. A naive but often still-effective
first pass before reaching for single-packet tooling; worth trying first
since it requires no special tooling.

## TOCTOU (time-of-check to time-of-use)

A check (is the balance sufficient? is the slot available? has this
already been redeemed?) and its corresponding use (deduct/consume/
redeem) that aren't atomic — the gap between them is the race window.
This does not require identical requests: two *different* requests
hitting the same underlying resource can race just as effectively (e.g.
one request reading a balance while a separate request is mid-transfer
against that same balance).

## Limit-overrun testing

Apply specifically to: withdrawal/transfer limits, one-time discount
codes, single-use invite links, account-creation rate limits, and
OTP/2FA attempt counters. Any place a limit is enforced via a
check-then-act pattern instead of an atomic decrement is a candidate.

## State-transition races

Two requests attempting to move the same resource through conflicting
state transitions simultaneously — both attempting to claim the "last"
seat/item, both attempting to redeem the same one-time link. Look for
the resource ending up in an impossible or double-allocated state as the
tell.

## Evidence to capture

Exact timestamps of each request, the response showing the resource was
granted or consumed more times than should have been possible, and
(where visible) the final state showing the overrun. Race conditions are
otherwise easy for a reviewer to dismiss as non-reproducible, so document
reproduction steps precisely — exact concurrency tooling used, exact
timing, exact before/after state.
