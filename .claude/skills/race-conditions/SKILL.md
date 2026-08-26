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

**The mechanism, not just the technique name**: HTTP/2 multiplexes many
requests over one TCP connection as HEADERS/DATA frames per stream.
Pre-stage N requests by sending each one's HEADERS frame plus all but the
final byte of its DATA frame — withholding `END_STREAM` so the server
can't dispatch yet. Then release all N final bytes (each carrying
`END_STREAM`) in a single TCP write; TCP coalesces them into one IP
packet, so the server's HTTP/2 parser sees all N streams complete in the
same scheduler tick. This collapses the race window from network jitter
(0.5–5 ms over a real connection) down to the application's own
atomicity gap — often sub-millisecond. Confirm true single-packet
delivery with a packet capture (`tcpdump`/Wireshark): all N
`END_STREAM`-bearing DATA frames should land in one TLS record/TCP
segment, not spread across several — Turbo Intruder's `engine=Engine.BURP2`
is the reference implementation. Estimate the race window first (compare
single-request timing against two-concurrent timing) before committing to
a full attack — an endpoint with genuine row-level locking won't race no
matter how tight the delivery.

Kettle's single-packet attack caps around N=30 concurrent requests per
connection (MTU + TLS record limits on one TCP stream). Flatt Security's
2024 "first-sequence-sync" extension lifts this ceiling by opening
multiple TCP connections and synchronizing their TCP sequence numbers so
IP fragments from all connections land at the server in the same
processing window — demonstrated at 10,000 concurrent requests delivered
in 166 ms. Reach for this specifically when the race needs N > 30, such
as brute-forcing a short numeric PIN/OTP within a tight per-window
attempt cap (e.g. a 6-digit PIN against a 5-attempt rate limit), where 30
concurrent guesses isn't enough coverage per window.

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

## Precedent

- **GitLab CVE-2022-4037** — concurrent email-change requests raced
  Devise's (Rails) confirmation-token generation against email
  persistence; the token sent to address A became valid for address B
  because the state transition wasn't atomic. This is Kettle's flagship
  "Smashing the State Machine" case study for single-packet exploitation.
- **nopCommerce CVE-2024-58248** — two parallel `PlaceOrder` requests both
  applying the same gift card completed as separate orders while the gift
  card balance was debited only once; checkout's gift-card balance
  check-then-debit had no row-level lock.

## Evidence to capture

Exact timestamps of each request, the response showing the resource was
granted or consumed more times than should have been possible, and
(where visible) the final state showing the overrun. Race conditions are
otherwise easy for a reviewer to dismiss as non-reproducible, so document
reproduction steps precisely — exact concurrency tooling used, exact
timing, exact before/after state.
