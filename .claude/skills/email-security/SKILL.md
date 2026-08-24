---
name: email-security
description: Email-domain security checklist -- SPF/DMARC/DKIM misconfiguration detection, open-relay/contact-form spoofing, ARC laundering, and third-party mail-gateway SPF re-evaluation gaps. Converted from master-pentest-prompt.md Phase 16, explicitly flagged in the source as the most-skipped phase -- do not skip it.
---

# Email security (most skipped -- do not skip)

## When to use

Every engagement, once the target's mail-sending domain is known. This
is explicitly called out in the source material as commonly skipped
despite being high-yield, especially when the domain sends
password-reset or invoice emails.

## SPF

`dig TXT <domain>`. Missing entirely? Ends in `+all` (explicitly allows
anyone)? `~all` (soft fail) instead of `-all` (hard fail)? More than 10
DNS lookups (SPF permerror, effectively disables the check)?

## DMARC

Missing entirely, `p=none` (monitor-only, doesn't actually block
spoofing), or `p=quarantine` (weaker than `p=reject`) all mean the domain
is spoofable to varying degrees. No `rua`/`ruf` reporting addresses means
the domain owner is blind to abuse even if a policy exists.

## DKIM

Are selectors present? Is mail actually signed? Shared ESP selectors
(`s1`/`s2` for SendGrid, `k2`/`k3` for Mailchimp) can mean an arbitrary
`From:` spoof still passes DKIM/DMARC alignment if the ESP's shared
signing key covers domains beyond the target's own.

## Other checks

- **Open relay probe**: test whether the mail server or a contact form
  can be abused as an arbitrary-recipient spam relay.
- **ARC laundering**: forwarded mail can carry `dmarc=pass` from the
  forwarding step even when the original message wouldn't have passed --
  check whether ARC headers are being trusted uncritically.
- **Third-party gateway SPF re-evaluation**: when MX points to a
  third-party gateway (Barracuda/Proofpoint) with early-failure-checking
  (EFC) off, SPF gets re-evaluated against the *gateway's* IP rather than
  the true sender's, which can let an attacker's mail pass SPF simply by
  routing through the same gateway.

## Impact framing

Report spoofability as critical when the domain sends password-reset
links or invoices -- a spoofable domain turns those flows into a
phishing/fraud vector, not just a hygiene finding.
