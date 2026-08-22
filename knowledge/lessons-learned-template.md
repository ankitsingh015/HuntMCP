# Lessons Learned — Confirmed-Finding Registry (Self-Improving)

> **This is a TEMPLATE, not a real registry.** Copy it to `chat-logs/lessons-learned.md`
> (gitignored — see `.gitignore`) and start filling it in with YOUR real, authorized
> engagements. Never commit the filled-in file to this or any repo: it will contain
> real target names, real findings, and possibly client-confidential/NDA'd data.
> Point `HUNTMCP_LESSONS_PATH` at an existing file (e.g. one you already maintain
> outside this repo) instead of duplicating it here if you already have one.
>
> **Purpose:** HuntBrain reads this file at the START of every engagement (Phase 0.8
> of `master-pentest-prompt.md`) and maps each technique onto the live target. After
> EVERY confirmed bug (and every triager-closed false positive) a new block is
> appended, so the methodology improves engagement over engagement.
>
> **CONTEXT CAP (compaction):** cap this file at ~400 lines. When it exceeds the cap,
> move the oldest/duplicate entries to `chat-logs/lessons-archive-<YYYY>.md` (keep
> only top recurring techniques + newest confirmations here) so it stays cheap for
> any model to load. Archive first, never just keep appending — nothing is ever
> deleted, only moved.
>
> **Format of each entry:**
> `VULN | CWE | target | method-that-found-it | key request/payload |
> impact chain | bypasses | result (paid/confirmed/closed-FP)`
>
> **Severity honesty rule:** record the REAL severity a strict triager would assign
> — never inflate LOW to MEDIUM. A finding that would be closed as N/A is still
> worth recording as a *method* (it may hit harder on another target), but its
> severity stays honest.

---

## Class 1 — Debug mode / verbose 500 leaks (example)

- **Framework debug mode ON → stack trace + source + SQL bindings**
  CWE-209/CWE-200 | example-corp.com (2026-01-01, HIGH F-01)
  Method: trigger 500s (empty payloads, invalid types, extra params) → framework
  debug page leaked source file paths, DB schema, SQL bindings. Impact chain:
  recon → env/secret hunting → RCE precondition. Result: CONFIRMED HIGH.

**Rules learned:** always force 500s early; harvest and FOLLOW every leaked
secret; trigger with malformed types not just empty values.

## Class 3 — IDOR / broken object-level authz on sequential IDs (example)

- **Financial-endpoint IDOR → PII exposure**
  CWE-639/CWE-359 | example-corp.com (2026-01-01, CRITICAL F-07)
  Method: two-account sweep; `GET /user/payout/show/{id}` with attacker session
  over sequential IDs → records from other users. Works from ANY authenticated
  account (reproduced on a second account). Result: CONFIRMED.
- **One IDOR implies the family:** always enumerate every resource route with
  `{id}` after the first hit.

**Rules learned:** after the FIRST IDOR, expand horizontally to every
`/show/{id}` `/store/{id}` `/edit/{id}` route; financial endpoints are highest
payout; reproduce from a SECOND account to prove any-logged-in-user impact.

---

## TOOLS / SCRIPTS (toolchain advancement — appended every engagement)

> Write every tool/one-liner that worked here, so the toolchain grows
> engagement over engagement.

- **example_recon.py** — describe what it automates and where it came from.

---

## Open items (hunt these next — your remaining threads)

1. (per-target next actions go here)

---

*Append after every engagement. Keep it raw and specific — a one-line exact
payload beats a paragraph of theory. This file + `knowledge/master-pentest-prompt.md`
are the workstation's accumulated methodology.*
