# P4-M1 — Full invariant model (design)

**Date:** 2026-11-16
**Status:** DRAFT — awaiting human approval
**Tracker row:** P4-M1 (`IMPLEMENTATION-TASK-TRACKER.md` §6), `[!]` → `[~]` on GO.
**Scope decision (human, 2026-11-16):** **B — "real + deeper."**
**Prereq satisfied:** P4-M0 GO/NO-GO → **GO** (human, 2026-11-16). To be recorded in tracker §8.

---

## 1. Intent and why

P4-M0 built `mcp-servers/invariant_probe.py`: a shallow, high-recall passive miner (two
templates — T1 ownership/horizontal-authz, T2 one-time-use/replay) that expresses each mined
candidate as a **hypothesis the FROZEN Phase-1 CEM counterfactual must falsify**, never an
asserted fact. It proved, on a blind benchmark through the real `run_cem_pipeline`, that the
probe→CEM pipeline confirms a class-less one-time-use violation and **rejects** the canonical
public/shared false positive at **FCC==0**. It was measured and recommended **GO**.

But P4-M0 is only a module with a **measurement scaffold**: nothing builds the observed corpus,
candidates run against a synthesized `invariant.local` URL (not a real captured request), and
there is no MCP/agent entry point. P4-M0 explicitly deferred three things to P4-M1:

(a) the full **actor→action→object→state-transition** model (beyond the two shallow templates);
(b) **production runnability** — mapping an opaque mined `resource` to a **real captured request**;
(c) **MCP/agent wiring**.

P4-M1 ships those so the invariant model actually runs during a hunt and stays trustworthy.

## 2. Goals

1. **Real corpus builder** — assemble the `{identity, resource, action, args, status, body,
   session}` exchange corpus `mine_invariants()` consumes from **already-captured** hunt data,
   with no new probing of the target.
2. **Real-request mapping (production runnability)** — a mined candidate's `base_request` is a
   **real captured request** (real URL/method/headers/param) that `run_cem_pipeline` can fire at
   the actual target, replacing the `invariant.local` scaffold.
3. **Deeper model** — an explicit actor→action→object→state-transition representation plus **two
   new invariant templates** (T3 vertical-privilege/role, T4 state-gated-parameter), each still a
   **frozen-CEM-provable** droppable-condition hypothesis.
4. **MCP + agent wiring** — one read-only mining/staging tool, and an exploit-agent instruction
   for when to mine invariants and feed survivors to the existing gated CEM run.
5. **Blind benchmark at FCC==0** — extend the protected invariant benchmark with blind scenarios
   and decoys for T3/T4; prove quality floor held and zero confirmed false invariants after the
   CEM gate.

## 3. Non-goals

- **Touching frozen CEM.** `cem_engine.py`, `test_cem_benchmark.py`, `tests/fixtures/cem_target/`,
  and the CEM schema stay byte-identical. `verify-phase1.sh` G1–G9 must still PASS.
- **A learned / auto-inferred state-machine engine** (Approach C). Rejected here — see §5.
- **New vuln detection outside the droppable-condition model.** Any invariant whose hypothesis
  cannot be reduced to a frozen-CEM perturbation is out of scope (see constraint C1).
- **New runtime dependency.** stdlib + existing modules only.
- **Autonomous CEM condition extraction** (that is P4-VALCOND, DEFERRED) — the oracle/conditions
  stay agent/operator-supplied (UD-3), same as P3-CEMHUNT.
- **Auto-confirming or auto-reporting invariants.** Candidates enter at `DISCOVERED`; CEM entry
  stays gated on the normal independent-validation → `CONFIRMED` flow; human-review-before-submit
  preserved.

## 4. Anti-goals (failure even if it "works")

- Emitting a candidate the frozen CEM **cannot** falsify — the "confident false invariant /
  garbage-in-for-CEM" mode P4-M0 exists to prevent. **Any new template that can produce a
  non-CEM-provable hypothesis is a design failure, not a feature.**
- Any increase in confirmed false necessity on the benchmark (FCC > 0).
- A corpus builder that issues a single new request to the target (it must be purely passive over
  captured data).
- Silently changing protected-benchmark ground truth to make the implementation pass.

## 5. Approaches considered

- **A — "make it real" (minimal):** goals 1, 2, 4 only; keep P4-M0's two templates. Smallest, ships
  the capability end-to-end and provably safe, but adds no new detection.
- **B — "real + deeper" (CHOSEN):** A plus goal 3 — a state-transition representation and two new
  templates, each still CEM-provable, blind-benchmarked. More FP surface to prove clean, bigger
  build, more benchmark scenarios; in exchange, the model detects authz/state invariants the two
  shallow templates miss while holding FCC==0.
- **C — full learned state-machine engine:** auto-infer the state machine from the corpus. Rejected:
  this is exactly the high-FP speculative build the UU research says "survives only if gated behind
  a measured shallow prototype," and §13 prefers simple/verifiable over speculative architecture. If
  ever wanted, it is a separate GO behind P4-M1's own measurement.

## 6. Constraints (the design rules)

- **C1 — Frozen-CEM provability is absolute.** Every emitted candidate's `cem_spec` MUST be runnable
  by the unchanged `run_cem_pipeline`: a `base_request` (GET/HEAD/OPTIONS by default), a
  `success_signature` oracle, and one or more conditions each perturbed by `{"drop": true}` on a
  **request param or header**. The state-transition model may enrich **candidate formation and
  confidence**, but the hypothesis handed to CEM always reduces to a droppable-condition test. A
  state/sequence precondition that is not expressible as a droppable param is **not** emitted as a
  CEM candidate (it may be surfaced as advisory context only, never as a confirmed invariant).
- **C2 — Passive only.** Corpus builder reads captured data; zero new target traffic. The only
  network path is the existing, already-gated `run_cem_pipeline`.
- **C3 — Status discipline.** Mined candidates are `DISCOVERED`. CEM entry stays gated on the
  existing CONFIRMED precondition + determinism gate; this task adds no CEM logic and no new
  request path of its own (same posture as P3-CEMHUNT).
- **C4 — Scope / budget / audit preserved.** All target-touching runs go through the existing
  `run_cem_pipeline`, so scope_guard, per-finding + engagement budget, and audit apply unchanged.
- **C5 — Protected-benchmark change = human approval.** Extending `lh_target.py` / `inv_answer_key.py`
  with new scenarios and re-locking the SHA-256 integrity locks is a protected-benchmark-methodology
  change (`.claude/rules/benchmarks.md`). Approving this doc authorizes the specific scenarios named
  in §8; the re-lock is recorded, not silent. Blindness held: the probe never imports the key.
- **C6 — S6 hook-protected files.** The read-only mining tool has **no `url` param** (like
  `find_resurrectable_hypotheses`), so it is **not** Tier-2 gated and needs **no**
  `scope_gate_hook.py` edit. If review concludes it must be hook-registered anyway, that edit
  requires a human-run `scripts/confirm-hook-edit.sh` and is called out, not done silently.

## 7. The design (what gets built)

### 7.1 Corpus builder — `invariant_corpus.py` (new, read-only)
Pure functions that assemble the exchange corpus from captured data, no network/fs-write/randomness:
- **Body + identity source:** `case_store` wire evidence (content-addressed `add_evidence` /
  `fetch_with_provenance` records) — this is where real response bodies and the issuing identity
  live. (Confirmed: `burp_db` stores **no** response body, only request metadata + headers.)
- **Request-skeleton source:** `burp-import-mcp` endpoints (`list_endpoints`/`get_endpoint_detail`)
  supply the real URL/method/headers used to reconstruct a runnable `base_request`.
- **`identity`** derived from the session cookie / `Authorization` header present on the exchange
  (hashed/labelled, never stored raw — reuse existing redaction).
- **`resource`** = the object-instance path (honours P4-M0's instance-scoping contract; collection
  templates stay low-confidence via the existing negative control).
- Each corpus row gains an optional **`base_request`** field (the real captured request) so
  `to_cem_hypothesis` uses a real request instead of synthesizing `invariant.local`.
- Degrades to `[]` on any missing/malformed source; never raises into the hunt.

### 7.2 State-transition representation + new templates — extend `invariant_probe.py`
- A lightweight per-`(resource, session)` **ordered action sequence** (`actor, action, status,
  body-state-class`) built from the corpus — the "state machine" is observable response-class
  deltas, not an inferred automaton.
- **T3 — vertical-privilege / role invariant:** a privileged action succeeds for a lower-privilege
  identity (identity/role differs, 2xx+content, no denial for the low-priv actor where a legitimate
  gate would deny). Candidate condition = the role/credential header → `{"drop": true}`. CEM-provable.
- **T4 — state-gated-parameter invariant:** within a `(resource, session)` sequence, an action
  succeeds while carrying a parameter/token the state machine identifies as the gate that *should*
  authorize the transition (e.g. a carried authorization/nonce/ownership param). Candidate condition
  = that param → `{"drop": true}`. CEM then tells us whether the param was actually necessary.
  CEM-provable by construction.
- Both keep P4-M0's high-recall + negative-control-confidence posture; the CEM gate is the precision.
- `mine_invariants()` returns T1+T2+T3+T4 candidates; `to_cem_hypothesis()` unchanged except it uses
  a row's real `base_request` when present.

### 7.3 MCP + agent wiring
- **Tool:** `mine_invariants` exposed on `case-mcp` (read-only, offline, no `url`): builds the corpus
  via `invariant_corpus`, mines candidates, and **stages** survivors as `DISCOVERED` findings +
  hypotheses via the existing `to_cem_hypothesis` path. Returns the staged `{finding_id, …,
  confidence, cem_spec}` list. It never runs CEM and never advances status.
- **Agent:** an `exploit-agent.md` step (sibling of the P3-CEMHUNT step 3.5) — after independent
  validation, mine invariants from the captured corpus, and for each survivor that reaches
  `CONFIRMED` through the normal flow, run the existing gated `run_cem_pipeline`. Explicit skip rules
  (state-changing steps, path-segment/IDOR-only, OOB/browser-proof) mirror the existing CEM guidance.

### 7.4 Benchmark extension (protected — needs approval per C5)
- Add blind scenarios to the long-horizon simulator for a **T3** violation (privileged action leaks
  to a low-priv identity; class-scannable split noted) and a **T4** violation (state-gated param not
  actually enforced — class-less, the differential-value case), plus **secured decoys** shaped like
  each (the role-gate denies; the param-gate enforces) so a candidate there is a false invariant the
  CEM gate must reject.
- Extend `inv_answer_key.py` (evaluator-only) with the new opaque ids; re-lock all SHA-256 locks
  (human-approved). Measurement extends `test_invariant_probe_pipeline.py`: through frozen CEM, the
  two new real violations are CONFIRMED-necessary and both decoys REJECTED → **0 confirmed false
  invariants, FCC==0**, with the real-request-mapping path exercised (not `invariant.local`).

## 8. Acceptance (maps to tracker §10 "P4-M1")
- Unit tests for `invariant_corpus` (source parsing, identity derivation, degrade-to-empty) and the
  T3/T4 templates + state-transition builder.
- Blind-benchmark pipeline run: T3+T4 violations confirmed, all decoys rejected, **FCC==0**, quality
  floor held (no regression in T1/T2 behaviour), real-request mapping exercised.
- `verify-phase1.sh` G1–G9 PASS (frozen CEM untouched); full regression green.
- Review+audit (`/code-review` + `/security-review`) clean or findings fixed; **prove-it-runs**:
  the real `mine_invariants` tool over an isolated temp `case.db` + captured-corpus fixture →
  staged `DISCOVERED` candidates with real `base_request`s, and the pipeline benchmark at FCC==0.

## 9. What's left to the builder
- Exact identity-label/redaction reuse from existing helpers.
- The precise body-state-class bucketing for the sequence representation (keep it observable, not
  inferred).
- Whether T4's "gate param" detection needs a small allow-list of known gate-param name shapes vs. a
  purely structural signal — builder's call, kept conservative (high-recall, CEM is precision).
- Final opaque scenario ids / fixture mechanics, following the existing `lh_target`/`inv_*` patterns.
