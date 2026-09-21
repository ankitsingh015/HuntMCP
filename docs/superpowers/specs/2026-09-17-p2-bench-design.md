# P2-BENCH — Benchmark + Telemetry Substrate: Design Spec

**Status:** Approved design, not yet implemented.
**Roadmap authority:** `MASTER-ROADMAP-FINAL-v3.md` §4 ("Benchmark + telemetry substrate | COMMITTED | 2 | P1"),
§5 (Phase 2), §11 (Measurement & Promotion Gates), §11-A (Quality Floor vs Absolute Security Invariants).
**Task tracker row:** `IMPLEMENTATION-TASK-TRACKER.md` §4, `P2-BENCH`.
**Governing rule file:** `.claude/rules/benchmarks.md` (protected benchmark principle, ground truth independence,
oracle integrity, blindness, quality gates, benchmark-change discipline, reproducibility).

---

## 1. Non-negotiable principles (apply to every section below, no exceptions)

1. **The benchmark is a measurement instrument only — never a capability ceiling.** Nothing in this design gates,
   filters, narrows, or otherwise restricts what tools, techniques, payload strategies, hypotheses, or vulnerability
   classes a real HuntMCP hunt may use, on this target or any other.
2. **Real hunts stay free to use any approach, including novel/unplanted findings.** The benchmark never tells a
   hunt what to look for, and never treats "not one of the 6 planted classes" as wrong.
3. **The initial range has 6 classes; the architecture must not need restructuring to add more.** SSRF, command
   injection, auth bypass beyond IDOR, and multi-step/stateful business-logic cases (needed later by VAL-AUTHZ) are
   explicitly anticipated additions, not hypothetical ones.
4. **The tool↔class mapping (§3) exists only to prove, at fixture build time, that each planted bug is real and
   genuinely detectable.** It is never consulted when grading an actual hunt run — `bench_evaluator.evaluate()` has
   no concept of "the right tool," only "was this case confirmed."
5. **`novel_findings` are preserved as their own bucket, never folded into false positives, never discarded.**
6. **False positives are defined ONLY as a confirmed claim against a case currently in patched/negative-control
   mode.** Anything that matches no known case is `novel_findings`, not a false positive.
7. **Ground truth is independent of the implementation, blind to the hunt, integrity-locked, and evaluator-only.**
   Editing it without a deliberate, separate, human-run re-lock action must fail loudly (`.claude/rules/
   benchmarks.md`: "do not silently update expected labels").
8. **Real tool runs prove planted bugs are genuinely detectable** — not synthetic string matches standing in for a
   real vulnerability.
9. **CEM (`cem_engine.py`, `case-mcp/server.py`, `tests/fixtures/cem_target/*`, `tests/test_cem_benchmark.py`) is
   completely untouched.** Zero lines changed, zero new imports in either direction.
10. **P2-BENCH introduces no new restriction, sandbox, confirmation gate, or hunting-policy change.** It is
    read-only measurement infrastructure sitting beside the existing security floor (S1–S6, S-GATE), not a change
    to it.

---

## 2. Scope

**In scope:** a loopback-only, multi-vulnerability-class target application; a blind case index; an
evaluator-only, integrity-locked answer key; an arm-agnostic scoring contract (`ObservedFinding` →
`bench_evaluator.evaluate()` → `BenchReport`); a fixture self-test proving each of the 6 planted bugs is real via
HuntMCP's own existing Tier-2 tools; evaluator-logic tests proving the scoring math is correct in isolation.

**Out of scope (explicitly deferred, not silently dropped):**
- Actually implementing a frontier-only reference arm (§7 defines the interface only — approved 2026-09-17: "architect the interface now, implement the run later").
- Wiring HuntMCP's full autonomous multi-agent pipeline (`huntbrain` → recon → scan → exploit) to run against this
  target end-to-end — that is P3/P4/P5's own job (P3-SCHEMA, P3-VALAUTHZ, P4-BM, P5-A1), consuming this substrate,
  not building it.
- The full endpoint×class×role coverage matrix (H3, `P4-COVMATRIX`) — this spec's `coverage` field is a simple
  ratio; the matrix is a later, separate task that depends on the minimal coverage instrument (`P2-COV`), which in
  turn depends on this substrate existing.
- Token/dollar cost accounting — `P2-TEL`'s job. `BenchReport.cost` is deliberately an open `dict[str, float]` so
  `P2-TEL` can add keys later without changing this contract.
- SSRF, command injection, auth-bypass-beyond-IDOR, and multi-step/stateful cases — natural next additions to the
  case index (§4), not built now.

---

## 3. The 6 initial vulnerability classes

Each class maps to a real, already-integrated Tier-2 MCP tool used **only** to prove the planted bug is genuine at
fixture build time (principle 4 — never used to grade a real hunt):

| Case | Vulnerable-mode bug | Patched-mode fix | Fixture-proof tool |
|---|---|---|---|
| SQL injection | Real SQLite, string-concatenated query on `/bench/products?id=` | Parameterized query | `sqlmap-mcp` |
| Reflected XSS | `/bench/search?q=` reflects unescaped into HTML | HTML-escaped | `dalfox-mcp` |
| IDOR | `/bench/orders/<id>` — no ownership check against session | Ownership check enforced (403 on mismatch) | `idor-mcp` (`sweep_idor`) |
| Exposed backup file | `/backup.sql.bak` present, real fake-secret content | 404 | `ffuf-mcp` |
| Security misconfiguration | Distinctive banner/string | Banner removed | `nuclei-mcp` (custom, hermetic template — not a public/live-updated one) |
| Open redirect | `/bench/login?next=` redirects to any value | Same-origin validated | `curl` (via `tool_resolver.run_tool`) |

*(Corrected during implementation planning: `httpx-mcp`'s `probe_hosts()` formats only status/title/tech/server/
length and never surfaces the `Location` header value, so it cannot distinguish "redirects anywhere" from
"redirects only same-origin." `curl` is the real, already-sandboxed, Tier-2-listed tool that actually exposes
`Location` directly — a build-time-proof-tool substitution only, per principle 4 this mapping is never a hunting
restriction either way.)*

Excluded from v1, for later addition without architecture change: SSRF (needs either a network dependency —
interactsh via `oob-mcp` — or a same-app loopback-callback design not yet decided), command injection (would hook
the heavily-gated `--os-shell` confirm flow), auth bypass beyond IDOR, and multi-step/stateful business-logic
cases (VAL-AUTHZ's own future requirement).

---

## 4. Target application (`bench_app.py`)

Pure stdlib `http.server` (`ThreadingHTTPServer` + `BaseHTTPRequestHandler`), matching
`tests/fixtures/cem_target/cem_benchmark_app.py`'s own construction exactly — no new dependency. Binds
`127.0.0.1` only, ephemeral port, zero outbound calls. Constructor takes `mode: "vulnerable" | "patched"`.
Maintains an independent in-process request log (path, query, headers, cookie) — evidence that isn't the tool's
own narrative, mirroring `cem_target`'s own B1 evidence-trail concept.

Includes several inert decoy endpoints carrying no planted bug, so the target isn't trivially "everything is
vulnerable" — supporting principle 2 (genuine recon/triage matters, not just "hit every endpoint").

The case-index data model (§5) is an open mapping (`case_id -> dict`), not a fixed-shape dataclass, specifically so
a future multi-step case (multiple endpoints, an ordered sequence, an identity-per-step) can be added as a new
entry shape without restructuring `bench_scenarios.py`, `bench_answer_key.py`, or `bench_evaluator.py`.

---

## 5. Ground truth: blind index + evaluator-only answer key + integrity locks

Directory: `tests/fixtures/bench_target/`. Every module is prefixed `bench_` — deliberately different from
`cem_target`'s `scenarios.py`/`answer_key.py`/`evaluator.py`/`harness.py`/`integrity.py`, so a bare `import
scenarios` in either test file can never silently resolve to the other fixture's module via Python's module cache
if both run in the same pytest process (a real risk with identically-named bare modules, not a hypothetical one).

- **`bench_scenarios.py`** — BLIND. `case_id -> {"endpoint": str, "method": str}` only. No vuln class, no
  severity, no expected verdict. A `FORBIDDEN_ANSWER_FIELDS` guard test (mirroring `cem_target/scenarios.py`'s own
  identical mechanism) asserts none of those fields ever appear here. **Never imported by any `mcp-servers/*`
  production code and never handed to any hunting tool call** — a real hunt run only ever receives the target's
  base URL, exactly like a real engagement. This file exists purely as the evaluator's own internal bookkeeping
  (which path corresponds to which case, for scoring) and as the future home of `P4-COVMATRIX`'s endpoint×class×
  role index.
- **`bench_answer_key.py`** — EVALUATOR-ONLY. `case_id -> {"vuln_class": str, "severity": str,
  "verification_tool": str, "expected": {"vulnerable": {...}, "patched": {...}}}`. The `verification_tool` field is
  read only by `test_p2_bench_fixture.py` (§8) — `bench_evaluator.evaluate()` never reads it (principle 4).
- **`bench_integrity.py`** — a literal, unmodified copy of `tests/fixtures/cem_target/integrity.py`'s ~40-line
  generic SHA-256 lock/verify/update utility. Copied, not refactored out of `cem_target`, so the FROZEN CEM area
  (principle 9) is touched by zero bytes. `verify()` is asserted at the top of both new test files before anything
  else runs; `update()` is a maintainer-only action, never called by a test run.
- `bench_scenarios.py.sha256.lock`, `bench_answer_key.py.sha256.lock` — the actual locks.

---

## 6. Scoring contract (`bench_evaluator.py`)

```python
class ObservedFinding(NamedTuple):
    location: str        # path the finding is about; matched against bench_scenarios endpoints
    confirmed: bool
    tool: str = ""
    evidence: dict | None = None   # NOT `= {}` -- a NamedTuple field default is shared across
                                    # every instance that omits it; see the implementation plan's
                                    # Task 9 for the confirmed aliasing bug this avoids

@dataclass(frozen=True)
class BenchReport:
    coverage: float                # confirmed-and-correct cases / total ground-truth cases
    yield_: int                    # true-positive count
    false_positives: int           # confirmed claims against a case currently in PATCHED mode
    novel_findings: int            # confirmed claims matching no known case -- never penalized
    cost: dict[str, float]         # open-shaped: tool_calls, wall_clock_s, requests (today); token/$ cost later (P2-TEL)
    per_case: dict                 # case_id -> detail, for debugging/reporting

def evaluate(observed: list[ObservedFinding], mode: str) -> BenchReport: ...
```

Matching is **by path**, ignoring query string, against `bench_scenarios.py`'s endpoints — never by anything the
arm was told in advance (nothing is told in advance). This is the ONLY function in this design that is arm-agnostic
by construction: HuntMCP's real pipeline today, or a future frontier-only baseline, both just need to produce a
`list[ObservedFinding]` in this shape.

For IDOR and SQLi specifically, the evaluator additionally cross-checks `bench_app`'s own independent request log
(mirroring `cem_target/evaluator.py`'s `verify_evidence_trail`) — a claimed confirmation must be backed by two
real, differing requests (different session cookie for IDOR; different payload for SQLi), not narrative alone.

A `reproducibility()` function (mirroring `cem_target/evaluator.py`'s own) asserts identical `BenchReport` values
across repeated runs of the same arm against the same mode.

---

## 7. Frontier-arm interface (architected now, not implemented)

The entire extension point is: produce a `list[ObservedFinding]`. `bench_evaluator.evaluate()` never needs to
change for a new arm. No stub class is created for the frontier-only arm itself (an empty, untested stub is dead
code) — the extension point is documented in `bench_evaluator.py`'s own module docstring, naming this spec as the
authority for when it's built. Today's only "arm" is HuntMCP's own real Tier-2 tool calls, normalized by a small,
test-file-local adapter function per class (never production code) inside `test_p2_bench_fixture.py`.

---

## 8. Testing plan

Two independent test files, mirroring `test_cem_benchmark.py`'s own J1-(real pipeline) vs K1/K2-(evaluator logic)
split:

**`tests/test_p2_bench_fixture.py`** — real tool runs, proving each planted bug is genuine. For each of the 6
classes: start `bench_app` in `vulnerable` mode, call the real MCP server tool function directly (matching
`test_cem_benchmark.py`'s own `importlib.util.spec_from_file_location` pattern for loading
`mcp-servers/<tool>-mcp/server.py`), assert it confirms the bug; repeat in `patched` mode, assert it does not.
sqlmap runs use a minimal/fast profile (not sqlmap's full default technique sweep) to keep the suite's wall-clock
cost reasonable. Each class's test is skippable if its binary isn't installed, mirroring
`test_sandbox_runner.py`'s own `requires_sandbox_image` pattern. Also asserts `bench_integrity.verify()` on both
protected files, and the `FORBIDDEN_ANSWER_FIELDS` blindness guard on `bench_scenarios.py`.

**`tests/test_p2_bench_evaluator.py`** — synthetic `ObservedFinding` inputs only, no real tools, no real target
server needed. Proves `evaluate()`'s own math: coverage/false-positive/novel-finding bucketing exactly matches
principles 5–6, reproducibility across repeated calls, and a coexistence check that importing both `bench_*` and
`cem_target`'s identically-shaped modules in the same pytest session does not cross-contaminate (principle from
§5's naming discussion).

---

## 9. Acceptance evidence (mirrors the tracker's own Acceptance-Evidence Matrix row for P2-BENCH)

- **Implementation:** all files in §5–§7 present.
- **Tests:** `test_p2_bench_fixture.py` (real tool runs, all 6 classes, vulnerable+patched) and
  `test_p2_bench_evaluator.py` (scoring logic) both green.
- **Runtime verification:** at least one full real-tool run against `vulnerable` mode confirms every case; the
  same run against `patched` mode confirms none, with zero false positives.
- **Ground-truth integrity:** `bench_integrity.verify()` passes on both protected files; blindness guard passes.
- **Reproducibility:** `BenchReport` identical across two repeated runs of the same arm/mode.
- **No regression:** full repo test suite green; zero lines changed under `cem_target/`, `cem_engine.py`,
  `case-mcp/server.py`, or any `mcp-servers/*` production module (this substrate only calls existing tool
  functions, never modifies them).
- **Tracker update:** `IMPLEMENTATION-TASK-TRACKER.md`'s `P2-BENCH` row updated with this evidence, matching the
  documentation depth of every prior completed task.

---

## 10. Explicit non-goals for this task (do not silently expand scope)

- No change to `scope_gate_hook.py`, `sandbox_runner.py`, `job_runtime.py`, or any S1–S6/S-GATE security-floor
  file. This benchmark target runs entirely on loopback and needs no new confirmation gate, no new sandbox
  profile, and no scope-hook change — it is exercised the same way `cem_target` already is today.
- No hunting-policy change of any kind — this is measurement infrastructure, read by future tasks (`P2-COV`,
  `P3-SCHEMA`, `P3-VALAUTHZ`, `P4-BM`, `P5-A1`), never a gate on what a hunt may do.
- No implementation of the frontier-only arm itself, per §7 and the approved answer of 2026-09-17.
- No change to CEM, per principle 9.
