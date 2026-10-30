# schemathesis-mcp design spec (P3-SCHEMA, OpenAPI-only build)

**Status:** approved for implementation planning (writing-plans to follow).
**Scope:** build the real `schemathesis-mcp` server — the part the 2026-10-10
fixture-validation work (`docs/superpowers/specs/2026-10-10-p3-schema-fixture-design.md`)
explicitly deferred. OpenAPI only; GraphQL is a separate, later follow-up task
(deliberately phased — GraphQL support in `schemathesis` is less mature and needs its
own fixture-validation step first, same discipline already applied to OpenAPI).

## 1. Objective and explicit non-goals

Give an agent a tool that runs `schemathesis` against a target's OpenAPI spec and
returns a structured list of falsifier hits (schema/property-robustness violations),
fully wired into this repo's existing safety stack (scope gate, sandbox, budget guard).

**Explicitly deferred — not silently satisfied by this task:**

- GraphQL support (separate follow-up task, own fixture-validation first).
- P3-ADAPTER (turning each falsifier hit into a CEM hypothesis via
  `case_store.log_hypothesis`) — separate tracker row, consumes this task's output
  format later. This task only needs to produce a stable, parseable output; it does not
  call `case_store` itself (same convention as every other scanner server — e.g.
  `nuclei-mcp`/`ffuf-mcp` return text, the agent/a later adapter decides what to do with
  it).
- P3-CEMHUNT, P3-DISCSPEC — separate tracker rows, unaffected.
- Clearing P3-SCHEMA's own GATED acceptance bar (WFC/WFD breadth vs the protected
  benchmark, FCC==0) — that is a promotion decision made later, with real benchmark
  evidence, not a build-time claim. This task stays `[~] GATED` even once merged,
  exactly like C1b's promotion-pending convention.
- Rebuilding/distributing the sandbox image is **not fully automatable from here** —
  see §4; the Dockerfile/tag edit is part of this task, but the actual `podman build`
  needs to be run (by whoever has podman set up) before the sandboxed path works for
  real.

## 2. Tool surface

New `mcp-servers/schemathesis-mcp/server.py` + its own `requirements.txt`
(`schemathesis==4.30.1`, the exact version already validated in the 2026-10-10 work —
no new version research needed).

- `run_schema_test(url: str, target: str, phases: str = "examples", checks: str = "not_a_server_error,status_code_conformance,response_schema_conformance", max_examples: int = 100, timeout: int = 300) -> str`
  Starts a background job (same `job_runtime.start_job` pattern as every other
  scanner), returns a `job_id` immediately.
- `check_scan(job_id: str) -> str` — poll. Same contract as every other scanner's
  `check_scan`: `"running"` while in progress, formatted results (or error) once done.
- `list_scans() -> str` — same as every other scanner.

`phases`/`checks`/`max_examples` default to exactly what the 2026-10-10 fixture work
verified live (deterministic `examples` phase, the 3-check profile that stayed clean on
the patched fixture and correctly fired on the vulnerable one). An agent can widen these
(e.g. add `fuzzing`), but the defaults are the only combination with direct empirical
evidence behind them in this repo.

## 3. Security-critical design decision: `target` is mandatory and always wins

`url` = where to fetch the OpenAPI spec from (schemathesis's `LOCATION` positional
argument; schemathesis fetches it directly). `target` = the real base URL schemathesis
actually sends generated requests to, passed explicitly as schemathesis's own
`-u/--url target` CLI **flag** — unfortunately named identically to this tool's own
`url` parameter despite meaning something different; implementers must not confuse the
two. (Verified live against the installed `schemathesis==4.30.1`: there is no
`--base-url` flag — an earlier draft of this spec named the wrong flag before this was
checked. `-u/--url` is the real one, documented as "API base URL (required for
file-based schemas)," and empirically confirmed to override a live-fetched spec's own
declared server too: running against the fixture with `--url` pointed at the fixture's
real base produced real requests/failures against it.) This CLI flag **always
overrides** whatever `servers[].url` the spec itself declares.

**Why this matters:** the OpenAPI document is content served BY the target —
attacker-influenced in the same sense `tool-output` from any other scanner is (P2-INJ's
whole threat model). If the base URL were left to the spec's own declared `servers[]`
value, a malicious or simply misconfigured spec could point every generated test
request at a different host entirely — a different asset, an internal hostname, or
something fully out of scope — and the static scope-gate check on the agent's `url`
argument would never see it, because that host string lives inside the fetched JSON
body, not in the tool call's own arguments. Making `target` a required, explicit
parameter and always passing the `--url` flag closes this at the source: schemathesis
is never allowed to decide for itself where requests go.

## 4. Safety wiring (reuses existing mechanisms, no new ones)

- **`scripts/hooks/scope_gate_hook.py`:** add `"schemathesis-mcp"` to
  `TIER2_MCP_SERVERS`. Both `url` and `target` are literal `HOST_ARG_KEYS` entries
  (`"url"`, `"target"`), so `_extract_hosts_from_tool_input()` catches both
  automatically — no new extraction logic needed.
- **In-code check too, belt-and-suspenders** (same pattern `case-mcp`'s
  `fetch_with_provenance`/`determinism_gate` already use, documented in the hook's own
  comment at scope_gate_hook.py:158-173): before calling `job_runtime.start_job`, the
  server calls `scope_guard.is_in_scope()` itself on both `url` and `target`. The
  hook's regex-based filter is a cheap early filter, not the real boundary — the
  in-code check is. Refuses with a clear error (never silently proceeds) if either is
  out of scope.
- **Cloud-metadata/link-local SSRF check, same two-layer requirement
  `fetch_with_provenance` already applies and `is_in_scope()` alone cannot provide:**
  `scope_guard.is_in_scope()`'s own `is_safe_test_host` fast-path treats loopback/
  RFC1918/link-local addresses as automatically in-scope *before* `out_of_scope` is
  even consulted — correct for this benchmark's own "needs no engagement.yaml" local
  test-host posture, but it means `is_in_scope()` alone cannot keep a request off a
  cloud instance-metadata endpoint (`169.254.169.254`, etc.) if that address is ever
  passed as `url`/`target`. `case-mcp/server.py`'s `_cem_outbound_policy_error()`
  already implements exactly this check (scheme allowlist + metadata/link-local deny)
  and is, by its own code comment, "generic, not CEM-specific despite the name" — it is
  currently private to that one file. This task extracts it into
  `scope_guard.py` as `scope_guard.outbound_policy_error(url) -> str | None`
  (same signature/behavior, just relocated to where it conceptually belongs — a
  generic outbound-request policy, not a CEM-specific one), updates `case-mcp/server.py`
  to import and call the relocated version at its existing 3 call sites instead of
  defining it locally, and has `schemathesis-mcp` call the same shared function on
  both `url` and `target`, in addition to (not instead of) `is_in_scope()`. One shared
  implementation, not a second hand-copied one — a future fix to this check (e.g. a new
  bypass found later) then protects every caller at once instead of needing to be
  re-applied file by file.
- **`job_runtime.start_job("schemathesis", ...)`:** automatically sandboxed (podman,
  via `sandbox_runner.py`) and automatically counted by `budget_guard.enforce()` — one
  budget unit per `run_schema_test` call, matching every other scanner's convention
  (budget tracks tool invocations, not the N individual HTTP requests schemathesis
  issues inside one run — same as `nuclei`/`ffuf` already do).
- **Sandbox image:** `schemathesis` must be added to `sandbox_runner.py`'s `_TOOL_MAP`
  (`"schemathesis": "/usr/local/bin/schemathesis"` — matches where
  `pip3 install --break-system-packages` puts a console-script entry point on this
  image's Debian base, same path convention already used for `sqlmap`) and to
  `mcp-servers/sandbox/Dockerfile`'s existing `pip3 install` line (alongside
  `sqlmap==1.8.4`/`impacket==0.12.0`), pinned to `schemathesis==4.30.1`.
  `sandbox_runner.SANDBOX_IMAGE` bumps from `"localhost/huntmcp-sandbox:2026-09-15"` to
  a new dated tag. **This requires an actual `podman build` to take effect** — editing
  the Dockerfile alone does not make the new tool available in the running sandbox;
  whoever has podman set up on this machine needs to rebuild and tag the image before
  `run_schema_test` can work end-to-end for real. This task will leave that command
  documented, not silently assumed as already done.

## 5. Data flow

1. `run_schema_test` validates scope (in-code, §4) →
2. builds the schemathesis CLI invocation: `schemathesis run <url> --url <target> --phases <phases> --checks <checks> --max-examples <max_examples> --report json --report-dir <scratch>` (note the flag-vs-param name collision flagged in §3 — the CLI's `--url` IS this tool's `target`, not its `url`) →
3. `job_runtime.start_job("schemathesis", args, timeout, _jobs, extra_mounts_rw=[scratch])` — same `extra_mounts_rw` pattern `sqlmap-mcp` already uses for its own `--output-dir`, since schemathesis must WRITE the report there →
4. `check_scan` polls `job_runtime.poll_job`; once done, reads the JSON report file back off disk (same read-back-after-job-done pattern `sqlmap-mcp`/`dalfox-mcp` already use). **Verified live against a real report** (both the vulnerable and patched fixture modes, via `/tmp/st_venv` during this spec's own writing — not assumed): the report's `failures` key is a list of `{"type": str, "title": str, "severity": str, "count": int, "operations": [str, ...]}` dicts (`operations` entries are `"METHOD /path"` strings — the API's own declared path template, not raw target content); a clean run has `failures: []`, top-level `exit_code: 0`, and `phases["examples"]["status"] == "success"`. **There is no response body or raw target text anywhere in this structured summary** — `type`/`title`/`severity`/`count`/`operations` are all schemathesis-computed or spec-template-derived, never target-authored free text. This is parsed directly into the falsifier list; §5 below's quarantine step applies only to the separate raw-CLI-text path, not to this structured parse.
5. the formatted text includes the structured falsifier list from step 4, **plus** the raw CLI stdout tail (truncated, same convention every other scanner's `_format_results` uses on a non-JSON/fallback path) for human-readable repro detail — schemathesis's own terminal output includes a `curl -X GET '<target_url>?...'` repro line and, when `not_a_server_error` or `response_schema_conformance` fires, the actual response body (e.g. `{"error": "internal error"}` in the fixture's own case) — this raw text genuinely is target-reflected content, and **is** wrapped via `injection_boundary.quarantine()` before being placed in the returned text, same P2-INJ discipline every other scanner's formatted output already applies (e.g. `dalfox-mcp`'s `evidence` field) →
6. the formatted text ends with a structured line, `Falsifiers (for case-mcp/P3-ADAPTER): <json>` — the json is exactly the parsed `failures` list from step 4 (never quarantined, since it carries no target-authored text) — mirroring the existing `Provenance (for case-mcp add_evidence): <json>` convention `ffuf-mcp`/`nuclei-mcp` already append. This is the stable contract P3-ADAPTER will later parse, not something P3-ADAPTER needs to be built to define first.
7. scratch dir cleaned up (`shutil.rmtree`) once the report is read, same as `sqlmap-mcp`'s own teardown in `check_scan`.

## 6. Error handling

- `schemathesis` binary missing (sandbox image not yet rebuilt, or run outside the
  sandbox during dev) → `FileNotFoundError` caught → friendly install/rebuild message,
  same pattern every other server's `_start()` already uses.
- Scope violation on `url` or `target` → clear, explicit error string, call refused
  before any job starts (no budget charged either, since `_enforce_budget` happens
  inside `job_runtime.start_job`, never reached).
- Spec fetch fails / malformed OpenAPI document → surfaced via schemathesis's own
  non-zero exit code + stderr tail, not swallowed into a generic message.
- Report file missing or malformed JSON after the job reports done → **explicit error
  string**, never a silently-empty "no falsifiers found" result — the earlier fixture
  work's own §5 "determinism safety net" principle applies here too: a parsing failure
  must never look identical to a genuine clean result.

## 7. Testing

- Unit tests mocking `job_runtime`/`sandbox_runner` (same style as
  `test_ffuf_mcp_*.py`/`test_sqlmap_mcp_*.py`) for: argument building, scope-check
  refusal (both `url`-out-of-scope and `target`-out-of-scope cases, independently),
  report-parsing, quarantine application, and the malformed-report error path.
- Real-fixture tests reusing the **already-existing, already-validated**
  `tests/fixtures/schema_target/schema_app.py` (vulnerable/patched modes) — this time
  driven through the actual new MCP server's `run_schema_test`/`check_scan` end to end,
  not the raw CLI the 2026-10-10 work used directly.
- **Any test that requires a real sandboxed run must gate on the actual sandbox image
  tag being present** (e.g. `podman image exists localhost/huntmcp-sandbox:<new-tag>`),
  **not just on the `podman` binary existing** — this exact gap (gating sandboxed tests
  on the binary alone, which let them silently report false confidence when the image
  itself was stale/missing) was a real bug found and fixed during P2-BENCH; this task
  must not reintroduce it.

## 8. Open questions (recorded, not guessed at)

- Rate-limiting against the target: schemathesis has its own `--rate-limit` flag;
  default value needs a sane default (proposed: a conservative fixed default,
  overridable later if a real engagement needs it) — not yet empirically tuned against
  a real target, flagged here rather than picked arbitrarily without evidence.
- GraphQL: fully deferred per §1, own future task.
