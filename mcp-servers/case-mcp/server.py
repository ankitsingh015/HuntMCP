import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import case_store
from mcp.server.fastmcp import FastMCP

app = FastMCP("case-mcp")


@app.tool()
def log_hypothesis(observation: str, hypothesis: str) -> str:
    """Record a new hypothesis for this engagement: what you observed, and
    what you think it means (e.g. observation="URL parameter `url=` fetched
    server-side and echoed in the response", hypothesis="server performs an
    unvalidated SSRF-prone fetch"). Starts at status NEW. Call
    update_hypothesis() as you test it. Returns the new hypothesis id --
    use it as hypothesis_id in log_experiment()/add_evidence()/
    create_finding()."""
    return json.dumps(case_store.log_hypothesis(observation, hypothesis))


@app.tool()
def update_hypothesis(hypothesis_id: int, status: str, note: str = "") -> str:
    """Move a hypothesis to a new status: NEW (untested) -> TESTING (a test
    is in flight) -> SUPPORTED/REFUTED/INCONCLUSIVE (test result) ->
    CONFIRMED (verified, ready to become a finding). note is a short
    free-text reason, e.g. why it was REFUTED."""
    return json.dumps(case_store.update_hypothesis(hypothesis_id, status, note))


@app.tool()
def add_evidence(type: str, content: str, hypothesis_id: int = 0, finding_id: int = 0) -> str:
    """Attach immutable evidence (raw request, response body, OOB callback
    log, screenshot description, DNS record, source snippet, or other
    metadata) to a hypothesis and/or a finding. type must be one of:
    request, response, callback, screenshot, dns, source, metadata.
    Content is hashed (SHA-256) and stored content-addressed, so writing
    identical content twice is a safe no-op. Pass hypothesis_id and/or
    finding_id (0 means "not linked" for that one) -- update_finding_status()
    refuses to mark a finding CONFIRMED or IMPACT_PROVEN until it has at
    least one linked evidence row, so call this BEFORE that call, not after."""
    return json.dumps(case_store.add_evidence(
        type, content,
        hypothesis_id=hypothesis_id or None,
        finding_id=finding_id or None,
    ))


@app.tool()
def log_experiment(tool: str, input: str, target: str, result: str = "", cost: int = 0,
                    hypothesis_id: int = 0, finding_id: int = 0, status: str = "done") -> str:
    """Record that a specific test actually ran: which tool, what input
    (e.g. the exact payload or command), against what target, and the
    result. Call this for every test you run, not just successful ones --
    check_experiment_exists() relies on it to stop you re-running a test
    you already tried earlier this engagement."""
    return json.dumps(case_store.log_experiment(
        tool, input, target, result=result, cost=cost,
        hypothesis_id=hypothesis_id or None, finding_id=finding_id or None, status=status,
    ))


@app.tool()
def check_experiment_exists(tool: str, input: str, target: str) -> str:
    """Check whether this exact tool+input+target combination has already
    been run and logged via log_experiment() this engagement -- call this
    BEFORE running a test to avoid repeating work."""
    exists = case_store.check_experiment_exists(tool, input, target)
    return "true" if exists else "false"


@app.tool()
def create_finding(vuln_class: str, endpoint: str, parameter: str = "", hypothesis_id: int = 0) -> str:
    """Register a new finding at status DISCOVERED. Optionally link the
    hypothesis_id that led to it. Returns the new finding id -- use it in
    add_evidence()/update_finding_status()/score_finding_confidence()."""
    return json.dumps(case_store.create_finding(
        vuln_class, endpoint, parameter=parameter, hypothesis_id=hypothesis_id or None,
    ))


@app.tool()
def update_finding_status(finding_id: int, status: str) -> str:
    """Move a finding through its lifecycle: DISCOVERED -> SUSPECTED ->
    VALIDATING -> CONFIRMED -> IMPACT_PROVEN -> REPORTED, or off to
    FALSE_POSITIVE/DUPLICATE/INCONCLUSIVE at any point. Moving to CONFIRMED
    or IMPACT_PROVEN is REJECTED if the finding has zero linked evidence
    rows -- call add_evidence(..., finding_id=...) first."""
    return json.dumps(case_store.update_finding_status(finding_id, status))


@app.tool()
def score_finding_confidence(finding_id: int, signals: str) -> str:
    """Set a finding's confidence from named evidence signals instead of
    self-rating it. signals is a JSON object of {label: points}, e.g.
    '{"endpoint_confirmed": 15, "parameter_confirmed": 15, "reproduction": 25,
    "oob_confirmation": 20}'. Points are summed (clamped 0-100) and banded:
    0-30 LOW, 31-60 MEDIUM, 61-80 HIGH, 81-100 CONFIRMED."""
    try:
        parsed = json.loads(signals)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"signals must be a JSON object: {e}"})
    return json.dumps(case_store.score_finding_confidence(finding_id, parsed))


@app.tool()
def group_root_cause(finding_ids: str, description: str) -> str:
    """Group 2+ findings under one underlying root cause (e.g. IDOR on
    /api/user, /api/orders, and /api/documents are all the same broken
    authorization middleware). finding_ids is a JSON array of ints, e.g.
    '[3, 5, 7]'. Use suggest_root_cause() first to see obvious candidates."""
    try:
        ids = json.loads(finding_ids)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"finding_ids must be a JSON array of ints: {e}"})
    return json.dumps(case_store.group_root_cause(ids, description))


@app.tool()
def suggest_root_cause() -> str:
    """Heuristic suggestion: findings that already share the same
    vuln_class+endpoint signature and aren't grouped under a root cause
    yet. A starting point, not semantic inference -- confirm with your own
    judgment before calling group_root_cause()."""
    return case_store.suggest_root_cause()


@app.tool()
def suggest_next_action() -> str:
    """What to work on next, prioritizing finishing what's already in
    flight (a TESTING hypothesis, an in-progress finding) over starting
    something fresh. Call this when deciding what to test next instead of
    picking arbitrarily."""
    return case_store.suggest_next_action()


@app.tool()
def case_summary() -> str:
    """Current case state: hypothesis/finding counts by status, evidence
    and experiment counts, root causes grouped. Call this to orient before
    deciding what to do next, or before handing off to another agent."""
    return case_store.case_summary()


@app.tool()
def case_export() -> str:
    """Full case state as JSON (all hypotheses, findings, evidence,
    experiments, root causes) -- for report-agent or human review. There
    is no matching case_import(); this engagement's case.db on disk is
    already the durable copy."""
    return case_store.case_export()


if __name__ == "__main__":
    print("case-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
