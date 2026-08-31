"""Cross-call repeat-loop detector -- an EARLIER warning signal than
budget_guard.py's raw call-count cap, for the specific failure mode a
count alone can't distinguish: a stuck agent re-issuing the exact same
(tool, args) pair over and over, versus a healthy agent making many
DIFFERENT real calls. budget_guard.py's 500-call cap eventually catches
either case, but only after burning through most or all of the budget on
a loop that was never going to produce anything new -- this catches it
while it's still cheap (3 identical calls in, not 500).

Design taken from reading a competitor project's actual source during a
broader research pass (see gitignored RESEARCH-TODO.md's CyberStrike
deep-dive for the full note) -- not guessed, and importantly not their
FIRST attempt either. Their own commit history shows a naive "N
consecutive no-progress steps" detector was built, tried, and DISABLED
after a retest showed it over-fired on ~70% of subagents: it couldn't
tell a genuine stall from legitimate polling/coordination (an
orchestrator checking status while a sub-task is in flight looks
identical to a stuck agent under a step-count rule). The mechanism that
replaced it and stayed enabled is the one implemented here: a pure
signature counter keyed on (tool, args). Byte-identical calls collide;
different argument VALUES never do, so an agent legitimately probing
id=1, id=2, id=3 in a real IDOR sweep is never mistaken for a loop.

Two-strike escalation, and deliberately ONE shared "nudged" flag for the
whole engagement rather than one per signature: the first time ANY
signature reaches `limit` repeats, that's a "nudge" (a strong hint to
change approach); if ANY signature -- the same one or a different one --
reaches `limit` again after that, it's an "abort" (stop now). A second
stuck pattern showing up right after the first nudge should escalate
immediately, not get its own independent three free repeats.

Not yet wired into scope_gate_hook.py's PreToolUse flow -- that's a
separate, more consequential change (it can block real tool calls, so it
gets its own dedicated integration + tests) than building and proving out
the detector logic itself here.
"""

from __future__ import annotations

import json
import os
import sys

try:
    import engagement_paths
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths

try:
    import file_lock
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import file_lock

_LEGACY_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "stuck_detector.json")
DEFAULT_PATH = engagement_paths.resolve(
    "stuck_detector.json", override_env="HUNTMCP_STUCK_DETECTOR_PATH", legacy_default=_LEGACY_PATH,
)

# Occurrences of one signature before the detector reacts. Matches the
# competitor project's own validated default -- not picked arbitrarily.
DEFAULT_LIMIT = 3


def _sort_keys(value):
    if isinstance(value, dict):
        return {k: _sort_keys(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [_sort_keys(v) for v in value]
    return value


def stable_stringify(value) -> str:
    """Deterministic, key-sorted JSON so {"a":1,"b":2} and {"b":2,"a":1}
    hash identically -- argument ORDER in a dict must never make two
    otherwise-identical calls look different."""
    return json.dumps(_sort_keys(value), sort_keys=True, separators=(",", ":"))


def tool_sig(tool_name: str, tool_input) -> str:
    """Signature for the repeat check. Keyed on tool name AND the full
    argument value -- not tool name alone -- so a tester legitimately
    probing different ids/urls never trips this; only byte-identical
    (tool, args) pairs do."""
    return f"{tool_name}::{stable_stringify(tool_input)}"


def _load(path: str) -> dict:
    if not os.path.isfile(path):
        return {"counts": {}, "nudged": False}
    with open(path) as f:
        return json.load(f)


def _save(state: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def observe(tool_name: str, tool_input, limit: int = DEFAULT_LIMIT,
            path: str = DEFAULT_PATH) -> str:
    """Record one (tool_name, tool_input) call and return "ok", "nudge", or
    "abort". See the module docstring for the two-strike design -- "nudge"
    the first time any signature reaches `limit` repeats this engagement,
    "abort" if any signature reaches `limit` again after that."""
    with file_lock.locked(path):
        state = _load(path)
        sig = tool_sig(tool_name, tool_input)
        count = state["counts"].get(sig, 0) + 1
        state["counts"][sig] = count

        verdict = "ok"
        if count >= limit:
            if state["nudged"]:
                verdict = "abort"
            else:
                verdict = "nudge"
                state["nudged"] = True

        _save(state, path)
    return verdict


def _cli() -> None:
    print(json.dumps(_load(DEFAULT_PATH), indent=2))


if __name__ == "__main__":
    _cli()
