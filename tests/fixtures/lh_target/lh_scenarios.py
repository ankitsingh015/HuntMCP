"""BLIND scenario index for the long-horizon benchmark.

This is everything a researcher is legitimately handed: an opaque scenario id, an
entry point, the identities and epochs available, the action vocabulary, and the
caller-supplied success oracle (what an observable leak WOULD look like).  It
contains NO expected conclusion, NO dimension label, NO causal verdict, and NO
semantically-leaking id -- those live only in lh_answer_key.py (evaluator-only).

Crucially, the decoy "correct no-finding" scenario is shaped identically to a
planted one (same keys, a fully-specified oracle), so nothing here reveals which
scenarios are vulnerable.  Every scenario advertises epochs (0, 1) so the epoch
count alone cannot flag the target-change / resurrection scenarios.

NEVER imported by any mcp-servers/* production code and NEVER handed to a hunting
tool: a real arm receives only this blind index + the simulator's base behaviour,
exactly like a real engagement receives only a base URL.
"""
from __future__ import annotations

from types import MappingProxyType

LH_BENCH_VERSION = "1.0.0"
SEED = 1337
TARGET_MODE = "deterministic-in-process"


def _s(entry, identities, actions, oracle):
    return MappingProxyType({
        "entry": entry,
        "identities": tuple(identities),
        "epochs": (0, 1),
        "actions": tuple(actions),
        "oracle": MappingProxyType({"body_contains": oracle}),
    })


SCENARIOS = MappingProxyType({
    "lh_s_alpha":   _s("/lh/alpha", ("alice",),          ("probe", "enumerate", "access"), "ALPHA-LEAK"),
    "lh_s_bravo":   _s("/lh/bravo", ("alice", "bob"),    ("read",),                        "BRAVO-DOC"),
    "lh_s_charlie": _s("/lh/charlie", ("alice",),        ("add_coupon", "checkout"),       "CREDIT"),
    "lh_s_delta":   _s("/lh/delta", ("alice",),          ("read",),                        "DELTA-DEBUG"),
    "lh_s_echo":    _s("/lh/echo", ("alice",),           ("probe", "callback"),            "ECHO-OOB"),
    "lh_s_foxtrot": _s("/lh/foxtrot", ("alice",),        ("scan",),                        "FOXTROT-KEY"),
    "lh_s_golf":    _s("/lh/golf", ("alice", "bob"),     ("read",),                        "GOLF-DOC"),
})

# Tokens that must NEVER appear in this manifest (asserted by the blindness guard).
FORBIDDEN_ANSWER_FIELDS = (
    "planted", "vuln_class", "dimension", "necessary", "apparently_not",
    "inconclusive", "resurrect", "recovery", "no_finding", "expected",
    "verdict", "minimal",
)
