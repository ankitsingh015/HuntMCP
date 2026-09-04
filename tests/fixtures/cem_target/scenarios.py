"""BLIND scenario manifest -- the ONLY benchmark data the CEM engine legitimately receives.

Contains exactly what a researcher would be handed: a neutral case id, a target endpoint,
candidate condition names to test, and the caller-supplied success oracle (UD-3). It MUST
NOT contain expected verdicts, must_not, determinism_status, minimal sets, FCCR class, or
any semantically leaking case name. The answer key lives in answer_key.py (evaluator-only).

Condition specs describe how to SET a condition to its baseline (triggering) and perturbed
(non-triggering) value -- a legitimate experiment input, not an answer. `endpoint` uses a
neutral route on the benchmark target so the path itself leaks nothing.
"""
from __future__ import annotations

from types import MappingProxyType


def _cond(name, kind, baseline, perturbed):
    return MappingProxyType({"name": name, "kind": kind, "baseline": baseline, "perturbed": perturbed})


# Frozen, blind. Keyed by neutral ids only.
SCENARIOS = MappingProxyType({
    "case_01": MappingProxyType({
        "endpoint": "/svc/alpha/42",
        "oracle": MappingProxyType({"status_in": (200,), "body_contains": "DOC-SECRET"}),
        "conditions": (
            _cond("session_cookie", "header", {"Cookie": "session=u"}, {}),
            _cond("trace_param", "query", {"trace": "1"}, {}),
        ),
    }),
    "case_02": MappingProxyType({
        "endpoint": "/svc/bravo",
        "oracle": MappingProxyType({"status_in": (200,), "body_contains": "REPORT-DATA"}),
        "conditions": (
            _cond("x_access_header", "header", {"X-Access": "grant"}, {}),
            _cond("session_cookie", "header", {"Cookie": "session=u"}, {}),
        ),
    }),
    "case_03": MappingProxyType({
        "endpoint": "/svc/charlie",
        "oracle": MappingProxyType({"status_in": (200,), "body_contains": "MERGED"}),
        "conditions": (
            _cond("role_admin", "header", {"X-Role": "admin"}, {}),
            _cond("flag_on", "query", {"flag": "on"}, {}),
        ),
    }),
    "case_04": MappingProxyType({
        "endpoint": "/svc/delta",
        "oracle": MappingProxyType({"status_in": (200,)}),
        "conditions": (_cond("probe_header", "header", {"X-Probe": "1"}, {}),),
    }),
    "case_05": MappingProxyType({
        "endpoint": "/svc/echo/k",
        "oracle": MappingProxyType({"status_in": (200,), "body_contains": "fresh"}),
        "conditions": (_cond("probe_header", "header", {"X-Probe": "1"}, {}),),
    }),
    "case_06": MappingProxyType({
        "endpoint": "/svc/foxtrot",
        "oracle": MappingProxyType({"status_in": (200,), "body_contains": "RACE-WON"}),
        "conditions": (_cond("probe_header", "header", {"X-Probe": "1"}, {}),),
    }),
    "case_07": MappingProxyType({  # mutation scenario; blind to mode
        "endpoint": "/svc/golf/99",
        "oracle": MappingProxyType({"status_in": (200,), "body_contains": "VICTIM-DOC"}),
        "conditions": (
            _cond("session_cookie", "header", {"Cookie": "session=u"}, {}),
            _cond("target_object_id", "path", {"id": "99"}, {"id": "42"}),
        ),
    }),
})

# Fields that must NEVER appear in this manifest (asserted by the blindness guard test).
FORBIDDEN_ANSWER_FIELDS = (
    "verdict", "expected", "must_not", "determinism_status", "minimal", "fccr",
    "necessary", "interacting", "probabilistic", "apparently_not",
)
