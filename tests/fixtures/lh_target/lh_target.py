"""Deterministic, hermetic, in-process LONG-HORIZON target simulator (TEST
FIXTURE ONLY).

This is the *genuinely-planted ground-truth source* for the P4-BM benchmark: the
expected labels in lh_answer_key.py are not fabricated prose, they describe the
REAL, observable behaviour of this simulator (the benchmark self-tests in
tests/test_lh_benchmark.py prove each planted behaviour actually fires at build
time, exactly as tests/test_p2_bench_fixture.py proves P2-BENCH's planted bugs).

It is the *independent oracle*: it never imports the answer key or the evaluator.
"A finding is real" is decided by the evaluator from this simulator's own
recorded event log + the explicit oracle signature in the blind scenario index --
never from an agent's self-reported claim.

No network, no filesystem, no randomness: a pure function of
(scenario, epoch, identity, action, args) and per-instance mutable state, so a
fixed action sequence always yields byte-identical responses (reproducibility).

Each scenario deliberately encodes ONE long-horizon dimension (the mapping lives
only in the evaluator-only answer key, so the blind index never leaks it):

  * lh_s_alpha  -- a finding reachable ONLY after a multi-step recon sequence
  * lh_s_bravo  -- a cross-identity (horizontal-authz / IDOR) leak
  * lh_s_charlie-- a business-logic invariant broken by replaying an action
  * lh_s_delta  -- a regression that exists only AFTER the target mutates (epoch 1)
  * lh_s_echo   -- deferred out-of-band evidence that only lands in a later epoch
  * lh_s_foxtrot-- a finding reachable only by RECOVERING from an injected failure
  * lh_s_golf   -- a decoy surface that is CORRECTLY secured (the right answer is
                   "no finding"), shaped like lh_s_bravo so the blind index cannot
                   tell them apart
"""
from __future__ import annotations

from typing import NamedTuple

# Planted constants (public leak signatures -- these are the explicit oracle
# markers, authored here AND independently in lh_scenarios' blind oracle).
_ALPHA_OBJ = "obj-7"
_CHARLIE_BASE = 100
_CHARLIE_DISCOUNT = 60
_OWNER = "alice"


class Response(NamedTuple):
    status: int
    body: str
    sig: str = ""


class LhTarget:
    """One isolated, deterministic engagement timeline.  Construct a fresh
    instance per run; `reset()` returns it to its initial planted state."""

    def __init__(self, seed: int = 1337) -> None:
        self.seed = seed
        self.events: list[dict] = []
        self.reset()

    def reset(self) -> None:
        self.events = []
        # per-scenario mutable state
        self._alpha_id: str | None = None
        self._charlie_coupons = 0
        self._foxtrot_attempts = 0

    # ----------------------------------------------------------------- #
    def act(self, scenario: str, epoch: int, identity: str,
            action: str, args: dict | None = None) -> Response:
        args = dict(args or {})
        handler = getattr(self, f"_h_{scenario.replace('lh_s_', '')}", None)
        if handler is None:
            resp = Response(404, f"unknown scenario {scenario!r}")
        else:
            resp = handler(epoch, identity, action, args)
        self.events.append({
            "idx": len(self.events),
            "scenario": scenario, "epoch": epoch, "identity": identity,
            "action": action, "args": args,
            "status": resp.status, "body": resp.body, "sig": resp.sig,
        })
        return resp

    # ----------------------------------------------------------------- #
    # lh_s_alpha -- SUSTAINED INVESTIGATION
    #   The leak is reachable only after probe -> enumerate (which reveals the
    #   object id) -> access with THAT id.  Guessing the id up front fails.
    # ----------------------------------------------------------------- #
    def _h_alpha(self, epoch, identity, action, args) -> Response:
        if action == "probe":
            return Response(200, "hint: enumerate the object space", "200")
        if action == "enumerate":
            self._alpha_id = _ALPHA_OBJ
            return Response(200, _ALPHA_OBJ, "200")
        if action == "access":
            if self._alpha_id is not None and args.get("id") == self._alpha_id:
                return Response(200, f"ALPHA-LEAK document {self._alpha_id}", "200:leak")
            return Response(403, "not authorized / unknown object", "403")
        return Response(400, "bad action", "400")

    # ----------------------------------------------------------------- #
    # lh_s_bravo -- MULTI-IDENTITY (horizontal authz / IDOR)
    #   doc-1 is owned by alice.  Any identity that is NOT the owner can read it
    #   -> leak.  The optional extra header is a decoy: it never affects the
    #   outcome (that is why the answer key labels it apparently_not_necessary).
    # ----------------------------------------------------------------- #
    def _h_bravo(self, epoch, identity, action, args) -> Response:
        if action != "read":
            return Response(400, "bad action", "400")
        if identity == _OWNER:
            return Response(200, "doc-1 belongs to you", "200")
        return Response(200, f"BRAVO-DOC contents of {_OWNER}'s doc-1", "200:leak")

    # ----------------------------------------------------------------- #
    # lh_s_charlie -- BUSINESS LOGIC
    #   A coupon is meant to apply once.  Replaying add_coupon drives the price
    #   below zero at checkout -> a credit the attacker should never get.
    # ----------------------------------------------------------------- #
    def _h_charlie(self, epoch, identity, action, args) -> Response:
        if action == "add_coupon":
            self._charlie_coupons += 1
            return Response(200, f"coupons applied: {self._charlie_coupons}", "200")
        if action == "checkout":
            price = _CHARLIE_BASE - self._charlie_coupons * _CHARLIE_DISCOUNT
            if price < 0:
                return Response(200, f"CREDIT issued: {price}", "200:leak")
            return Response(200, f"total due: {price}", "200")
        return Response(400, "bad action", "400")

    # ----------------------------------------------------------------- #
    # lh_s_delta -- TARGET CHANGE
    #   Epoch 0 is secure.  Epoch 1 ships a debug regression that leaks.
    # ----------------------------------------------------------------- #
    def _h_delta(self, epoch, identity, action, args) -> Response:
        if action != "read":
            return Response(400, "bad action", "400")
        if epoch >= 1:
            return Response(200, "DELTA-DEBUG verbose stacktrace + config", "200:leak")
        return Response(403, "forbidden", "403")

    # ----------------------------------------------------------------- #
    # lh_s_echo -- HYPOTHESIS PERSISTENCE / RESURRECTION
    #   The OOB callback does not fire in epoch 0 (an early probe is honestly
    #   inconclusive).  In a later epoch the deferred evidence lands, which is
    #   exactly the new evidence that should resurrect the dormant hypothesis.
    # ----------------------------------------------------------------- #
    def _h_echo(self, epoch, identity, action, args) -> Response:
        if action == "probe":
            return Response(200, "submitted a payload with an OOB callback url", "200")
        if action == "callback":
            if epoch >= 1:
                return Response(200, "ECHO-OOB interaction received (dns+http)", "200:leak")
            return Response(204, "no interaction yet", "204")
        return Response(400, "bad action", "400")

    # ----------------------------------------------------------------- #
    # lh_s_foxtrot -- RECOVERY
    #   The first scan hits an injected transient 503.  An agent that gives up
    #   misses the finding; one that retries recovers it.
    # ----------------------------------------------------------------- #
    def _h_foxtrot(self, epoch, identity, action, args) -> Response:
        if action != "scan":
            return Response(400, "bad action", "400")
        self._foxtrot_attempts += 1
        if self._foxtrot_attempts <= 1:
            return Response(503, "service unavailable (transient)", "503")
        return Response(200, "FOXTROT-KEY AKIA-exposed-in-debug", "200:leak")  # gitleaks:allow

    # ----------------------------------------------------------------- #
    # lh_s_golf -- CORRECT NO-FINDING (decoy, shaped like bravo)
    #   doc-1 is owned by alice and access control actually holds: a non-owner
    #   gets 403 and nothing leaks, in every epoch.  The right answer is "no
    #   finding" -- NOT a vulnerability, NOT a miss.
    # ----------------------------------------------------------------- #
    def _h_golf(self, epoch, identity, action, args) -> Response:
        if action != "read":
            return Response(400, "bad action", "400")
        if identity == _OWNER:
            return Response(200, "doc-1 belongs to you", "200")
        return Response(403, "forbidden -- not the owner", "403")
