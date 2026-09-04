"""Phase-1 TEST-ENVIRONMENT tests (no CEM logic). Verifies the benchmark substrate itself:
neutral-route target behavior, state reset, split-file integrity, immutability, mutation
mode difference, and cleanup. Does NOT test CEM verdicts.
"""
import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures", "cem_target"))

import answer_key  # noqa: E402
import integrity  # noqa: E402
import scenarios  # noqa: E402
from harness import CemBenchmarkServer, ExternalTargetRefused, http_get  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "cem_target")


@pytest.fixture()
def target():
    srv = CemBenchmarkServer().start()
    try:
        yield srv
    finally:
        srv.stop()


@pytest.fixture()
def patched_target():
    srv = CemBenchmarkServer(mode="patched").start()
    try:
        yield srv
    finally:
        srv.stop()


def test_target_binds_loopback_only(target):
    assert target.base_url.startswith("http://127.0.0.1:") and target.port > 0


def test_alpha_requires_session_cookie(target):
    no_cookie, _ = http_get(f"{target.base_url}/svc/alpha/42")
    ok, body = http_get(f"{target.base_url}/svc/alpha/42", headers={"Cookie": "session=abc"})
    assert no_cookie == 401 and ok == 200 and "DOC-SECRET" in body


def test_alpha_trace_param_irrelevant(target):
    h = {"Cookie": "session=abc"}
    a, _ = http_get(f"{target.base_url}/svc/alpha/42", headers=h)
    b, _ = http_get(f"{target.base_url}/svc/alpha/42?trace=1", headers=h)
    assert a == b == 200


def test_bravo_two_paths(target):
    via_h, _ = http_get(f"{target.base_url}/svc/bravo", headers={"X-Access": "grant"})
    via_c, _ = http_get(f"{target.base_url}/svc/bravo", headers={"Cookie": "session=x"})
    neither, _ = http_get(f"{target.base_url}/svc/bravo")
    assert via_h == 200 and via_c == 200 and neither == 403


def test_charlie_interaction(target):
    both, _ = http_get(f"{target.base_url}/svc/charlie?flag=on", headers={"X-Role": "admin"})
    role, _ = http_get(f"{target.base_url}/svc/charlie", headers={"X-Role": "admin"})
    flag, _ = http_get(f"{target.base_url}/svc/charlie?flag=on")
    assert both == 200 and role == 403 and flag == 403


def test_delta_non_constant(target):
    assert len({http_get(f"{target.base_url}/svc/delta")[0] for _ in range(6)}) > 1


def test_echo_first_then_blocked_and_reset(target):
    first, _ = http_get(f"{target.base_url}/svc/echo/k1")
    second, _ = http_get(f"{target.base_url}/svc/echo/k1")
    assert first == 200 and second == 403
    target.reset()
    assert http_get(f"{target.base_url}/svc/echo/k1")[0] == 200


def test_foxtrot_single_request_loses(target):
    assert http_get(f"{target.base_url}/svc/foxtrot")[0] == 409


def test_foxtrot_wins_under_concurrency(target):
    results, lock = [], threading.Lock()

    def hit():
        s, _ = http_get(f"{target.base_url}/svc/foxtrot")
        with lock:
            results.append(s)

    ts = [threading.Thread(target=hit) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert 200 in results


def test_mutation_vulnerable_vs_patched_differ(target, patched_target):
    # B2: same blind request, genuinely different security behavior between modes.
    h = {"Cookie": "session=u"}
    vuln, vbody = http_get(f"{target.base_url}/svc/golf/99", headers=h)
    pat, _ = http_get(f"{patched_target.base_url}/svc/golf/99", headers=h)
    assert vuln == 200 and "VICTIM-DOC" in vbody   # vulnerable: IDOR leak
    assert pat == 403                               # patched: fixed
    # own object still readable in both (sanity)
    assert http_get(f"{target.base_url}/svc/golf/42", headers=h)[0] == 200
    assert http_get(f"{patched_target.base_url}/svc/golf/42", headers=h)[0] == 200


def test_request_log_records_interaction(target):
    http_get(f"{target.base_url}/svc/alpha/42", headers={"Cookie": "session=u"})
    http_get(f"{target.base_url}/svc/alpha/42")
    log = target.requests()
    assert len(log) == 2 and log[0]["session"] is True and log[1]["session"] is False


def test_scenarios_integrity(target):
    ok, msg = integrity.verify(os.path.join(FIX, "scenarios.py"))
    assert ok, msg


def test_answer_key_integrity(target):
    ok, msg = integrity.verify(os.path.join(FIX, "answer_key.py"))
    assert ok, msg


def test_scenarios_immutable():
    with pytest.raises(TypeError):
        scenarios.SCENARIOS["case_01"]["oracle"]["status_in"] = (500,)  # type: ignore[index]


def test_answer_key_immutable():
    with pytest.raises(TypeError):
        answer_key.EXPECTED["case_01"]["verdicts"]["session_cookie"] = "hacked"  # type: ignore[index]


def test_harness_refuses_external_host():
    with pytest.raises(ExternalTargetRefused):
        http_get("http://example.com/")


def test_cleanup_releases_port():
    srv = CemBenchmarkServer().start()
    port = srv.port
    srv.stop()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        connected = s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()
    assert not connected
