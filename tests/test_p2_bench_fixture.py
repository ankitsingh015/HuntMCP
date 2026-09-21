import os
import sqlite3
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "bench_target"))

from bench_app import BenchApp


@pytest.fixture
def vulnerable_app():
    app = BenchApp(mode="vulnerable").start()
    try:
        yield app
    finally:
        app.stop()


@pytest.fixture
def patched_app():
    app = BenchApp(mode="patched").start()
    try:
        yield app
    finally:
        app.stop()


def test_app_binds_loopback_only_and_returns_a_base_url(vulnerable_app):
    assert vulnerable_app.base_url.startswith("http://127.0.0.1:")


def test_sqli_vulnerable_boolean_injection_returns_all_products(vulnerable_app):
    import urllib.request
    baseline = urllib.request.urlopen(f"{vulnerable_app.base_url}/bench/products?id=1").read().decode()
    injected = urllib.request.urlopen(
        f"{vulnerable_app.base_url}/bench/products?id=1%20OR%201=1"
    ).read().decode()
    assert injected.count("PRODUCT-") > baseline.count("PRODUCT-")


def test_sqli_patched_boolean_injection_has_no_effect(patched_app):
    import urllib.request
    baseline = urllib.request.urlopen(f"{patched_app.base_url}/bench/products?id=1").read().decode()
    injected = urllib.request.urlopen(
        f"{patched_app.base_url}/bench/products?id=1%20OR%201=1"
    ).read().decode()
    assert injected.count("PRODUCT-") == baseline.count("PRODUCT-")


def test_request_log_records_the_path_and_query(vulnerable_app):
    import urllib.request
    urllib.request.urlopen(f"{vulnerable_app.base_url}/bench/products?id=7")
    assert any(
        e["path"] == "/bench/products" and e["query"].get("id") == ["7"]
        for e in vulnerable_app.request_log
    )


def test_xss_vulnerable_reflects_script_tag_unescaped(vulnerable_app):
    import urllib.request
    body = urllib.request.urlopen(
        f"{vulnerable_app.base_url}/bench/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
    ).read().decode()
    assert "<script>alert(1)</script>" in body


def test_xss_patched_escapes_the_script_tag(patched_app):
    import urllib.request
    body = urllib.request.urlopen(
        f"{patched_app.base_url}/bench/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
    ).read().decode()
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_idor_vulnerable_attacker_session_sees_owners_order(vulnerable_app):
    import urllib.request
    req = urllib.request.Request(
        f"{vulnerable_app.base_url}/bench/orders/42", headers={"Cookie": "session=attacker-session"}
    )
    body = urllib.request.urlopen(req).read().decode()
    assert "ORDER-DETAIL-42-SECRET" in body


def test_idor_patched_attacker_session_is_refused(patched_app):
    import urllib.error
    import urllib.request
    req = urllib.request.Request(
        f"{patched_app.base_url}/bench/orders/42", headers={"Cookie": "session=attacker-session"}
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 403


def test_idor_patched_owner_session_still_works(patched_app):
    import urllib.request
    req = urllib.request.Request(
        f"{patched_app.base_url}/bench/orders/42", headers={"Cookie": "session=owner-session"}
    )
    body = urllib.request.urlopen(req).read().decode()
    assert "ORDER-DETAIL-42-SECRET" in body


def test_backup_file_vulnerable_is_present(vulnerable_app):
    import urllib.request
    body = urllib.request.urlopen(f"{vulnerable_app.base_url}/backup.sql.bak").read().decode()
    assert "DB_PASSWORD=bench-fixture-fake-secret-not-real" in body


def test_backup_file_patched_is_absent(patched_app):
    import urllib.error
    import urllib.request
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{patched_app.base_url}/backup.sql.bak")
    assert exc.value.code == 404


def test_misconfig_vulnerable_banner_header_present(vulnerable_app):
    import urllib.request
    resp = urllib.request.urlopen(f"{vulnerable_app.base_url}/bench/status")
    assert resp.headers.get("X-Bench-Debug-Panel") == "build 2026.09-DEBUG-ENABLED"


def test_misconfig_patched_banner_header_absent(patched_app):
    import urllib.request
    resp = urllib.request.urlopen(f"{patched_app.base_url}/bench/status")
    assert resp.headers.get("X-Bench-Debug-Panel") is None


def test_open_redirect_vulnerable_follows_any_next(vulnerable_app):
    import urllib.request
    import urllib.error
    class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        opener.open(f"{vulnerable_app.base_url}/bench/login?next=https://attacker.example/steal")
        assert False, "Expected HTTPError for redirect"
    except urllib.error.HTTPError as e:
        assert e.code == 302
        assert e.headers.get("Location") == "https://attacker.example/steal"


def test_open_redirect_patched_ignores_external_next(patched_app):
    import urllib.request
    import urllib.error
    class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        opener.open(f"{patched_app.base_url}/bench/login?next=https://attacker.example/steal")
        assert False, "Expected HTTPError for redirect"
    except urllib.error.HTTPError as e:
        assert e.code == 302
        assert e.headers.get("Location") == "/bench/home"


def test_harness_refuses_a_non_loopback_url():
    from bench_harness import ExternalTargetRefused, http_get
    with pytest.raises(ExternalTargetRefused):
        http_get("https://example.com")


def test_harness_reaches_the_real_loopback_target(vulnerable_app):
    from bench_harness import http_get
    status, body = http_get(f"{vulnerable_app.base_url}/bench/decoy")
    assert status == 200
    assert "nothing interesting" in body
