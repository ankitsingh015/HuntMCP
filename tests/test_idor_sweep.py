import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "idor_sweep", os.path.join(ROOT, "mcp-servers", "idor-mcp", "idor_sweep.py"),
)
idor_sweep = importlib.util.module_from_spec(_spec)
# Must be registered in sys.modules BEFORE exec_module -- idor_sweep.py's
# @dataclass decorators look up sys.modules[cls.__module__] to resolve
# their type annotations, which fails with a bare AttributeError on
# NoneType if the module isn't registered yet at class-definition time.
sys.modules["idor_sweep"] = idor_sweep
_spec.loader.exec_module(idor_sweep)

FetchResult = idor_sweep.FetchResult


def test_build_headers_both_present():
    headers = idor_sweep._build_headers("session=abc123", "tok_xyz")
    assert headers == {"Cookie": "session=abc123", "Authorization": "Bearer tok_xyz"}


def test_build_headers_neither_present():
    assert idor_sweep._build_headers(None, None) == {}


def test_build_headers_cookie_only():
    assert idor_sweep._build_headers("session=abc123", None) == {"Cookie": "session=abc123"}


def test_classify_protected_when_other_gets_403():
    owner = FetchResult(status=200, body="owner's real order data, $500 total")
    other = FetchResult(status=403, body="Forbidden")
    verdict, ratio, detail = idor_sweep._classify(owner, other)
    assert verdict == "PROTECTED"
    assert ratio is None


def test_classify_protected_on_401_and_404_too():
    owner = FetchResult(status=200, body="owner's real order data")
    for status in (401, 404):
        other = FetchResult(status=status, body="")
        verdict, _, _ = idor_sweep._classify(owner, other)
        assert verdict == "PROTECTED"


def test_classify_leaked_when_bodies_near_identical():
    body = "order #4521: 3x Widget Pro, shipping to 123 Main St, total $89.97"
    owner = FetchResult(status=200, body=body)
    other = FetchResult(status=200, body=body)
    verdict, ratio, _ = idor_sweep._classify(owner, other)
    assert verdict == "LEAKED"
    assert ratio == 1.0


def test_classify_different_when_bodies_unrelated():
    owner = FetchResult(status=200, body="order #4521: 3x Widget Pro, shipping to 123 Main St")
    other = FetchResult(status=200, body="404")
    verdict, ratio, _ = idor_sweep._classify(owner, other)
    assert verdict == "DIFFERENT"
    assert ratio < idor_sweep.AMBIGUOUS_RATIO_THRESHOLD


def test_classify_ambiguous_when_partially_similar():
    owner = FetchResult(status=200, body="order #4521 total $89.97 shipping to 123 Main Street Springfield")
    other = FetchResult(status=200, body="order #4521 total unavailable shipping to REDACTED")
    verdict, ratio, _ = idor_sweep._classify(owner, other)
    assert verdict in ("AMBIGUOUS", "DIFFERENT")  # exact bucket depends on ratio, both are "not LEAKED"
    assert verdict != "LEAKED"


def test_classify_owner_baseline_failed_on_non_200():
    owner = FetchResult(status=404, body="")
    other = FetchResult(status=200, body="something")
    verdict, ratio, detail = idor_sweep._classify(owner, other)
    assert verdict == "OWNER_BASELINE_FAILED"
    assert "empty test account" in detail or "baseline" in detail


def test_classify_owner_baseline_failed_on_empty_body():
    """Regression: the exact 'empty test account, nothing to steal' problem
    the review flagged -- if the OWNER's own request returns 200 but no
    real data, no verdict about the OTHER identity's access means anything."""
    owner = FetchResult(status=200, body="   ")
    other = FetchResult(status=200, body="something")
    verdict, ratio, detail = idor_sweep._classify(owner, other)
    assert verdict == "OWNER_BASELINE_FAILED"


def test_classify_error_when_owner_request_failed():
    owner = FetchResult(status=None, body="", error="Connection refused")
    other = FetchResult(status=200, body="x")
    verdict, ratio, detail = idor_sweep._classify(owner, other)
    assert verdict == "ERROR"
    assert "Connection refused" in detail


def test_classify_error_when_other_request_failed():
    owner = FetchResult(status=200, body="real data")
    other = FetchResult(status=None, body="", error="timed out")
    verdict, ratio, detail = idor_sweep._classify(owner, other)
    assert verdict == "ERROR"
    assert "timed out" in detail


def test_classify_error_on_unexpected_other_status():
    owner = FetchResult(status=200, body="real data")
    other = FetchResult(status=500, body="")
    verdict, ratio, detail = idor_sweep._classify(owner, other)
    assert verdict == "ERROR"


def test_sweep_result_summary_counts():
    result = idor_sweep.SweepResult(url_template="https://target.com/api/orders/{id}")
    result.verdicts = [
        idor_sweep.IdVerdict(object_id="1", owner_status=200, other_status=200, verdict="LEAKED"),
        idor_sweep.IdVerdict(object_id="2", owner_status=200, other_status=403, verdict="PROTECTED"),
        idor_sweep.IdVerdict(object_id="3", owner_status=200, other_status=403, verdict="PROTECTED"),
    ]
    assert result.summary_counts() == {"LEAKED": 1, "PROTECTED": 2}


def test_check_one_id_url_and_body_substitute_id_placeholder(monkeypatch):
    calls = []

    def fake_fetch(url, method, headers, body, timeout_s):
        calls.append((url, headers.get("Cookie"), body))
        return FetchResult(status=200, body="data for " + url)

    monkeypatch.setattr(idor_sweep, "_fetch", fake_fetch)
    verdict = idor_sweep.check_one_id(
        "https://target.com/api/orders/{id}", "4521", "GET",
        {"Cookie": "owner=1"}, {"Cookie": "other=1"},
        None, idor_sweep.DEFAULT_TIMEOUT_S,
    )
    assert calls[0][0] == "https://target.com/api/orders/4521"
    assert calls[1][0] == "https://target.com/api/orders/4521"
    assert calls[0][1] == "owner=1"
    assert calls[1][1] == "other=1"
    assert verdict.object_id == "4521"


# ---------------------------------------------------------------------------
# Single-credential ID-guess mode
# ---------------------------------------------------------------------------

def test_generate_id_guesses_returns_empty_for_non_numeric_id():
    # UUIDs/hashids have no meaningful "neighbor" -- must not pretend to guess.
    assert idor_sweep.generate_id_guesses("f47ac10b-58cc-4372-a567-0e02b2c3d479") == []


def test_generate_id_guesses_never_repeats_known_id():
    guesses = idor_sweep.generate_id_guesses("5", count=20)
    assert "5" not in guesses


def test_generate_id_guesses_tries_admin_like_ids_first():
    guesses = idor_sweep.generate_id_guesses("500", count=10)
    assert guesses[0] == "0"
    assert guesses[1] == "1"


def test_generate_id_guesses_includes_negative_variant_for_positive_base():
    guesses = idor_sweep.generate_id_guesses("500", count=10)
    assert "-500" in guesses


def test_generate_id_guesses_no_negative_variant_when_base_not_positive():
    # known_id=0: no positive base to negate, so "-0" should never appear.
    guesses = idor_sweep.generate_id_guesses("0", count=10)
    assert "-0" not in guesses


def test_generate_id_guesses_includes_sequential_neighbors():
    guesses = idor_sweep.generate_id_guesses("500", count=10)
    assert "501" in guesses
    assert "499" in guesses


def test_generate_id_guesses_respects_count_cap():
    guesses = idor_sweep.generate_id_guesses("500", count=4)
    assert len(guesses) == 4


def test_generate_id_guesses_no_duplicates():
    guesses = idor_sweep.generate_id_guesses("1", count=10)
    assert len(guesses) == len(set(guesses))


def test_classify_guess_protected_on_403():
    verdict, detail = idor_sweep._classify_guess(FetchResult(status=403, body=""))
    assert verdict == "PROTECTED"


def test_classify_guess_accessible_on_200_with_body():
    verdict, detail = idor_sweep._classify_guess(FetchResult(status=200, body="real object data"))
    assert verdict == "ACCESSIBLE"
    assert "verify by hand" in detail


def test_classify_guess_empty_response_on_200_empty_body():
    verdict, detail = idor_sweep._classify_guess(FetchResult(status=200, body="   "))
    assert verdict == "EMPTY_RESPONSE"


def test_classify_guess_error_on_request_failure():
    verdict, detail = idor_sweep._classify_guess(FetchResult(status=None, body="", error="timed out"))
    assert verdict == "ERROR"
    assert "timed out" in detail


def test_classify_guess_error_on_unexpected_status():
    verdict, detail = idor_sweep._classify_guess(FetchResult(status=500, body=""))
    assert verdict == "ERROR"


def test_check_one_guess_substitutes_id_placeholder(monkeypatch):
    calls = []

    def fake_fetch(url, method, headers, body, timeout_s):
        calls.append(url)
        return FetchResult(status=200, body="data")

    monkeypatch.setattr(idor_sweep, "_fetch", fake_fetch)
    verdict = idor_sweep.check_one_guess(
        "https://target.com/api/orders/{id}", "0", "GET", {"Cookie": "session=1"},
        None, idor_sweep.DEFAULT_TIMEOUT_S,
    )
    assert calls == ["https://target.com/api/orders/0"]
    assert verdict.object_id == "0"
    assert verdict.verdict == "ACCESSIBLE"


def test_sweep_idor_guess_skips_guessing_when_baseline_fails(monkeypatch):
    def fake_fetch(url, method, headers, body, timeout_s):
        return FetchResult(status=401, body="")  # dead/invalid credential

    monkeypatch.setattr(idor_sweep, "_fetch", fake_fetch)
    result = idor_sweep.sweep_idor_guess(
        "https://target.com/api/orders/{id}", "500", cookie_header="session=dead",
    )
    assert result.baseline_ok is False
    assert result.verdicts == []
    assert "invalid/expired" in result.baseline_detail


def test_sweep_idor_guess_proceeds_when_baseline_ok(monkeypatch):
    seen_urls = []

    def fake_fetch(url, method, headers, body, timeout_s):
        seen_urls.append(url)
        if url.endswith("/500"):
            return FetchResult(status=200, body="owner's own order")
        return FetchResult(status=403, body="")  # every guess is protected

    monkeypatch.setattr(idor_sweep, "_fetch", fake_fetch)
    result = idor_sweep.sweep_idor_guess(
        "https://target.com/api/orders/{id}", "500", cookie_header="session=alive", guess_count=5,
    )
    assert result.baseline_ok is True
    assert len(result.verdicts) == 5
    assert all(v.verdict == "PROTECTED" for v in result.verdicts)
    assert result.summary_counts() == {"PROTECTED": 5}


def test_guess_sweep_result_summary_counts():
    result = idor_sweep.GuessSweepResult(url_template="https://target.com/api/orders/{id}", known_id="1")
    result.verdicts = [
        idor_sweep.GuessVerdict(object_id="0", status=200, verdict="ACCESSIBLE"),
        idor_sweep.GuessVerdict(object_id="2", status=403, verdict="PROTECTED"),
        idor_sweep.GuessVerdict(object_id="3", status=403, verdict="PROTECTED"),
    ]
    assert result.summary_counts() == {"ACCESSIBLE": 1, "PROTECTED": 2}
