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


def _verdicts(*verdicts: str) -> list:
    return [
        idor_sweep.IdVerdict(object_id=str(i), owner_status=None, other_status=None, verdict=v)
        for i, v in enumerate(verdicts)
    ]


def test_owner_baseline_failure_warning_none_when_all_healthy():
    result = idor_sweep.SweepResult(url_template="https://target.com/api/orders/{id}")
    result.verdicts = _verdicts("PROTECTED", "LEAKED", "PROTECTED", "DIFFERENT")
    assert result.owner_baseline_failure_warning() is None


def test_owner_baseline_failure_warning_none_below_min_sample():
    # 2/2 = 100% OWNER_BASELINE_FAILED, but below OWNER_BASELINE_FAILURE_MIN_SAMPLE
    # (3) -- too small a batch to call it systemic rather than two bad ids.
    result = idor_sweep.SweepResult(url_template="https://target.com/api/orders/{id}")
    result.verdicts = _verdicts("OWNER_BASELINE_FAILED", "OWNER_BASELINE_FAILED")
    assert result.owner_baseline_failure_warning() is None


def test_owner_baseline_failure_warning_none_below_ratio_threshold():
    # 1/4 = 25% OWNER_BASELINE_FAILED -- plausibly just one bad id, not systemic.
    result = idor_sweep.SweepResult(url_template="https://target.com/api/orders/{id}")
    result.verdicts = _verdicts("OWNER_BASELINE_FAILED", "PROTECTED", "PROTECTED", "LEAKED")
    assert result.owner_baseline_failure_warning() is None


def test_owner_baseline_failure_warning_fires_above_ratio_threshold():
    # 4/5 = 80% OWNER_BASELINE_FAILED -- meets the threshold exactly.
    result = idor_sweep.SweepResult(url_template="https://target.com/api/orders/{id}")
    result.verdicts = _verdicts(
        "OWNER_BASELINE_FAILED", "OWNER_BASELINE_FAILED", "OWNER_BASELINE_FAILED",
        "OWNER_BASELINE_FAILED", "PROTECTED",
    )
    warning = result.owner_baseline_failure_warning()
    assert warning is not None
    assert "4/5" in warning
    assert "80%" in warning
    assert "owner_cookie_header" in warning and "owner_bearer_token" in warning


def test_owner_baseline_failure_warning_fires_when_every_id_fails():
    result = idor_sweep.SweepResult(url_template="https://target.com/api/orders/{id}")
    result.verdicts = _verdicts(*(["OWNER_BASELINE_FAILED"] * 5))
    warning = result.owner_baseline_failure_warning()
    assert warning is not None
    assert "5/5" in warning and "100%" in warning


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
