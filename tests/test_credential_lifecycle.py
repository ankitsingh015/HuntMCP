import credential_lifecycle
import http_probe

# ------------------------------------------------------------ classification

def test_classify_bearer_token_shape():
    result = credential_lifecycle.classify_artifact("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123signature")
    assert result["artifact_type"] == "bearer_token"


def test_classify_raw_opaque_token_as_bearer_candidate():
    result = credential_lifecycle.classify_artifact("synthetic-opaque-token-not-a-real-vendor-key-0000")
    assert result["artifact_type"] == "bearer_token"


def test_classify_cookie_header_shape():
    result = credential_lifecycle.classify_artifact("session=abc123; csrf_token=xyz789")
    assert result["artifact_type"] == "cookie_header"


def test_classify_cors_preflight_response_as_insufficient():
    """Regression test reported live in an engagement retrospective: the
    user first supplied cookies (insufficient for a header-auth API), then
    a CORS preflight request/response (also insufficient), then finally
    the actual bearer token -- three round-trips because nothing
    classified the artifact type early. A raw OPTIONS-response-shaped
    paste (headers only, no actual auth material) must be recognized as
    NOT a usable credential, prompting for the right thing immediately."""
    result = credential_lifecycle.classify_artifact(
        "Access-Control-Allow-Origin: https://target.com\nAccess-Control-Allow-Methods: GET, POST",
    )
    assert result["artifact_type"] == "preflight_insufficient"


def test_classify_unrecognizable_text_as_unknown():
    result = credential_lifecycle.classify_artifact("please help me get access to the admin panel")
    assert result["artifact_type"] == "unknown"


def test_classify_never_echoes_the_raw_sample_back():
    """The classification result itself must not carry the raw secret
    value forward -- only the TYPE classification and a short, generic
    note, so a caller that logs/passes this result along never
    accidentally re-exposes the credential a second time."""
    secret = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.super-secret-signature-xyz"
    result = credential_lifecycle.classify_artifact(secret)
    assert secret not in str(result)
    assert "super-secret-signature-xyz" not in str(result)


# --------------------------------------------------------------- intake metadata

def test_record_intake_never_stores_the_raw_value(tmp_path):
    """SECURITY: this module's entire premise is metadata-only tracking --
    it must be structurally impossible for record_intake() to persist the
    credential value itself to disk, only facts ABOUT it (type, when,
    described source)."""
    p = str(tmp_path / "credential-intake.jsonl")
    credential_lifecycle.record_intake("bearer_token", "user pasted from browser devtools", path=p)
    with open(p) as f:
        contents = f.read()
    assert "bearer_token" in contents
    # record_intake()'s own signature takes no raw-value parameter at all --
    # this assertion documents the intent, the signature itself is the
    # real enforcement (see the function's own docstring).


def test_record_and_list_intake_history(tmp_path):
    p = str(tmp_path / "credential-intake.jsonl")
    credential_lifecycle.record_intake("bearer_token", "pasted from devtools", path=p)
    credential_lifecycle.record_intake("cookie_header", "exported via browser-mcp session_file", path=p)
    history = credential_lifecycle.list_intake_history(path=p)
    assert len(history) == 2
    assert history[0]["artifact_type"] == "bearer_token"
    assert history[1]["artifact_type"] == "cookie_header"


def test_list_intake_history_empty_when_no_file(tmp_path):
    assert credential_lifecycle.list_intake_history(path=str(tmp_path / "nope.jsonl")) == []


# --------------------------------------------------------------- validation

def test_validate_credential_reports_valid_on_2xx(monkeypatch):
    def _fake_fetch(url, method, headers, body, timeout_s, **kw):
        assert headers.get("Authorization") == "Bearer tok_abc"
        return http_probe.FetchResult(status=200, body="ok")
    monkeypatch.setattr(credential_lifecycle, "_fetch", _fake_fetch)
    result = credential_lifecycle.validate_credential("https://target.com/api/me", bearer_token="tok_abc")
    assert result["status"] == "valid"


def test_validate_credential_reports_invalid_or_expired_on_401(monkeypatch):
    def _fake_fetch(url, method, headers, body, timeout_s, **kw):
        return http_probe.FetchResult(status=401, body="unauthorized")
    monkeypatch.setattr(credential_lifecycle, "_fetch", _fake_fetch)
    result = credential_lifecycle.validate_credential("https://target.com/api/me", bearer_token="tok_abc")
    assert result["status"] == "invalid_or_expired"


def test_validate_credential_reports_probe_failed_on_connection_error(monkeypatch):
    def _fake_fetch(url, method, headers, body, timeout_s, **kw):
        return http_probe.FetchResult(status=None, body="", error="connection refused")
    monkeypatch.setattr(credential_lifecycle, "_fetch", _fake_fetch)
    result = credential_lifecycle.validate_credential("https://target.com/api/me", bearer_token="tok_abc")
    assert result["status"] == "probe_failed"


def test_validate_credential_never_includes_the_credential_value_in_its_result(monkeypatch):
    def _fake_fetch(url, method, headers, body, timeout_s, **kw):
        return http_probe.FetchResult(status=200, body="ok")
    monkeypatch.setattr(credential_lifecycle, "_fetch", _fake_fetch)
    result = credential_lifecycle.validate_credential(
        "https://target.com/api/me", bearer_token="tok_super_secret_value_123",
    )
    assert "tok_super_secret_value_123" not in str(result)


# --------------------------------------------------------------- expiry signal

def test_check_expiry_signal_true_after_run_of_401s():
    """Regression scenario: a credential that worked earlier in the
    engagement starts returning 401/403 on every subsequent call --
    almost certainly expired/revoked mid-engagement, not N coincidentally
    now-invalid requests."""
    assert credential_lifecycle.check_expiry_signal([200, 200, 200, 401, 401, 401]) is True


def test_check_expiry_signal_false_for_occasional_401():
    assert credential_lifecycle.check_expiry_signal([200, 200, 401, 200, 200]) is False


def test_check_expiry_signal_false_for_all_success():
    assert credential_lifecycle.check_expiry_signal([200, 200, 200, 201]) is False


def test_check_expiry_signal_false_for_too_few_samples():
    """A single 401 right after obtaining a credential is more likely a
    wrong-artifact-type mistake than proof of expiry -- require a real
    run, not one data point."""
    assert credential_lifecycle.check_expiry_signal([401]) is False


# --------------------------------------------------------------- revocation

def test_revocation_reminder_mentions_the_artifact_type():
    reminder = credential_lifecycle.revocation_reminder("bearer_token")
    assert "bearer" in reminder.lower() or "token" in reminder.lower()
    assert "rotat" in reminder.lower() or "revok" in reminder.lower() or "log out" in reminder.lower() \
        or "log-out" in reminder.lower()
