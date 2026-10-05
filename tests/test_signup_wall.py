import signup_wall


def test_disposable_email_rejection_phrase_is_detected():
    """Regression test reported live in an engagement retrospective: hours
    were spent on failed automated signup attempts (disposable-address
    rejection on an OTP path) before recognizing the wall was a hard,
    policy-level disable rather than a transient test gap. This should
    surface immediately on the FIRST rejection, not after N retries."""
    result = signup_wall.classify_signup_response(
        status=422, body='{"error": "This email domain is not allowed. Disposable email addresses are blocked."}',
    )
    assert result["blocked_reason"] == "disposable_email_rejected"
    assert "human" in result["recommendation"].lower()


def test_ordinary_validation_error_is_not_a_signup_wall():
    result = signup_wall.classify_signup_response(
        status=422, body='{"error": "Password must be at least 8 characters."}',
    )
    assert result["blocked_reason"] is None
    assert result["recommendation"] is None


def test_temp_mail_phrase_variant_is_detected():
    result = signup_wall.classify_signup_response(status=400, body="Temporary email addresses are not permitted.")
    assert result["blocked_reason"] == "disposable_email_rejected"


def test_throwaway_phrase_variant_is_detected():
    result = signup_wall.classify_signup_response(status=403, body="Throwaway email detected -- please use a real address.")
    assert result["blocked_reason"] == "disposable_email_rejected"


def test_successful_signup_response_is_not_a_wall():
    result = signup_wall.classify_signup_response(status=201, body='{"id": "user_123", "status": "created"}')
    assert result["blocked_reason"] is None


def test_none_body_does_not_crash():
    result = signup_wall.classify_signup_response(status=500, body=None)
    assert result["blocked_reason"] is None
