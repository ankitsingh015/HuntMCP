"""redact.redact_structured / is_secret_key -- key-aware redaction for parsed JSON, the part
redact_text() (text-shape only) cannot do. Word-based key matching, not substring."""
import copy
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

import redact  # noqa: E402


@pytest.mark.parametrize("key", ["payment_token", "accessToken", "api_key", "apiKey", "APIKey", "X-Api-Key",
                                 "password", "passwords", "session_id", "authToken", "refresh_token",
                                 "client_secret", "Authorization", "pin", "otp", "cvv", "Cookie", "bearerToken",
                                 "accesstoken", "ACCESSTOKEN", "refreshtoken", "csrftoken", "userpassword",
                                 "dbpassword", "private_key", "privateKey", "accessKey", "signing_key",
                                 "passphrase", "passcode", "pass", "jwt", "sid"])
def test_secret_looking_keys_are_detected(key):
    assert redact.is_secret_key(key)


@pytest.mark.parametrize("key", ["shipping_address", "mapping", "author", "authorized_at", "spinner",
                                 "options", "photo", "owner", "total", "items", "status", "email", "", "123"])
def test_ordinary_keys_are_not_flagged(key):
    assert not redact.is_secret_key(key)


def test_values_under_secret_keys_are_replaced_with_a_stable_hash_marker():
    out = redact.redact_structured({"owner": "alice", "payment_token": "tok_live_abcdef123456"})
    assert out["owner"] == "alice"
    assert "tok_live_abcdef123456" not in str(out) and out["payment_token"].startswith("[REDACTED:")
    again = redact.redact_structured({"payment_token": "tok_live_abcdef123456"})
    assert again["payment_token"] == out["payment_token"]  # same secret -> same marker


def test_nested_dicts_lists_and_container_values_are_covered():
    data = {"a": [{"api_key": "sk_live_zzzzzzzz1234"}, {"ok": 1}],
            "credentials": {"user": "u", "pw": "hunter2hunter2"}, "n": None, "flag": True}
    out = redact.redact_structured(data)
    blob = str(out)
    assert "sk_live_zzzzzzzz1234" not in blob and "hunter2hunter2" not in blob
    assert out["a"][1] == {"ok": 1} and out["n"] is None and out["flag"] is True


def test_secret_key_with_none_or_bool_value_is_left_alone_and_numbers_are_redacted():
    out = redact.redact_structured({"token": None, "session": False, "pin": 123456})
    assert out["token"] is None and out["session"] is False
    assert "123456" not in str(out["pin"])


def test_string_leaves_still_get_text_shape_redaction():
    out = redact.redact_structured({"note": "call https://t/x?access_token=SECRETVALUE123"})
    assert "SECRETVALUE123" not in out["note"]


def test_input_is_not_mutated():
    data = {"password": "p4ssw0rdp4ssw0rd", "x": [1, {"token": "tttttttttt"}]}
    snapshot = copy.deepcopy(data)
    redact.redact_structured(data)
    assert data == snapshot


@pytest.mark.parametrize("key", ["otp", "pin", "cvv", "cvc", "ssn", "pwd", "pass"])
def test_low_entropy_secrets_get_a_marker_with_no_brute_forceable_hash(key):
    out = redact.redact_structured({key: "123456"})
    assert out[key] == f"[REDACTED:{key}]" and "sha256" not in out[key]


def test_high_entropy_secrets_keep_the_equality_hash():
    out = redact.redact_structured({"api_key": "sk_live_zzzzzzzz1234"})
    assert "sha256:" in out["api_key"]


@pytest.mark.parametrize("key", ["password", "passwd", "passcode", "passphrase", "userPassword"])
def test_password_style_values_get_no_brute_forceable_hash(key):
    out = redact.redact_structured({key: "123456"})
    assert "sha256" not in out[key] and "123456" not in out[key]


def test_card_numbers_stored_as_json_numbers_are_redacted():
    out = redact.redact_structured({"number": 4111111111111111, "order": 1234567890123})
    assert "4111111111111111" not in str(out["number"])
    assert out["order"] == 1234567890123  # fails Luhn -> an ordinary id stays


def test_name_value_pairs_use_the_name_as_the_key():
    out = redact.redact_structured({"name": "api_key", "value": "sk_live_zzzzzzzz1234"})
    assert "sk_live_zzzzzzzz1234" not in str(out)
    plain = redact.redact_structured({"name": "city", "value": "Berlin"})
    assert plain["value"] == "Berlin"


def test_totp_codes_are_secret_keys():
    assert redact.is_secret_key("totp") and redact.is_secret_key("totpCode")


def test_secrets_embedded_in_json_object_keys_are_redacted_too():
    url_key = "https://x/y?api_key=SECRETKEY123"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    out = redact.redact_structured({"password": "p", url_key: 200, "items": {jwt: 1}})
    blob = str(out)
    assert "SECRETKEY123" not in blob and jwt not in blob


@pytest.mark.parametrize("key", ["PHPSESSID", "sessid", "JSESSIONID", "connect.sid"])
def test_common_session_cookie_names_are_secret_keys(key):
    assert redact.is_secret_key(key)


def test_ordinary_keys_are_unchanged_by_key_redaction():
    data = {"shipping_address": "x", "items": [{"sku": "abc"}], "n": 1}
    assert redact.redact_structured(data) == data


@pytest.mark.parametrize("key", ["_gh_sess", "SSID", "SAPISID", "sess"])
def test_more_session_cookie_names_are_secret_keys(key):
    assert redact.is_secret_key(key)


# --- eighth review: a body the stdlib JSON parser refuses must not skip key-aware redaction -----

HUGE = "9" * 5000  # int literal longer than Python's 4300-digit limit -> json.loads raises ValueError


def test_loads_for_redaction_survives_huge_integers_and_keeps_them_as_text():
    parsed = redact.loads_for_redaction('{"n": ' + HUGE + ', "k": 1}')
    assert parsed["n"] == HUGE and parsed["k"] == 1


def test_loads_for_redaction_still_rejects_non_json():
    with pytest.raises(ValueError):
        redact.loads_for_redaction("not json")
