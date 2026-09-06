import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mcp-servers"))
from redact import hash_value, redact_text

# A real-shaped (but fabricated) JWT: header.payload.signature, all valid
# base64url segments, header segment starting with the standard "eyJ".
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

# A real Visa test card number that passes Luhn (a well-known public test
# number, not a live account).
VALID_LUHN_CARD = "4111111111111111"
INVALID_LUHN_16_DIGITS = "1234567890123456"


def test_redact_text_empty_string_returns_empty():
    assert redact_text("") == ""


def test_redact_text_leaves_plain_url_untouched():
    url = "https://target.com/api/orders/4521?page=2&sort=desc"
    assert redact_text(url) == url


def test_redact_text_leaves_uuid_value_untouched():
    url = "https://target.com/api/users/f47ac10b-58cc-4372-a567-0e02b2c3d479"
    assert redact_text(url) == url


def test_redact_text_leaves_ordinary_numeric_id_untouched():
    assert redact_text("object_id=4521") == "object_id=4521"


def test_redact_text_redacts_token_query_param_keeps_key_name():
    result = redact_text("https://target.com/api?token=eyJsomefakevalue")
    assert "token=" in result
    assert "eyJsomefakevalue" not in result
    assert "[REDACTED:token" in result


def test_redact_text_redacts_api_key_query_param():
    result = redact_text("https://target.com/api?api_key=sk_live_abc123")
    assert "sk_live_abc123" not in result
    assert "[REDACTED:" in result


def test_redact_text_does_not_redact_unrelated_key_with_similar_substring():
    # "session_id" must not trip the "session" key check -- only an exact
    # "session=" segment should.
    result = redact_text("https://target.com/api?session_id=4521")
    assert result == "https://target.com/api?session_id=4521"


def test_redact_text_redacts_authorization_header_line():
    text = "Authorization: Bearer abc.def.ghi\nContent-Type: application/json"
    result = redact_text(text)
    assert "abc.def.ghi" not in result
    assert "Authorization: [REDACTED:header-value" in result
    assert "Content-Type: application/json" in result  # untouched


def test_redact_text_redacts_cookie_header_line():
    text = "Cookie: session=s3cr3tvalue; other=1"
    result = redact_text(text)
    assert "s3cr3tvalue" not in result
    assert result.startswith("Cookie: [REDACTED:header-value")


def test_redact_text_redacts_jwt_shape():
    result = redact_text(f"some text {FAKE_JWT} more text")
    assert FAKE_JWT not in result
    assert "[REDACTED:jwt" in result
    assert "some text" in result and "more text" in result


def test_redact_text_redacts_luhn_valid_card_number():
    result = redact_text(f"card on file: {VALID_LUHN_CARD}")
    assert VALID_LUHN_CARD not in result
    assert "[REDACTED:card-number" in result


def test_redact_text_leaves_luhn_invalid_16_digit_number_untouched():
    # Same length as a card number, but fails the Luhn check -- plausibly a
    # long numeric id/order number, not a real card, so left alone.
    result = redact_text(f"order number: {INVALID_LUHN_16_DIGITS}")
    assert INVALID_LUHN_16_DIGITS in result


def test_redact_text_same_secret_produces_same_hash_suffix():
    # Neither "first" nor "second" are deny-listed keys, so the JWT-shape
    # check is what catches both occurrences -- same value, must hash equal,
    # so a reader can tell they're the same secret without seeing it.
    text = f"first={FAKE_JWT} second={FAKE_JWT}"
    result = redact_text(text)
    assert result.count(hash_value(FAKE_JWT)) == 2


def test_hash_value_is_deterministic():
    assert hash_value("secret123") == hash_value("secret123")


def test_hash_value_differs_for_different_inputs():
    assert hash_value("secret123") != hash_value("secret124")


# ---------------------------------------------------------------------------
# Public surface reused by cem_engine._redact_recursive (audit fix): the same
# header-name list _HEADER_LINE_RE is built from, and the same replacement-
# text builder _header_sub/_kv_sub/_jwt_sub/_card_sub all call internally --
# exported so a dict-aware caller can redact a value it already knows came
# from a secret-carrying header KEY, without redact_text ever needing to
# accept a structured dict itself (this module's own documented boundary).
# ---------------------------------------------------------------------------

from redact import KNOWN_SECRET_HEADER_NAMES, redacted


def test_known_secret_header_names_matches_what_header_line_redaction_covers():
    # regression guard: if this list ever changes, _HEADER_LINE_RE's actual
    # coverage changes with it (the regex is built FROM this constant) --
    # pin the exact set so a silent narrowing/widening doesn't go unnoticed.
    assert set(KNOWN_SECRET_HEADER_NAMES) == {"authorization", "cookie", "set-cookie", "x-api-key"}


def test_redacted_matches_the_flat_text_header_line_format_exactly():
    # same value, same reason -- a dict-value caller (cem_engine) building
    # its own replacement via redacted() must produce byte-identical output
    # to what redact_text() already produces for the equivalent flat text,
    # so a bundle mixing both redaction paths looks uniform.
    flat = redact_text(f"Authorization: {FAKE_JWT}")
    _, _, flat_value = flat.partition(": ")
    assert redacted(FAKE_JWT, "header-value") == flat_value


def test_redacted_hash_is_of_the_original_value():
    result = redacted("supersecret", "header-value")
    assert result == f"[REDACTED:header-value sha256:{hash_value('supersecret')}]"
