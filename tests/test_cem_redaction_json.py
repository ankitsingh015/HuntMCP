"""CEM bundle/provenance redaction, JSON-aware (closes the secret-in-JSON-key and non-canonical
header-name halves of docs/cem-phase1-limitations.md C8, without changing any CEM verdict logic).
Narrow by design: only (a) string leaves that are JSON objects/arrays and (b) the children of a dict
stored under the key "headers" get key-aware treatment -- never arbitrary dict keys, because CEM's own
structural dicts use condition names such as session_cookie / auth_cookie as keys."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

import case_store  # noqa: E402
import cem_engine  # noqa: E402
from redact import redact_text  # noqa: E402

R = cem_engine._redact_recursive


def test_a_json_object_string_has_secret_named_keys_redacted_and_the_rest_kept():
    body = json.dumps({"user": "alice", "payment_token": "tok_live_abcdef123456", "n": {"api_key": "sk_live_zzzzzzzz1234"}})
    out = R({"body": body})["body"]
    assert "tok_live_abcdef123456" not in out and "sk_live_zzzzzzzz1234" not in out
    assert json.loads(out)["user"] == "alice"


def test_a_json_string_with_nothing_to_redact_is_returned_byte_for_byte_as_before():
    body = '{ "user":"alice",  "items": [1, 2, 3] }'  # odd spacing must survive: it is evidence
    assert R({"body": body})["body"] == redact_text(body) == body


def test_a_non_json_string_behaves_exactly_as_before():
    for text in ("plain text", "token=abc123def456", "[not json", "{broken"):
        assert R(text) == redact_text(text)


def test_json_arrays_are_covered_too():
    out = R(json.dumps([{"password": "hunter2hunter2"}, {"ok": 1}]))
    assert "hunter2hunter2" not in out and json.loads(out)[1] == {"ok": 1}


def test_non_canonical_secret_header_names_are_redacted_inside_a_headers_dict():
    out = R({"headers": {"X-Auth-Token": "opaque123456789", "X-Session-Id": "sess123456789",
                         "Content-Type": "application/json", "Authorization": "Bearer abcdefghijk"}})
    h = out["headers"]
    assert "opaque123456789" not in str(h) and "sess123456789" not in str(h) and "abcdefghijk" not in str(h)
    assert h["Content-Type"] == "application/json"


def test_header_dict_nested_under_a_request_is_found():
    out = R({"request": {"url": "http://t/", "headers": {"x-api-key": "k3y-value-123456"}}})
    assert "k3y-value-123456" not in str(out)


def test_condition_names_and_other_structural_keys_are_never_treated_as_secret_keys():
    data = {"verdicts": {"session_cookie": "necessary", "auth_cookie": "apparently_not_necessary"},
            "controls": {"session_cookie": "pinned"}}
    assert R(data) == data


def test_absurdly_deep_json_text_is_withheld_not_stored_raw_and_never_raises():
    deep = '{"a":' * 100000 + '{"payment_token":"tok_live_abcdef123456"}' + "}" * 100000
    out = R({"body": deep})["body"]
    assert "tok_live_abcdef123456" not in out


def test_provenance_inherits_the_json_aware_redaction():
    prov = {"method": "POST", "url": "http://t/", "headers": {"X-Auth-Token": "opaque123456789"},
            "body": '{"refresh_token": "rt-abcdef123456"}'}
    out = case_store._redact_provenance(prov)
    assert "opaque123456789" not in str(out) and "rt-abcdef123456" not in str(out)
    assert out["method"] == "POST" and out["url"] == "http://t/"


def test_a_secret_in_a_json_key_is_still_redacted_when_the_body_also_has_a_secret_named_key():
    """Regression guard: the old whole-string redact_text() hid key=value / JWT text inside object
    KEYS; the structured path must not lose that just because it found a secret-named key."""
    body = json.dumps({"password": "p", "https://x/y?api_key=SECRETKEY123": 200})
    assert "SECRETKEY123" not in R({"body": body})["body"]


def test_a_body_with_nan_and_nothing_to_redact_is_returned_byte_for_byte():
    body = '{"v": NaN, "user": "alice",  "w": Infinity}'
    assert R({"body": body})["body"] == redact_text(body) == body


def test_a_body_with_a_huge_integer_still_gets_its_secret_named_keys_redacted():
    body = '{"payment_token": "tok_live_SECRET123", "n": ' + "9" * 5000 + "}"
    out = R({"response": body})["response"]
    assert "tok_live_SECRET123" not in out
