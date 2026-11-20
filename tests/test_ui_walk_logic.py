"""#164: pure decision logic for the UI-walk (no browser)."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import ui_walk_logic as L


def test_classify_destructive():
    assert L.classify_control({"tag": "button", "text": "Delete item"}) == "destructive"


def test_classify_logout():
    assert L.classify_control({"tag": "a", "text": "Sign out"}) == "logout"
    assert L.classify_control({"tag": "a", "text": "", "href": "/logout"}) == "logout"


def test_classify_account_delete_beats_destructive():
    assert L.classify_control({"tag": "button", "text": "Delete account"}) == "account-delete"


def test_classify_payment():
    assert L.classify_control({"tag": "button", "text": "Pay now"}) == "payment"


def test_classify_expand_tab():
    assert L.classify_control({"tag": "button", "role": "tab", "text": "API keys"}) == "expand"


def test_classify_submit():
    assert L.classify_control({"tag": "button", "type": "submit", "text": "Save"}) == "submit"


def test_classify_navigational_link():
    assert L.classify_control({"tag": "a", "href": "/items", "text": "Items"}) == "navigational"


def test_classify_unknown_language_is_other():
    # Documents the classifier's limit: Pass 1 interception, not this, is the guarantee.
    assert L.classify_control({"tag": "button", "text": "Löschen"}) == "other"


def test_never_click_set():
    assert L.NEVER_CLICK == frozenset({"logout", "account-delete", "payment"})


def test_signature_ignores_row_index():
    a = {"role": "button", "text": "Edit", "form_action": "", "dom_path": "table>tr:nth-of-type(3)>td>button"}
    b = {"role": "button", "text": "Edit", "form_action": "", "dom_path": "table>tr:nth-of-type(7)>td>button"}
    assert L.control_signature(a, "/items") == L.control_signature(b, "/items")
    assert len(L.control_signature(a, "/items")) == 16


def test_signature_differs_by_text():
    a = {"role": "button", "text": "Edit", "dom_path": "div>button"}
    b = {"role": "button", "text": "View", "dom_path": "div>button"}
    assert L.control_signature(a, "/items") != L.control_signature(b, "/items")


def test_mutating_get_url():
    assert L.is_mutating_get_url("https://x.test/a/logout")
    assert L.is_mutating_get_url("https://x.test/u?action=delete")
    assert not L.is_mutating_get_url("https://x.test/catalog?page=2")
    assert not L.is_mutating_get_url("https://x.test/cancellation-policy")


def test_payment_host():
    assert L.is_payment_host("api.stripe.com")
    assert L.is_payment_host("stripe.com")
    assert not L.is_payment_host("stripe.com.evil.io")
    assert not L.is_payment_host("notstripe.com")


def test_make_canary_shape():
    t = L.make_canary()
    assert t.startswith("hm") and len(t) == 10
    assert L.make_canary() != t


def test_canary_value_text_payload_contains_token():
    v = L.canary_value("hm1234abcd", "text", None)
    assert "hm1234abcd" in v and "onerror" in v


def test_canary_value_keeps_token_under_maxlength():
    v = L.canary_value("hm1234abcd", "text", 12)
    assert len(v) <= 12 and "hm1234abcd" in v


def test_canary_value_email_and_number():
    assert L.canary_value("hm1234abcd", "email", None) == "hm1234abcd@example.com"
    assert L.canary_value("hm1234abcd", "url", None) == "https://example.com/hm1234abcd"
    assert L.canary_value("hm1234abcd", "number", None) == ""


def test_owned_via_created_id_in_url():
    req = {"url": "https://x.test/api/items/42", "body": ""}
    assert L.is_walker_owned(req, {"42"}, "", set())


def test_owned_via_created_id_in_json_body():
    req = {"url": "https://x.test/api/delete", "body": '{"id": "42"}'}
    assert L.is_walker_owned(req, {"42"}, "", set())


def test_owned_via_container_token():
    assert L.is_walker_owned(None, set(), "row hm1234abcd x", {"hm1234abcd"})


def test_not_owned_when_neither():
    req = {"url": "https://x.test/api/items/42", "body": ""}
    assert not L.is_walker_owned(req, {"7"}, "Alice's report", {"hm1234abcd"})


def test_owned_id_match_is_segment_exact():
    req = {"url": "https://x.test/api/items/42", "body": ""}
    assert not L.is_walker_owned(req, {"4"}, "", set())


def test_looks_logged_out():
    assert L.looks_logged_out("https://x.test/login?next=/a", [], True)
    assert L.looks_logged_out("https://x.test/app", [{"text": "Sign in"}], True)
    assert not L.looks_logged_out("https://x.test/app", [{"text": "Sign in"}], False)
    assert not L.looks_logged_out("https://x.test/app", [{"text": "Settings"}], True)


def test_default_scope_check_loopback_needs_no_engagement():
    assert L._default_scope_check("http://127.0.0.1:8000/")


def test_default_scope_check_external_without_engagement_is_false():
    assert not L._default_scope_check("https://real-target-unlisted.com/")


def test_canary_value_contenteditable_is_textlike():
    assert "hm1234abcd" in L.canary_value("hm1234abcd", "contenteditable", None)


# ---- review fixes ------------------------------------------------------------
def test_url_has_segment_is_exact():
    assert L.url_has_segment("https://x.test/api/items/1", "1")
    assert L.url_has_segment("https://x.test/api/items?id=1", "1")
    assert not L.url_has_segment("https://x.test/api/items/10", "1")
    assert not L.url_has_segment("https://x.test/api/items/1abc", "1")


def test_make_canary_short_length_for_maxlength_fields():
    t = L.make_canary(6)
    assert t.startswith("hm") and len(t) == 6
    assert L.canary_value(t, "text", 6) == t


def test_form_is_unsafe_to_submit():
    assert L.form_unsafe_reason([{"tag": "button", "type": "submit", "text": "Close account"}], "") == "account-delete"
    assert L.form_unsafe_reason([{"tag": "button", "text": "Place order"}], "") == "payment"
    assert L.form_unsafe_reason([{"tag": "button", "text": "Delete project"}], "") == "destructive"
    assert L.form_unsafe_reason([{"tag": "button", "text": "Save"}], "https://x.test/u?action=delete") == "mutating-action"
    assert L.form_unsafe_reason([{"tag": "button", "text": "Save"}], "https://x.test/api/p1") is None
