"""P4-M1 Task 1 -- read-only captured-request corpus builder.

invariant_corpus.build_corpus() assembles the observed-exchange corpus the
invariant probe consumes, from already-captured Burp-import endpoints (identity
from the auth/cookie header, resource from the path, status, and the REAL
request skeleton as `base_request`). Bodies are not stored by Burp, so `body`
is "" -- the probe degrades to high recall (Task 2); CEM stays the precision
gate. Pure/read-only: no network, no subprocess, no writes.
"""
from __future__ import annotations

import json

import invariant_corpus


def _burp_row(id, method, url, headers, status=200, host="app.example.com", path=None):
    from urllib.parse import urlsplit
    return {
        "id": id, "method": method, "url": url, "host": host,
        "path": path if path is not None else urlsplit(url).path,
        "status": status, "mimetype": "application/json",
        "headers_json": json.dumps(headers),
    }


def test_build_corpus_extracts_identity_resource_status_from_burp_rows():
    rows = [
        _burp_row(1, "GET", "https://app.example.com/orders/42",
                  {"Authorization": "Bearer alice-token"}),
        _burp_row(2, "GET", "https://app.example.com/orders/42",
                  {"Authorization": "Bearer bob-token"}),
    ]
    corpus = invariant_corpus.build_corpus("app.example.com", burp_rows=rows)
    assert len(corpus) == 2
    assert {e["resource"] for e in corpus} == {"/orders/42"}
    assert len({e["identity"] for e in corpus}) == 2
    assert all(e["status"] == 200 for e in corpus)
    # the real captured request is carried for CEM real-request mapping
    assert corpus[0]["base_request"]["url"] == "https://app.example.com/orders/42"
    assert corpus[0]["base_request"]["method"] == "GET"
    assert "Authorization" in corpus[0]["base_request"]["headers"]


def test_identity_label_is_redacted_and_stable():
    h = {"Authorization": "Bearer super-secret-token-value"}
    a = invariant_corpus.identity_label(h)
    b = invariant_corpus.identity_label(dict(h))
    assert a == b                      # stable
    assert "super-secret-token-value" not in a   # redacted, never the raw token
    assert a != invariant_corpus.identity_label({"Authorization": "Bearer other"})
    assert invariant_corpus.identity_label({}) == "anon"


def test_body_absent_yields_empty_string_not_missing():
    rows = [_burp_row(1, "GET", "https://app.example.com/orders/42",
                      {"Cookie": "session=alice"})]
    corpus = invariant_corpus.build_corpus("app.example.com", burp_rows=rows)
    assert corpus[0]["body"] == ""


def test_non_get_method_row_is_marked_not_cem_eligible():
    rows = [_burp_row(1, "POST", "https://app.example.com/orders",
                      {"Authorization": "Bearer alice"})]
    corpus = invariant_corpus.build_corpus("app.example.com", burp_rows=rows)
    assert corpus[0]["base_request"]["method"] == "POST"   # preserved, Task 2 excludes from CEM


def test_resource_of_strips_query_string():
    assert invariant_corpus.resource_of("https://h/orders/42?token=x") == "/orders/42"


def test_action_of_maps_get_to_read():
    assert invariant_corpus.action_of("GET") == "read"
    assert invariant_corpus.action_of("HEAD") == "read"
    assert invariant_corpus.action_of("DELETE") == "delete"


def test_malformed_row_is_skipped_not_fatal():
    rows = [
        {"id": 1, "method": "GET", "url": "https://app.example.com/ok",
         "path": "/ok", "status": 200, "headers_json": "{not json"},   # bad json
        _burp_row(2, "GET", "https://app.example.com/orders/7",
                  {"Authorization": "Bearer alice"}),
    ]
    corpus = invariant_corpus.build_corpus("app.example.com", burp_rows=rows)
    assert [e["resource"] for e in corpus] == ["/orders/7"]   # bad row skipped, good row kept


def test_empty_or_none_source_returns_empty_list():
    assert invariant_corpus.build_corpus("app.example.com", burp_rows=[]) == []
    assert invariant_corpus.build_corpus("app.example.com", burp_rows=None, db_path="/nonexistent") == []
