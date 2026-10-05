"""Unit tests for mcp-servers/upload_retrievability.py -- real urllib
requests against a loopback-only stdlib HTTP server (same pattern as
test_http_probe.py/test_cors_probe.py), not a monkeypatched fake.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import upload_retrievability


class _StorageHandler(BaseHTTPRequestHandler):
    """A small fake storage namespace: /objects/<real-id> exists (200),
    everything else under /objects/ returns the SAME static 404 page."""

    _STATIC_404_BODY = b"<html><body>404 Not Found</body></html>"

    def do_GET(self) -> None:
        if self.path == "/objects/real-upload-id.png":
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(b"\x89PNG fake image bytes")
            return
        if self.path == "/objects/anomalous-id":
            # A DIFFERENT 404-shaped response (different body) -- simulates
            # a path that exists at the routing layer (e.g. access-denied)
            # rather than genuinely not existing.
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Forbidden")
            return
        # Every other /objects/* path: the SAME static 404 (the baseline
        # shape a genuinely-nonexistent object returns).
        self.send_response(404)
        self.end_headers()
        self.wfile.write(self._STATIC_404_BODY)

    def log_message(self, *args) -> None:  # silence stdlib request logging
        pass


@pytest.fixture
def storage_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _StorageHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_all_candidates_match_baseline_is_verified_not_retrievable(storage_server):
    result = upload_retrievability.check_retrievability(
        candidate_urls=[
            f"{storage_server}/objects/guess-1",
            f"{storage_server}/objects/guess-2.png",
            f"{storage_server}/objects/guess-3",
        ],
        baseline_url=f"{storage_server}/objects/definitely-nonexistent-control-id",
    )
    assert result.verdict == "verified_not_retrievable"
    assert result.retrievable_at is None
    assert len(result.candidates) == 3
    assert all(c.matches_baseline for c in result.candidates)


def test_a_200_candidate_is_retrievable(storage_server):
    result = upload_retrievability.check_retrievability(
        candidate_urls=[
            f"{storage_server}/objects/guess-1",
            f"{storage_server}/objects/real-upload-id.png",
        ],
        baseline_url=f"{storage_server}/objects/definitely-nonexistent-control-id",
    )
    assert result.verdict == "retrievable"
    assert result.retrievable_at == f"{storage_server}/objects/real-upload-id.png"


def test_anomalous_non_200_non_matching_candidate_is_flagged_not_silently_clean(storage_server):
    """A candidate that's neither a clean 200 NOR indistinguishable from
    the baseline 404 (e.g. a 403 with a different body) must not be
    silently folded into "verified not retrievable" -- that would be
    exactly the false confidence this module exists to avoid."""
    result = upload_retrievability.check_retrievability(
        candidate_urls=[
            f"{storage_server}/objects/guess-1",
            f"{storage_server}/objects/anomalous-id",
        ],
        baseline_url=f"{storage_server}/objects/definitely-nonexistent-control-id",
    )
    assert result.verdict == "unknown_anomalous_response"
    anomalous = [c for c in result.candidates if not c.matches_baseline]
    assert len(anomalous) == 1
    assert anomalous[0].url.endswith("/anomalous-id")


def test_unreachable_baseline_is_unknown_not_a_false_negative():
    """Never auto-assume a clean negative when the baseline itself
    couldn't be established -- same "no auto-derived oracle" principle as
    this repo's CEM success_signature (PHASE1-EXECUTION-PLAN UD-3)."""
    result = upload_retrievability.check_retrievability(
        candidate_urls=["http://127.0.0.1:1/objects/guess-1"],
        baseline_url="http://127.0.0.1:1/objects/control",
        timeout_s=1,
    )
    assert result.verdict == "unknown_baseline_unreachable"
    assert result.retrievable_at is None


def test_empty_candidate_list_is_unknown_no_candidates():
    result = upload_retrievability.check_retrievability(candidate_urls=[], baseline_url="http://127.0.0.1:1/x")
    assert result.verdict == "unknown_no_candidates"
