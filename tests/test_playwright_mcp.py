import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "playwright_mcp_challenge_solver",
    os.path.join(ROOT, "mcp-servers", "playwright-mcp", "challenge_solver.py"),
)
challenge_solver = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(challenge_solver)


def test_detect_no_challenge_on_clean_page():
    assert challenge_solver._detect_challenge_type(
        "<html><body>Welcome to the app</body></html>", {}
    ) is None


def test_detect_cloudflare_by_body_marker():
    html = "<html><head><title>Just a moment...</title></head></html>"
    assert challenge_solver._detect_challenge_type(html, {}) == "cloudflare"


def test_detect_cloudflare_by_header():
    assert challenge_solver._detect_challenge_type("", {"cf-mitigated": "challenge"}) == "cloudflare"


def test_detect_cloudflare_header_case_insensitive():
    # Real HTTP headers are case-insensitive; response.headers dicts from
    # different clients normalize differently -- confirm the check doesn't
    # silently miss a differently-cased header name/value.
    assert challenge_solver._detect_challenge_type("", {"CF-Mitigated": "Challenge"}) == "cloudflare"


def test_detect_akamai_by_interstitial_marker():
    html = "<html><body><h1>Pardon Our Interruption</h1><p>Reference #18.abc123</p></body></html>"
    assert challenge_solver._detect_challenge_type(html, {}) == "akamai"


def test_detect_does_not_false_positive_on_normal_akamai_telemetry():
    # _abck/sensor_data/ak_bmsc are Akamai's normal client-sensor telemetry --
    # present on nearly every page load on an Akamai-fronted site, challenged
    # or not. Matching on those alone would flag ordinary, unblocked pages as
    # an active challenge (see challenge_solver.py's _CHALLENGE_SIGNATURES
    # comment) -- must not false-positive on a normal page just because the
    # sensor script is present.
    html = "<html><body>Welcome<script>var params={sensor_data:'...'};</script></body></html>"
    assert challenge_solver._detect_challenge_type(html, {}) is None


def test_detect_imperva_by_header():
    # Imperva's signal is the header's mere presence, not a specific value
    # -- confirm a None-valued signature entry matches any header value.
    assert challenge_solver._detect_challenge_type("", {"X-Iinfo": "9-123456-0"}) == "imperva"


def test_detect_imperva_by_cookie_name_in_body():
    html = "document.cookie='incap_ses_123_4567890=abcdef'"
    assert challenge_solver._detect_challenge_type(html, {}) == "imperva"


def test_detect_datadome_by_captcha_redirect():
    html = "window.location='https://geo.captcha-delivery.com/captcha/?initialCid=1'"
    assert challenge_solver._detect_challenge_type(html, {}) == "datadome"


def test_detect_perimeterx_by_press_and_hold():
    html = "<div>Please Press & Hold to confirm you are a human</div>"
    assert challenge_solver._detect_challenge_type(html, {}) == "perimeterx"


def test_detect_does_not_false_positive_on_unrelated_403():
    # A generic 403 with no vendor-specific markers is a WAF rule block
    # (tool_resolver.classify_block()'s territory), not a JS challenge --
    # must not be misclassified as one.
    html = "<html><body>403 Forbidden</body></html>"
    assert challenge_solver._detect_challenge_type(html, {"content-type": "text/html"}) is None


def test_body_still_shows_challenge_true_when_marker_present():
    html = "<html><head><title>Just a moment...</title></head></html>"
    assert challenge_solver._body_still_shows_challenge(html, "cloudflare") is True


def test_body_still_shows_challenge_false_once_marker_clears():
    # The post-wait recheck is deliberately body-markers-only (not a second
    # _detect_challenge_type() call with headers={}) -- see the function's
    # docstring. Confirm it correctly reports "cleared" once the challenge
    # markers are gone from the DOM, independent of the original headers.
    html = "<html><body>Welcome to the app</body></html>"
    assert challenge_solver._body_still_shows_challenge(html, "cloudflare") is False
