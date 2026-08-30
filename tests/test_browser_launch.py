import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mcp-servers"))
from browser_launch import STEALTH_ARGS, launch_kwargs, parse_cookie_header


def test_launch_kwargs_includes_stability_and_stealth_args():
    args = launch_kwargs()["args"]
    assert "--no-sandbox" in args
    assert "--disable-dev-shm-usage" in args
    for stealth_arg in STEALTH_ARGS:
        assert stealth_arg in args


def test_launch_kwargs_stealth_args_include_automation_controlled_flag():
    # The one flag that actually matters here (see browser_launch.py's own
    # comment): without it, Chromium sets navigator.webdriver=true, which
    # basic bot-detection JS can key off even on an otherwise-normal page.
    assert "--disable-blink-features=AutomationControlled" in STEALTH_ARGS


def test_launch_kwargs_is_headless_by_default():
    assert launch_kwargs()["headless"] is True


def test_parse_cookie_header_single_cookie():
    cookies = parse_cookie_header("session=abc123", "https://target.com/app")
    assert cookies == [{"name": "session", "value": "abc123", "domain": "target.com", "path": "/"}]


def test_parse_cookie_header_multiple_cookies():
    cookies = parse_cookie_header("session=abc123; csrftoken=xyz789", "https://target.com/app")
    assert cookies == [
        {"name": "session", "value": "abc123", "domain": "target.com", "path": "/"},
        {"name": "csrftoken", "value": "xyz789", "domain": "target.com", "path": "/"},
    ]


def test_parse_cookie_header_strips_whitespace():
    cookies = parse_cookie_header("  session = abc123 ;  csrftoken=xyz789  ", "https://target.com/")
    assert cookies == [
        {"name": "session", "value": "abc123", "domain": "target.com", "path": "/"},
        {"name": "csrftoken", "value": "xyz789", "domain": "target.com", "path": "/"},
    ]


def test_parse_cookie_header_value_can_contain_equals():
    # JWTs and base64 values often contain '=' padding -- must split on the
    # FIRST '=' only, not treat a later one as a separate cookie.
    cookies = parse_cookie_header("token=abc=def=ghi", "https://target.com/")
    assert cookies == [{"name": "token", "value": "abc=def=ghi", "domain": "target.com", "path": "/"}]


def test_parse_cookie_header_skips_malformed_segments():
    cookies = parse_cookie_header("session=abc123; ; malformed; csrftoken=xyz789", "https://target.com/")
    assert cookies == [
        {"name": "session", "value": "abc123", "domain": "target.com", "path": "/"},
        {"name": "csrftoken", "value": "xyz789", "domain": "target.com", "path": "/"},
    ]


def test_parse_cookie_header_empty_string_returns_empty_list():
    assert parse_cookie_header("", "https://target.com/") == []


def test_parse_cookie_header_scopes_domain_from_url():
    cookies = parse_cookie_header("session=abc123", "https://api.target.com:8443/v1/data")
    assert cookies[0]["domain"] == "api.target.com"
