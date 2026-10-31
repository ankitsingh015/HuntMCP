"""Unit tests for the P3-H4 scan-identification header primitive
(mcp-servers/scan_headers.py).

Pattern mirrors test_scan_policy.py: an engagement.yaml-driven,
independent-of-scope_guard.py module, tested against real tmp_path
engagement files rather than mocks.
"""
import pytest

import scan_headers


def _write_engagement(tmp_path, extra_yaml=""):
    p = tmp_path / "engagement.yaml"
    p.write_text(
        "target: example.com\nin_scope:\n  - example.com\n"
        "out_of_scope:\n  - other.example\n" + extra_yaml,
    )
    return str(p)


# ---------------------------------------------------------------------------
# load_scan_header
# ---------------------------------------------------------------------------

def test_load_scan_header_absent_by_default(tmp_path):
    """An engagement.yaml written before this field existed (or one that
    simply doesn't configure a header) must behave exactly like today --
    no identification header sent."""
    path = _write_engagement(tmp_path)
    assert scan_headers.load_scan_header(path) == {}


def test_load_scan_header_missing_file_returns_empty(tmp_path):
    assert scan_headers.load_scan_header(str(tmp_path / "nope.yaml")) == {}


def test_load_scan_header_reads_name_and_value(tmp_path):
    path = _write_engagement(
        tmp_path, "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    header = scan_headers.load_scan_header(path)
    assert header == {"name": "X-Bug-Bounty", "value": "ankit015"}


def test_load_scan_header_rejects_name_without_value(tmp_path):
    path = _write_engagement(tmp_path, "scan_header_name: X-Bug-Bounty\n")
    header = scan_headers.load_scan_header(path)
    assert "error" in header


def test_load_scan_header_rejects_value_without_name(tmp_path):
    path = _write_engagement(tmp_path, "scan_header_value: ankit015\n")
    header = scan_headers.load_scan_header(path)
    assert "error" in header


def test_load_scan_header_rejects_invalid_header_name_token(tmp_path):
    """A header name must be a valid RFC 7230 token -- rejects e.g. a space
    or colon in the name, which would otherwise corrupt the request line
    once formatted as "name: value"."""
    path = _write_engagement(
        tmp_path, 'scan_header_name: "X Bug: Bounty"\nscan_header_value: ankit015\n',
    )
    header = scan_headers.load_scan_header(path)
    assert "error" in header


def test_load_scan_header_rejects_crlf_in_value(tmp_path):
    """Header-injection guard: a CRLF in the configured value could split
    the request into a second, attacker-shaped header/request."""
    path = _write_engagement(
        tmp_path, 'scan_header_name: X-Bug-Bounty\nscan_header_value: "ankit015\\r\\nEvil: 1"\n',
    )
    header = scan_headers.load_scan_header(path)
    assert "error" in header


def test_load_scan_header_fails_loud_when_pyyaml_unavailable(tmp_path, monkeypatch):
    path = _write_engagement(
        tmp_path, "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    monkeypatch.setattr(scan_headers, "yaml", None)
    header = scan_headers.load_scan_header(path)
    assert "error" in header


# ---------------------------------------------------------------------------
# get_scan_headers -- the destination-boundary enforcement point
# ---------------------------------------------------------------------------

def test_get_scan_headers_attached_for_in_scope_target(tmp_path):
    path = _write_engagement(
        tmp_path, "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    headers = scan_headers.get_scan_headers("https://example.com/orders/1", path)
    assert headers == {"X-Bug-Bounty": "ankit015"}


def test_get_scan_headers_empty_for_out_of_scope_host(tmp_path):
    """The whole point of H4's 'correct destination boundary': this header
    must never reach a host the engagement doesn't authorize, even if it's
    publicly reachable and even if it's a sibling of the real target."""
    path = _write_engagement(
        tmp_path, "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    headers = scan_headers.get_scan_headers("https://attacker.example/anything", path)
    assert headers == {}


def test_get_scan_headers_empty_for_explicitly_excluded_host(tmp_path):
    path = _write_engagement(
        tmp_path, "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    headers = scan_headers.get_scan_headers("https://other.example/", path)
    assert headers == {}


def test_get_scan_headers_empty_when_nothing_configured(tmp_path):
    path = _write_engagement(tmp_path)
    headers = scan_headers.get_scan_headers("https://example.com/", path)
    assert headers == {}


def test_get_scan_headers_empty_when_no_engagement_file(tmp_path):
    headers = scan_headers.get_scan_headers("https://example.com/", str(tmp_path / "nope.yaml"))
    assert headers == {}


def test_get_scan_headers_empty_on_malformed_config(tmp_path):
    """A misconfigured header (e.g. name without value) must fail closed --
    never sent, not sent with a broken/partial value."""
    path = _write_engagement(tmp_path, "scan_header_name: X-Bug-Bounty\n")
    headers = scan_headers.get_scan_headers("https://example.com/", path)
    assert headers == {}


# ---------------------------------------------------------------------------
# get_scan_header_args -- CLI "-H"/custom-flag convenience for scanner MCP
# servers (httpx/nuclei/katana/ffuf/dalfox use "-H"; sqlmap uses "--header")
# ---------------------------------------------------------------------------

def test_get_scan_header_args_default_flag(tmp_path):
    path = _write_engagement(
        tmp_path, "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    args = scan_headers.get_scan_header_args("https://example.com/", path)
    assert args == ["-H", "X-Bug-Bounty: ankit015"]


def test_get_scan_header_args_custom_flag(tmp_path):
    path = _write_engagement(
        tmp_path, "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    args = scan_headers.get_scan_header_args("https://example.com/", path, flag="--header")
    assert args == ["--header", "X-Bug-Bounty: ankit015"]


def test_get_scan_header_args_empty_for_out_of_scope_target(tmp_path):
    path = _write_engagement(
        tmp_path, "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    assert scan_headers.get_scan_header_args("https://attacker.example/", path) == []


def test_get_scan_header_args_empty_when_nothing_configured(tmp_path):
    path = _write_engagement(tmp_path)
    assert scan_headers.get_scan_header_args("https://example.com/", path) == []


# ---------------------------------------------------------------------------
# get_scan_header_args_for_hosts -- batch variant for a tool that takes
# multiple hosts in one invocation (httpx-mcp's probe_hosts/
# screenshot_hosts): the header must only ever be attached if EVERY host
# in the batch is in scope, since a single CLI invocation sends the same
# "-H" flag to every host in the list -- no way to attach it selectively.
# ---------------------------------------------------------------------------

def test_get_scan_header_args_for_hosts_all_in_scope(tmp_path):
    path = _write_engagement(
        tmp_path, "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    args = scan_headers.get_scan_header_args_for_hosts(["example.com", "example.com"], path)
    assert args == ["-H", "X-Bug-Bounty: ankit015"]


def test_get_scan_header_args_for_hosts_empty_if_any_host_out_of_scope(tmp_path):
    path = _write_engagement(
        tmp_path, "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    args = scan_headers.get_scan_header_args_for_hosts(["example.com", "attacker.example"], path)
    assert args == []


def test_get_scan_header_args_for_hosts_empty_for_empty_list(tmp_path):
    path = _write_engagement(
        tmp_path, "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    assert scan_headers.get_scan_header_args_for_hosts([], path) == []


def test_get_scan_header_args_for_hosts_reads_engagement_yaml_only_once(tmp_path, monkeypatch):
    """Efficiency regression: a batch call (httpx-mcp's probe_hosts() can
    pass 50-500+ domains straight from subfinder-mcp's output) must read
    and parse engagement.yaml a constant number of times, not once per
    host -- the config/scope answer is the same for every host in a
    single call, there's nothing host-dependent about reading the file
    itself."""
    path = _write_engagement(
        tmp_path, "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    read_calls = []
    real_load_scan_header = scan_headers.load_scan_header

    def _counting_load_scan_header(p=None):
        read_calls.append(1)
        return real_load_scan_header(p)
    monkeypatch.setattr(scan_headers, "load_scan_header", _counting_load_scan_header)

    hosts = ["example.com"] * 20
    args = scan_headers.get_scan_header_args_for_hosts(hosts, path)

    assert args == ["-H", "X-Bug-Bounty: ankit015"]
    assert len(read_calls) == 1


# ---------------------------------------------------------------------------
# Regression: get_scan_headers()/load_scan_header() must never raise --
# every caller (http_probe.fetch(), each scanner MCP server) relies on a
# graceful {}/error-dict return, never an uncaught exception, for any
# malformed input in engagement.yaml or the URL being checked.
# ---------------------------------------------------------------------------

def test_load_scan_header_rejects_non_string_name_without_raising(tmp_path):
    """A bare YAML scalar (e.g. an unquoted integer) is a plausible typo --
    `scan_header_name: 123` parses as an int, not a str. Must fail loud
    with {"error": ...}, never raise TypeError out of the regex match."""
    path = _write_engagement(
        tmp_path, "scan_header_name: 123\nscan_header_value: ankit015\n",
    )
    header = scan_headers.load_scan_header(path)
    assert "error" in header


def test_load_scan_header_rejects_non_string_value_without_raising(tmp_path):
    path = _write_engagement(
        tmp_path, "scan_header_name: X-Bug-Bounty\nscan_header_value: 123\n",
    )
    header = scan_headers.load_scan_header(path)
    assert "error" in header


def test_load_scan_header_rejects_malformed_yaml_without_raising(tmp_path):
    p = tmp_path / "engagement.yaml"
    p.write_text("target: example.com\nin_scope: [this is not: valid: yaml\n")
    header = scan_headers.load_scan_header(str(p))
    assert "error" in header


def test_get_scan_headers_empty_for_malformed_yaml(tmp_path):
    p = tmp_path / "engagement.yaml"
    p.write_text("target: example.com\nin_scope: [this is not: valid: yaml\n")
    assert scan_headers.get_scan_headers("https://example.com/", str(p)) == {}


def test_get_scan_headers_empty_for_malformed_url_when_header_configured(tmp_path):
    """Regression: a URL shaped like a malformed IPv6 literal must degrade
    to "no header" (matching http_probe.fetch()'s own established
    convention for an unparseable URL), never raise ValueError out of
    scope_guard.is_in_scope()'s internal urlparse() call."""
    path = _write_engagement(
        tmp_path, "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    assert scan_headers.get_scan_headers("http://[::1", path) == {}
