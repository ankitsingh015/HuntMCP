import base64
import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BURP_DIR = os.path.join(ROOT, "mcp-servers", "burp-import-mcp")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(BURP_DIR, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


parser = _load("burp_import_parser", "parser.py")
db = _load("burp_import_db", "db.py")


def _b64(raw_request: str) -> str:
    return base64.b64encode(raw_request.encode()).decode()


AUTHED_REQUEST = "GET /api/profile HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123\r\n\r\n"
ANON_REQUEST = "GET /robots.txt HTTP/1.1\r\nHost: example.com\r\n\r\n"
BEARER_REQUEST = "GET /api/orders HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer eyJabc\r\n\r\n"


def _sample_xml() -> str:
    return f"""<?xml version="1.0"?>
<items burpVersion="2023.1" exportTime="Mon Jan 01 00:00:00 GMT 2024">
<item>
<time>Mon Jan 01 12:00:00 GMT 2024</time>
<url><![CDATA[https://example.com/api/profile]]></url>
<host ip="93.184.216.34">example.com</host>
<port>443</port>
<protocol>https</protocol>
<method><![CDATA[GET]]></method>
<path><![CDATA[/api/profile]]></path>
<extension>null</extension>
<request base64="true"><![CDATA[{_b64(AUTHED_REQUEST)}]]></request>
<status>200</status>
<responselength>1234</responselength>
<mimetype>JSON</mimetype>
<response base64="true"><![CDATA[e30=]]></response>
<comment></comment>
</item>
<item>
<time>Mon Jan 01 12:01:00 GMT 2024</time>
<url><![CDATA[https://example.com/robots.txt]]></url>
<host ip="93.184.216.34">example.com</host>
<port>443</port>
<protocol>https</protocol>
<method><![CDATA[GET]]></method>
<path><![CDATA[/robots.txt]]></path>
<extension>txt</extension>
<request base64="true"><![CDATA[{_b64(ANON_REQUEST)}]]></request>
<status>200</status>
<responselength>50</responselength>
<mimetype>text</mimetype>
<response base64="true"><![CDATA[]]></response>
<comment></comment>
</item>
<item>
<time>Mon Jan 01 12:02:00 GMT 2024</time>
<url><![CDATA[https://example.com/api/orders]]></url>
<host ip="93.184.216.34">example.com</host>
<port>443</port>
<protocol>https</protocol>
<method><![CDATA[GET]]></method>
<path><![CDATA[/api/orders]]></path>
<extension>null</extension>
<request base64="true"><![CDATA[{_b64(BEARER_REQUEST)}]]></request>
<status>200</status>
<responselength>500</responselength>
<mimetype>JSON</mimetype>
<response base64="true"><![CDATA[W10=]]></response>
<comment></comment>
</item>
</items>"""


def test_parse_burp_xml_extracts_all_items():
    entries = parser.parse_burp_xml(_sample_xml())
    assert len(entries) == 3


def test_parse_burp_xml_detects_cookie_auth():
    entries = parser.parse_burp_xml(_sample_xml())
    profile = next(e for e in entries if e["path"] == "/api/profile")
    assert profile["has_cookie"] is True
    assert profile["has_auth_header"] is False
    assert profile["headers"]["Cookie"] == "session=abc123"


def test_parse_burp_xml_detects_bearer_auth():
    entries = parser.parse_burp_xml(_sample_xml())
    orders = next(e for e in entries if e["path"] == "/api/orders")
    assert orders["has_auth_header"] is True
    assert orders["headers"]["Authorization"] == "Bearer eyJabc"


def test_parse_burp_xml_anonymous_request_has_no_auth():
    entries = parser.parse_burp_xml(_sample_xml())
    robots = next(e for e in entries if e["path"] == "/robots.txt")
    assert robots["has_cookie"] is False
    assert robots["has_auth_header"] is False


def test_parse_burp_xml_extracts_method_status_host():
    entries = parser.parse_burp_xml(_sample_xml())
    profile = next(e for e in entries if e["path"] == "/api/profile")
    assert profile["method"] == "GET"
    assert profile["status"] == 200
    assert profile["host"] == "example.com"
    assert profile["url"] == "https://example.com/api/profile"


def test_parse_burp_xml_invalid_xml_raises():
    import pytest

    with pytest.raises(ValueError):
        parser.parse_burp_xml("not xml at all <<<")


def test_parse_burp_xml_empty_items_returns_empty_list():
    entries = parser.parse_burp_xml('<?xml version="1.0"?><items></items>')
    assert entries == []


def test_parse_burp_xml_skips_malformed_item_without_aborting():
    xml = """<?xml version="1.0"?>
<items>
<item>
<url><![CDATA[https://example.com/good]]></url>
<host ip="1.2.3.4">example.com</host>
<method><![CDATA[GET]]></method>
<path><![CDATA[/good]]></path>
<status>not-a-number-but-shouldnt-crash</status>
</item>
<item>
</item>
</items>"""
    entries = parser.parse_burp_xml(xml)
    # First item survives (status just becomes None rather than crashing),
    # second (no url/host at all) is skipped.
    assert len(entries) == 1
    assert entries[0]["path"] == "/good"
    assert entries[0]["status"] is None


def test_parse_raw_headers_word_stops_at_blank_line():
    raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY-SHOULD-NOT-BE-PARSED-AS-HEADER: yes"
    headers, _has_cookie, _has_auth = parser._parse_raw_headers(raw)
    assert "BODY-SHOULD-NOT-BE-PARSED-AS-HEADER" not in headers
    assert headers["Host"] == "example.com"


# --- db.py ---

def test_import_entries_counts_new_vs_updated(tmp_path):
    p = str(tmp_path / "burp-import.db")
    entries = parser.parse_burp_xml(_sample_xml())

    first = db.import_entries("example.com", entries, source_file="export1.xml", path=p)
    assert first["imported"] == 3
    assert first["updated"] == 0
    assert first["authenticated"] == 2  # profile (cookie) + orders (bearer)

    second = db.import_entries("example.com", entries, source_file="export2.xml", path=p)
    assert second["imported"] == 0
    assert second["updated"] == 3


def test_list_endpoints_filters_by_target(tmp_path):
    p = str(tmp_path / "burp-import.db")
    entries = parser.parse_burp_xml(_sample_xml())
    db.import_entries("example.com", entries, source_file="export.xml", path=p)
    db.import_entries("other.com", entries[:1], source_file="export.xml", path=p)

    rows = db.list_endpoints(target="example.com", path=p)
    assert len(rows) == 3
    assert all(r["target"] == "example.com" for r in rows)


def test_list_endpoints_authenticated_only_filter(tmp_path):
    p = str(tmp_path / "burp-import.db")
    entries = parser.parse_burp_xml(_sample_xml())
    db.import_entries("example.com", entries, source_file="export.xml", path=p)

    rows = db.list_endpoints(target="example.com", authenticated_only=True, path=p)
    assert len(rows) == 2
    paths = {r["path"] for r in rows}
    assert paths == {"/api/profile", "/api/orders"}


def test_get_endpoint_returns_full_headers(tmp_path):
    import json

    p = str(tmp_path / "burp-import.db")
    entries = parser.parse_burp_xml(_sample_xml())
    db.import_entries("example.com", entries, source_file="export.xml", path=p)

    rows = db.list_endpoints(target="example.com", authenticated_only=True, path=p)
    profile_row = next(r for r in rows if r["path"] == "/api/profile")

    fetched = db.get_endpoint(profile_row["id"], path=p)
    headers = json.loads(fetched["headers_json"])
    assert headers["Cookie"] == "session=abc123"


def test_get_endpoint_unknown_id_returns_none(tmp_path):
    p = str(tmp_path / "burp-import.db")
    assert db.get_endpoint(999999, path=p) is None
