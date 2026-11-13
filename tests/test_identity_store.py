import json
import os

import engagement_paths
import identity_store


def _seed_identities(label, entry):
    path = engagement_paths.resolve("secrets/identities.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump({label: entry}, f)
    return path


def test_get_headers_builds_cookie_and_authorization():
    _seed_identities(
        "xyz",
        {
            "cookies": [
                {
                    "name": "session",
                    "value": "abc",
                    "domain": "t.com",
                    "path": "/",
                    "httpOnly": True,
                    "secure": True,
                    "sameSite": "Lax",
                    "expires": -1,
                }
            ],
            "authorization": "Bearer tok123",
            "captured_at": 1,
            "source_login_url": "https://t.com/login",
            "whoami": {},
        },
    )
    h = identity_store.get_headers("xyz")
    assert h["Cookie"] == "session=abc"
    assert h["Authorization"] == "Bearer tok123"


def test_get_headers_absent_returns_empty():
    assert identity_store.get_headers("nobody") == {}


def test_get_session_file_returns_path_when_exists():
    path = engagement_paths.resolve("secrets/sessions/xyz.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("{}")
    assert identity_store.get_session_file("xyz") == path


def test_get_session_file_none_when_absent():
    assert identity_store.get_session_file("ghost") is None
