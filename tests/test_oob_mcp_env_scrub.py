"""S3 follow-up (code-review finding, CONFIRMED): oob-mcp/server.py's
generate_payload_url() starts interactsh-client via a direct
subprocess.Popen() call, deliberately bypassing tool_resolver.run_tool()
(it's long-lived/detached -- see that module's own docstring) -- which
meant it never got run_tool()'s S3 environment scrub either.

generate_payload_url() itself talks to interactsh's real public
infrastructure to mint a callback URL (a real network dependency, up to a
20s wait) -- not something to depend on in a fast, deterministic test. This
test instead points the server at a small fake "interactsh-client" binary
(a python3 one-liner) that immediately satisfies the URL-shaped regex
generate_payload_url() waits for, so the REAL Popen call path in server.py
still runs end-to-end, just without any real network call.
"""

import importlib.util
import os
import stat
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "oob_server", os.path.join(ROOT, "mcp-servers", "oob-mcp", "server.py")
)
oob_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oob_server)


def _make_fake_interactsh_client(tmp_path, env_dump_path):
    """A stand-in binary that: (1) immediately prints an interactsh-URL-
    shaped string so generate_payload_url()'s wait loop returns fast, and
    (2) dumps its own environment to env_dump_path so the test can inspect
    exactly what the real Popen call actually passed down -- the same
    proof pattern used for run_tool()/start_job()'s own env-scrub tests."""
    script = tmp_path / "fake-interactsh-client"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, time\n"
        f"with open({str(env_dump_path)!r}, 'w') as f:\n"
        "    json.dump(dict(os.environ), f)\n"
        "print('abc123def456789.oast.fun')\n"
        "time.sleep(5)\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def test_generate_payload_url_subprocess_does_not_inherit_secret_env_vars(monkeypatch, tmp_path):
    import json

    monkeypatch.setattr(oob_server, "_enforce_budget", lambda name: None)
    monkeypatch.setattr(oob_server, "OOB_DIR", str(tmp_path / "oob-sessions"))
    monkeypatch.setattr(oob_server, "REGISTRY_PATH", str(tmp_path / "oob-sessions" / "registry.json"))
    monkeypatch.setenv("HUNTMCP_TEST_FAKE_SECRET", "super-secret-value")

    env_dump_path = tmp_path / "child-env.json"
    fake_binary = _make_fake_interactsh_client(tmp_path, env_dump_path)
    monkeypatch.setattr(oob_server, "resolve_tool", lambda name: fake_binary)

    result = oob_server.generate_payload_url(label="test")
    assert "oast.fun" in result  # sanity: the real code path found our fake URL

    # Clean up the still-running fake process (it self-sleeps 5s) so it
    # doesn't linger after the test -- registry has its pid.
    registry = oob_server._load_registry()
    for entry in registry.values():
        try:
            os.kill(entry["pid"], 9)
        except ProcessLookupError:
            pass

    child_env = json.loads(env_dump_path.read_text())
    assert "HUNTMCP_TEST_FAKE_SECRET" not in child_env
    assert child_env.get("PATH")  # sanity: not scrubbed into unusability
