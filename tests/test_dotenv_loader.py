import dotenv_loader


def _write_env_file(tmp_path, content: str) -> str:
    path = tmp_path / ".env"
    path.write_text(content)
    return str(path)


def test_get_secret_returns_real_env_var_when_set(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTMCP_TEST_KEY", "from-shell")
    path = _write_env_file(tmp_path, "HUNTMCP_TEST_KEY=from-file\n")
    assert dotenv_loader.get_secret("HUNTMCP_TEST_KEY", path=path) == "from-shell"


def test_get_secret_falls_back_to_env_file_when_no_real_var(monkeypatch, tmp_path):
    monkeypatch.delenv("HUNTMCP_TEST_KEY", raising=False)
    path = _write_env_file(tmp_path, "HUNTMCP_TEST_KEY=from-file\n")
    assert dotenv_loader.get_secret("HUNTMCP_TEST_KEY", path=path) == "from-file"


def test_get_secret_returns_none_when_key_absent_everywhere(monkeypatch, tmp_path):
    monkeypatch.delenv("HUNTMCP_TEST_KEY", raising=False)
    path = _write_env_file(tmp_path, "OTHER_KEY=value\n")
    assert dotenv_loader.get_secret("HUNTMCP_TEST_KEY", path=path) is None


def test_get_secret_returns_none_when_file_does_not_exist(monkeypatch, tmp_path):
    monkeypatch.delenv("HUNTMCP_TEST_KEY", raising=False)
    assert dotenv_loader.get_secret("HUNTMCP_TEST_KEY", path=str(tmp_path / "does-not-exist")) is None


def test_get_secret_ignores_comments_and_blank_lines(monkeypatch, tmp_path):
    monkeypatch.delenv("HUNTMCP_TEST_KEY", raising=False)
    path = _write_env_file(tmp_path, "# a comment\n\nHUNTMCP_TEST_KEY=value\n")
    assert dotenv_loader.get_secret("HUNTMCP_TEST_KEY", path=path) == "value"


def test_get_secret_strips_surrounding_quotes(monkeypatch, tmp_path):
    monkeypatch.delenv("HUNTMCP_TEST_KEY", raising=False)
    path = _write_env_file(tmp_path, 'HUNTMCP_TEST_KEY="value"\n')
    assert dotenv_loader.get_secret("HUNTMCP_TEST_KEY", path=path) == "value"


def test_get_secret_does_not_write_requested_key_into_os_environ(monkeypatch, tmp_path):
    """Core S3 guarantee: get_secret() hands the value directly to the
    caller and goes no further -- it must never populate os.environ, or
    the value would be inherited by any subprocess this process later
    spawns (subprocess.run() inherits the full parent environment by
    default), exactly the 'harvestable via a shared environment' problem
    S3 exists to close."""
    import os

    monkeypatch.delenv("HUNTMCP_TEST_KEY", raising=False)
    path = _write_env_file(tmp_path, "HUNTMCP_TEST_KEY=from-file\n")
    dotenv_loader.get_secret("HUNTMCP_TEST_KEY", path=path)
    assert "HUNTMCP_TEST_KEY" not in os.environ


def test_get_secret_never_exposes_unrelated_keys_from_the_same_file(monkeypatch, tmp_path):
    """The per-key contract: a caller that asks for ONE key must never be
    able to see -- or leak into os.environ -- any OTHER key that happens
    to live in the same .env file, unlike the old load_dotenv_if_present()
    which dumped every key into shared process state at once."""
    import os

    monkeypatch.delenv("KEY_A", raising=False)
    monkeypatch.delenv("KEY_B", raising=False)
    path = _write_env_file(tmp_path, "KEY_A=secret-a\nKEY_B=secret-b\n")

    result = dotenv_loader.get_secret("KEY_A", path=path)

    assert result == "secret-a"
    assert "KEY_A" not in os.environ
    assert "KEY_B" not in os.environ
