"""Tiny built-in per-key .env reader -- no python-dotenv dependency for
something this small.

get_secret(key) reads ONE named credential at a time. It replaces the
older load_dotenv_if_present(), which dumped EVERY key in .env into the
calling process's shared os.environ at import time -- so a server that
only needed, say, GITHUB_TOKEN ended up with every OTHER service's
credential sitting in os.environ too, inherited by any subprocess that
process later spawns (subprocess.run() inherits the full parent
environment by default) and visible to anything else running in that same
process. (S3 -- IMPLEMENTATION-TASK-TRACKER.md, "secrets scoped out of
untrusted execution".)

get_secret() never writes to os.environ -- it hands the requested value
directly back to the caller and goes no further, so a credential is only
ever visible to the code that explicitly asked for it by name.

Real environment variables still always win over .env, same as before,
just evaluated per key instead of dumping the whole file: a value you've
explicitly exported takes precedence over the same key in the file.
"""

import os

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
_ENV_PATH = os.path.join(_REPO_ROOT, ".env")

# Keyed by resolved path, not just a single bool -- so callers that pass an
# explicit path: str = _ENV_PATH here, at definition time, would freeze in
# whichever value _ENV_PATH had at import time and ignore a later
# monkeypatch (the same bug engagement_paths.py's own resolve() docstring
# documents and avoids). Reading the module-global _ENV_PATH inside the
# function body instead keeps every call live to the current value.
_cache: dict[str, dict[str, str]] = {}


def _parse_env_file(path: str) -> dict[str, str]:
    if path in _cache:
        return _cache[path]
    values: dict[str, str] = {}
    if os.path.isfile(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key:
                    values[key] = value
    _cache[path] = values
    return values


def get_secret(key: str, path: str | None = None) -> str | None:
    """Return `key`'s value: a real exported env var if set, else the same
    key read from the .env file at `path` (default: the repo-root .env),
    else None. Never touches os.environ."""
    if key in os.environ:
        return os.environ[key]
    if path is None:
        path = _ENV_PATH
    return _parse_env_file(path).get(key)
