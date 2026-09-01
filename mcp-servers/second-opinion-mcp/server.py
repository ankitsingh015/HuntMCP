"""Cross-model second opinion (Phase 2.10 backlog, `trailofbits/skills`
`second-opinion` pattern).

Before a HIGH-confidence finding gets finalized, exploit-agent can ask a
DIFFERENT provider than the one currently running it to independently
review the evidence -- same multi-provider infra `model_gateway.py`
already uses for failover, reused here for cross-validation instead. A
second model with no stake in the first one's reasoning is more likely to
notice a rationalization the first one talked itself into (the exact
failure mode Phase 1.5's "rationalizations to reject" check exists for).

This does NOT replace Phase 1.5 or the confidence tag -- it's an optional
extra check exploit-agent can reach for on a finding it wants more
certainty on, not a required step for every finding.

IMPORTANT -- like hackerone-mcp, this has NOT been tested against a live
API call for any provider (no API keys were available while building it).
Endpoint paths and request/response shapes follow each provider's
documented API as understood at the time this was written -- verify
against a real key before depending on it in a real engagement. Request-
building and response-parsing logic were verified against each provider's
documented shape using mocked HTTP responses, not a real call.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from dotenv_loader import load_dotenv_if_present  # noqa: E402
from model_gateway import PROVIDER_CHAIN, select_provider  # noqa: E402

from mcp.server.fastmcp import FastMCP

load_dotenv_if_present()

app = FastMCP("second-opinion-mcp")

REVIEW_PROMPT_TEMPLATE = """You are doing an independent second-opinion review of a \
security finding someone else already investigated. Be skeptical -- your job is \
specifically to catch a rationalization the first reviewer talked themselves into, \
not to rubber-stamp their conclusion.

Finding under review:
{finding_summary}

Answer in 2-4 sentences: does the evidence actually support this being a real, \
confirmed vulnerability, or does something about it look like a common false-\
positive pattern (e.g. reflected-but-not-executed XSS, a scanner flag accepted \
without independent reproduction, IDOR on non-sensitive data)? State your verdict \
clearly: CONFIRMED, LIKELY FALSE POSITIVE, or NEEDS MORE EVIDENCE."""

# OpenAI-compatible chat/completions shape -- covers 4 of the 5 hosted providers.
_OPENAI_COMPAT_BASE_URLS = {
    "openai": "https://api.openai.com/v1/chat/completions",
    "deepseek": "https://api.deepseek.com/chat/completions",
    "groq": "https://api.groq.com/openai/v1/chat/completions",
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
}


def _pick_second_opinion_provider(exclude: str):
    """First provider in the chain, other than `exclude`, that has a key
    (or for ollama, OLLAMA_HOST) actually set -- same availability check
    select_provider()'s automatic chain uses, not a special case. Ollama
    isn't unconditionally "available" just because it needs no API key;
    it still needs a server actually configured. Returns a PROVIDER_CHAIN
    entry or None if nothing else is available."""
    for entry in PROVIDER_CHAIN:
        provider, key_env, _, _ = entry
        if provider == exclude:
            continue
        if os.getenv(key_env):
            return entry
    return None


def _post_json(url: str, headers: dict, body: dict, timeout: int = 60) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{url} returned {e.code}: {e.read().decode(errors='replace')[:300]}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"{url} unreachable: {e.reason}") from e


def _call_anthropic(model: str, api_key: str, prompt: str) -> str:
    data = _post_json(
        "https://api.anthropic.com/v1/messages",
        {"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        {"model": model, "max_tokens": 512, "messages": [{"role": "user", "content": prompt}]},
    )
    return "".join(block.get("text", "") for block in data.get("content", []))


def _call_openai_compat(url: str, model: str, api_key: str, prompt: str) -> str:
    data = _post_json(
        url,
        {"Authorization": f"Bearer {api_key}", "content-type": "application/json"},
        {"model": model, "max_tokens": 512, "messages": [{"role": "user", "content": prompt}]},
    )
    return data["choices"][0]["message"]["content"]


def _call_ollama(model: str, host: str, prompt: str) -> str:
    data = _post_json(
        f"{host.rstrip('/')}/api/chat",
        {"content-type": "application/json"},
        {"model": model, "messages": [{"role": "user", "content": prompt}], "stream": False},
    )
    return data.get("message", {}).get("content", "")


@app.tool()
def get_second_opinion(finding_summary: str, primary_role: str = "exploit") -> str:
    """Ask a DIFFERENT model provider than the one currently running this
    role to independently review a finding's evidence -- skeptical, not a
    rubber stamp. `finding_summary` should include the vuln class,
    endpoint, payload, and what was observed (the same evidence
    exploit-agent's Phase 1.5 check already has). Returns the second
    model's verdict as text (CONFIRMED / LIKELY FALSE POSITIVE / NEEDS
    MORE EVIDENCE + its reasoning), for the human or exploit-agent to
    weigh alongside the original confidence tag."""
    try:
        primary = select_provider(primary_role)
    except (RuntimeError, ValueError) as e:
        return f"Error: could not determine the primary provider to exclude: {e}"

    entry = _pick_second_opinion_provider(exclude=primary.name)
    if entry is None:
        return (
            "No second provider available -- only one provider has a key configured "
            f"({primary.name}). Set at least one more of: "
            + ", ".join(e[1] for e in PROVIDER_CHAIN if e[0] != primary.name)
        )

    provider, key_env, default_model, base_url_env = entry
    prompt = REVIEW_PROMPT_TEMPLATE.format(finding_summary=finding_summary)

    try:
        if provider == "anthropic":
            verdict = _call_anthropic(default_model, os.getenv(key_env), prompt)
        elif provider in _OPENAI_COMPAT_BASE_URLS:
            verdict = _call_openai_compat(_OPENAI_COMPAT_BASE_URLS[provider], default_model, os.getenv(key_env), prompt)
        elif provider == "ollama":
            host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
            model = os.getenv("HUNTMCP_LOCAL_MODEL", default_model)
            verdict = _call_ollama(model, host, prompt)
        else:
            return f"Error: no call implementation for provider {provider!r}."
    except RuntimeError as e:
        return f"Error calling {provider}: {e}"

    return f"Second opinion from {provider} ({default_model}):\n{verdict.strip()}"


if __name__ == "__main__":
    print("second-opinion-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
