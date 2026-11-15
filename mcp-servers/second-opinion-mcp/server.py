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
from dotenv_loader import get_secret  # noqa: E402
from model_gateway import PROVIDER_CHAIN, select_provider  # noqa: E402

from mcp.server.fastmcp import FastMCP

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


class SecondOpinionUnavailable(RuntimeError):
    """Raised by get_second_opinion() when NO genuine cross-model review is
    possible this session -- no provider key at all, or only the primary's.

    Issue #135: this used to be a soft string returned from inside a normal
    tool response ("No model provider available"), which looked like any
    other successful result and got buried in one finding's draft notes --
    discovered only by chance while drafting that report. Raising instead
    surfaces it as a protocol-level tool ERROR the caller cannot mistake for
    a CONFIRMED / LIKELY FALSE POSITIVE verdict, so a finding is never
    silently treated as cross-model-reviewed when it wasn't."""


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
        if get_secret(key_env):
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


def cross_model_status(primary_role: str = "exploit") -> tuple[bool, str]:
    """(available, human_reason). available=True iff a DIFFERENT provider
    than the one that would run `primary_role` has a key configured -- i.e.
    a genuine cross-model second opinion is actually possible this session.
    Shared by get_second_opinion() (which raises when False) and
    startup_warning() (which prints a loud banner when False), so the
    availability decision is made in exactly one place. Never raises."""
    try:
        primary = select_provider(primary_role)
    except (RuntimeError, ValueError) as e:
        return False, (
            f"No model provider is configured at all ({e}). A cross-model "
            "second opinion is impossible this session -- any finding is "
            "reviewed by only the model running the engagement, with no "
            "independent check."
        )
    entry = _pick_second_opinion_provider(exclude=primary.name)
    if entry is None:
        return False, (
            f"Only one provider has a key configured ({primary.name}); a "
            "cross-model second opinion needs a DIFFERENT provider so the "
            "reviewer has no stake in the first model's reasoning. Set at "
            "least one more of: "
            + ", ".join(e[1] for e in PROVIDER_CHAIN if e[0] != primary.name)
        )
    return True, (
        f"available -- primary {primary.name!r}, second opinion via {entry[0]!r}"
    )


def startup_warning(primary_role: str = "exploit") -> str | None:
    """The loud banner __main__ prints to stderr when cross-model review is
    NOT available, so the gap is a visible engagement-start fact (issue
    #135) instead of something discovered by chance mid-report. Returns None
    when a second opinion IS available (nothing to warn about).

    The engagement-level MCP health-check (issue #134) is intended to also
    surface this; until that lands, this startup banner is the visible
    signal, alongside get_second_opinion() raising on use."""
    available, reason = cross_model_status(primary_role)
    if available:
        return None
    bar = "!" * 72
    return (
        f"\n{bar}\n"
        "second-opinion-mcp: CROSS-MODEL REVIEW UNAVAILABLE THIS SESSION.\n"
        f"  {reason}\n"
        "  Every get_second_opinion() call will FAIL (raise), not return a\n"
        "  verdict. Any finding you would have cross-checked has NO independent\n"
        "  review this session -- disclose that on the finding rather than\n"
        "  letting its absence imply more rigor than was applied (see the\n"
        "  pre-submission-validation skill).\n"
        f"{bar}\n"
    )


@app.tool()
def get_second_opinion(finding_summary: str, primary_role: str = "exploit") -> str:
    """Ask a DIFFERENT model provider than the one currently running this
    role to independently review a finding's evidence -- skeptical, not a
    rubber stamp. `finding_summary` should include the vuln class,
    endpoint, payload, and what was observed (the same evidence
    exploit-agent's Phase 1.5 check already has). Returns the second
    model's verdict as text (CONFIRMED / LIKELY FALSE POSITIVE / NEEDS
    MORE EVIDENCE + its reasoning), for the human or exploit-agent to
    weigh alongside the original confidence tag.

    RAISES SecondOpinionUnavailable (a protocol-level tool error, not a
    returned string) when no genuine cross-model review is possible this
    session -- no provider key at all, or only the primary role's. That
    error means "this finding got NO independent cross-model check"; treat
    it as a disclosable gap in rigor (see the pre-submission-validation
    skill), never as a transient failure to silently ignore (issue #135)."""
    # Fail LOUDLY (raise -> protocol-level tool error) when no genuine
    # cross-model review is possible, instead of returning a soft string the
    # caller could mistake for a verdict and paste into a report (issue #135).
    available, reason = cross_model_status(primary_role)
    if not available:
        raise SecondOpinionUnavailable(reason)

    primary = select_provider(primary_role)
    entry = _pick_second_opinion_provider(exclude=primary.name)
    provider, key_env, default_model, base_url_env = entry
    prompt = REVIEW_PROMPT_TEMPLATE.format(finding_summary=finding_summary)

    try:
        if provider == "anthropic":
            verdict = _call_anthropic(default_model, get_secret(key_env), prompt)
        elif provider in _OPENAI_COMPAT_BASE_URLS:
            verdict = _call_openai_compat(_OPENAI_COMPAT_BASE_URLS[provider], default_model, get_secret(key_env), prompt)
        elif provider == "ollama":
            host = get_secret("OLLAMA_HOST") or "http://localhost:11434"
            model = os.getenv("HUNTMCP_LOCAL_MODEL", default_model)
            verdict = _call_ollama(model, host, prompt)
        else:
            return f"Error: no call implementation for provider {provider!r}."
    except RuntimeError as e:
        return f"Error calling {provider}: {e}"

    return f"Second opinion from {provider} ({default_model}):\n{verdict.strip()}"


if __name__ == "__main__":
    print("second-opinion-mcp starting...", file=sys.stderr)
    _banner = startup_warning()
    if _banner:
        print(_banner, file=sys.stderr)
    app.run(transport="stdio")
