"""Model provider gateway — no lock-in, easy manual override.

Two ways to pick a model, checked in this order:

1. EXPLICIT OVERRIDE (easiest way to pick exactly what you want):
     HUNTMCP_MODEL=whiterabbitneo          # every agent uses this
     HUNTMCP_MODEL_EXPLOIT=whiterabbitneo  # only the exploit agent uses this,
                                            # everything else still falls
                                            # through the chain below
2. AUTOMATIC FALLBACK CHAIN (used only when no override is set): first
   provider in PROVIDER_CHAIN whose API key (or OLLAMA_HOST, for local) is
   actually set, in priority order. This is what makes HuntMCP "just work"
   with whatever key you already have, without picking anything by hand.

Neither path is hardcoded to one vendor. Swapping providers is a config
change (an env var), never a code change.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass


@dataclass
class ProviderConfig:
    name: str
    default_model: str
    base_url: str | None
    api_key: str | None
    source: str  # "explicit_override" | "role_override" | "chain"


# (provider name, API-key env var, a sane default model, base_url override env var)
# Order = priority when no override is set. Local Ollama is last so a hosted
# key is preferred by default, but it's always available with zero setup —
# and it's the slot for a purpose-built open-weight security model (e.g.
# WhiteRabbitNeo) when a hosted model's refusal behavior gets in the way of
# already-authorized, already-scope-confirmed work.
PROVIDER_CHAIN: list[tuple[str, str, str, str | None]] = [
    ("anthropic", "ANTHROPIC_API_KEY", "claude-opus-4-7", None),
    ("openai", "OPENAI_API_KEY", "gpt-5", None),
    ("deepseek", "DEEPSEEK_API_KEY", "deepseek-v4", None),
    ("groq", "GROQ_API_KEY", "llama-3.3-70b-versatile", None),
    ("openrouter", "OPENROUTER_API_KEY", "openrouter/auto", None),
    ("ollama", "OLLAMA_HOST", "whiterabbitneo", "OLLAMA_HOST"),
]

_NAMED_MODELS = {
    # convenience names you can pass to HUNTMCP_MODEL directly
    "claude": "anthropic",
    "opus": "anthropic",
    "gpt": "openai",
    "deepseek": "deepseek",
    "groq": "groq",
    "openrouter": "openrouter",
    "ollama": "ollama",
    "local": "ollama",
    "whiterabbitneo": "ollama",
}


def _provider_by_name(name: str) -> tuple[str, str, str, str | None] | None:
    key = _NAMED_MODELS.get(name.lower(), name.lower())
    for entry in PROVIDER_CHAIN:
        if entry[0] == key:
            return entry
    return None


def _build_config(entry: tuple[str, str, str, str | None], source: str) -> ProviderConfig:
    provider, key_env, default_model, base_url_env = entry
    return ProviderConfig(
        name=provider,
        default_model=default_model,
        base_url=os.getenv(base_url_env) if base_url_env else None,
        api_key=os.getenv(key_env) if key_env != "OLLAMA_HOST" else None,
        source=source,
    )


def select_provider(agent_role: str | None = None) -> ProviderConfig:
    """Pick a provider for the given agent role (e.g. "recon", "exploit",
    "report"). Explicit overrides always win over the automatic chain.
    """
    # 1. per-agent override, e.g. HUNTMCP_MODEL_EXPLOIT
    if agent_role:
        role_var = f"HUNTMCP_MODEL_{agent_role.upper()}"
        role_override = os.getenv(role_var)
        if role_override:
            entry = _provider_by_name(role_override)
            if entry is None:
                raise ValueError(f"{role_var}={role_override!r} is not a known provider")
            return _build_config(entry, source=f"role_override:{role_var}")

    # 2. global override, e.g. HUNTMCP_MODEL
    override = os.getenv("HUNTMCP_MODEL")
    if override:
        entry = _provider_by_name(override)
        if entry is None:
            raise ValueError(f"HUNTMCP_MODEL={override!r} is not a known provider")
        return _build_config(entry, source="explicit_override")

    # 3. automatic fallback chain — first provider with a key actually set
    for entry in PROVIDER_CHAIN:
        provider, key_env, _, _ = entry
        if os.getenv(key_env):
            return _build_config(entry, source="chain")

    raise RuntimeError(
        "No model provider available. Set one of: "
        + ", ".join(e[1] for e in PROVIDER_CHAIN)
        + " (or HUNTMCP_MODEL to force a choice)."
    )


def _cli() -> None:
    """python3 mcp-servers/model_gateway.py [agent_role]
    Prints exactly which provider/model would be used and why — the
    "ease of selection" check: run this any time to see what's active
    before spending real tokens on it.
    """
    role = sys.argv[1] if len(sys.argv) > 1 else None
    try:
        cfg = select_provider(role)
    except (RuntimeError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    label = f" (agent: {role})" if role else ""
    print(f"Selected provider{label}: {cfg.name}")
    print(f"  model:  {cfg.default_model}")
    print(f"  source: {cfg.source}")
    print(f"  key set: {'yes' if cfg.api_key else ('n/a (local)' if cfg.name == 'ollama' else 'no')}")


if __name__ == "__main__":
    _cli()
