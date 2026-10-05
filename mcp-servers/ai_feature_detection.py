"""AI/LLM-feature detection -- routes recon output to a bounded prompt-
injection pass instead of only parser-level attacks (XXE etc.).

Why this exists: a platform exposed an LLM-backed document-analysis
feature (user files feed an LLM), a first-class indirect prompt-injection
surface (OWASP GenAI LLM01), but no routing heuristic selected an
injection pass -- reported live in an engagement retrospective: the
feature was probed for XXE only, and the prompt-injection counterfactual
was identified only during review, after the engagement. A `Skill`
`emerging-surfaces` capability already covers the actual testing
methodology (OWASP LLM Top 10, direct/indirect prompt injection); what
was missing was the DETECTION step that tells an agent to load it in the
first place.

Same "generic phrase/pattern classifier over already-collected text" shape
as tool_resolver.classify_block() and signup_wall.py -- run over recon's
own already-crawled page content, JS bundle text, and extracted endpoint
lists (js_endpoints.py's own output is a natural input), not a new live
probe of its own.
"""

from __future__ import annotations

import re

# Endpoint-path-shaped signals: chat/assistant/completions/ai-named API
# routes. Deliberately requires a path-literal shape (quoted string
# starting with "/", same convention as js_endpoints.py's own
# _PATH_LITERAL_RE) so a bare mention of the word "chat" in prose doesn't
# also match here -- that's ai_feature_mention's job instead.
_ENDPOINT_PATH_RE = re.compile(
    r'''["'`](/[a-zA-Z0-9_./-]*\b(?:chat|chatbot|assistant|copilot|completions?|'''
    r'''ai[-_]?(?:chat|assistant|analysis|analyze))\b[a-zA-Z0-9_./-]*)["'`]''',
    re.IGNORECASE,
)

# A feature described in prose/UI copy as AI-powered/AI-generated, or an
# "AI [feature noun]" phrase -- word-boundaried so "domain"/"contains"/
# "maintain" never match on a bare "ai" substring.
_AI_FEATURE_MENTION_RE = re.compile(
    r"\bAI[- ](?:powered|generated|assistant|driven)\b"
    r"|\b(?:document|resume|contract|image)\s+(?:analysis|understanding|summar\w*)\b",
    re.IGNORECASE,
)

# Known LLM/GenAI vendor SDK or API references -- a strong, low-false-
# positive signal that a real LLM call happens somewhere in this flow.
_LLM_VENDOR_RE = re.compile(
    r"\b(?:OpenAI|Anthropic|Claude|Gemini|GPT-?\d|Bedrock|Vertex ?AI|"
    r"AzureOpenAI|LangChain|LlamaIndex)\b",
)

# Explicit "upload a file, AI does something with it" phrasing -- the
# indirect-prompt-injection-shaped flow specifically (file content fed to
# an LLM), distinct from a generic AI feature mention.
_UPLOAD_TO_LLM_RE = re.compile(
    r"\bupload\b[^.]{0,60}\bAI\b[^.]{0,40}\b(?:summar\w*|analy\w*|process\w*|review\w*)\b",
    re.IGNORECASE,
)

_PATTERNS_BY_CATEGORY = {
    "endpoint_path": _ENDPOINT_PATH_RE,
    "ai_feature_mention": _AI_FEATURE_MENTION_RE,
    "llm_vendor_reference": _LLM_VENDOR_RE,
    "upload_to_llm_flow": _UPLOAD_TO_LLM_RE,
}


def detect_ai_features(text: str, source: str = "") -> list[dict]:
    """Scans `text` (crawled page content, a JS bundle, an extracted
    endpoint list -- anything recon already collected) for AI/LLM-feature
    signals. Returns a deduped list of {"category", "matched_text",
    "source"} dicts, or [] if nothing matched. `source` is caller-supplied
    context (e.g. the URL/file the text came from) carried through
    unchanged, for the caller's own reporting."""
    seen: set[tuple[str, str]] = set()
    hits: list[dict] = []
    for category, pattern in _PATTERNS_BY_CATEGORY.items():
        for m in pattern.finditer(text):
            matched = m.group(0)
            key = (category, matched.lower())
            if key in seen:
                continue
            seen.add(key)
            hits.append({"category": category, "matched_text": matched, "source": source})
    return hits


def summarize_signals(hits: list[dict]) -> dict:
    """{"has_ai_feature": bool, "categories": [...]} -- the routing
    decision itself: has_ai_feature=True is the trigger to load `Skill`
    `emerging-surfaces` and run its bounded direct/indirect prompt-
    injection pass, using only the operator's own test data, same
    discipline the skill's own methodology already requires."""
    categories = sorted({h["category"] for h in hits})
    return {"has_ai_feature": bool(hits), "categories": categories}
