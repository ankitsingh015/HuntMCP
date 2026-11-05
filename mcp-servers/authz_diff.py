"""P3-VALAUTHZ -- multi-identity authorization differential (smallest useful version).

Two additions on top of idor-mcp's single-id sweep (which it does not replace):

  (a) an owner-fetch-and-compare ORACLE stricter than the sweep's fuzzy
      difflib ratio: identity B must receive the byte-for-byte (JSON-
      normalized) same object identity A receives, AND three negative controls
      must rule out the ways that can happen without an authorization bug --
      the object is public (unauthenticated fetch gets it too), the data is
      authenticated-but-global (B's OWN object looks identical), or A's own
      view is unstable. A missing control degrades to INCONCLUSIVE, never to
      LEAKED: false negatives are acceptable here, false positives are not.
  (b) a TWO-STEP REPLAY: step 1 is run as A and yields an opaque id (JSON
      field named by `carried_path`); step 2 is then fetched under B carrying
      A's id, i.e. an id that was only ever valid in A's session. This reaches
      authorization flaws a sweep cannot, because the id is not known up front.

Safety (every item has a test):
  - read-only by default: any non-GET/HEAD/OPTIONS step needs the same
    per-finding human approval object cem_engine uses ({methods, reason,
    authorized_by}); refused BEFORE any request is sent.
  - scope + outbound policy are checked before EVERY request (not once per
    call); budget is consumed per request; redirects are never followed.
  - the carried id comes from an untrusted response: it is restricted to a
    conservative charset before it goes into a URL, and the step-2 template
    must share step 1's origin with the placeholder outside the authority.
  - credentials are passed straight to the fetch and never stored on the result.

This module discovers/validates the EXISTENCE of an authorization gap; it does
not decide severity or set a finding CONFIRMED (that stays the independent
re-run + evidence gate in case-mcp), and it does not touch cem_engine's logic.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, urlsplit

import http_probe
import scope_check as _scope
from budget_guard import BudgetExceeded
from cem_engine import (
    CEM_APPROVABLE_METHODS,
    CEM_READ_ONLY_METHODS,
    check_request_allowed,
    normalize_method,
)
from redact import (
    KNOWN_SECRET_HEADER_NAMES,
    is_secret_key,
    loads_for_redaction,
    redact_structured,
    redact_text,
    redacted,
)

PROTECTED_STATUSES = frozenset({401, 403, 404})
CARRIED_PLACEHOLDER = "{carried}"
_CARRIED_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,127}")  # must START alphanumeric: no ".", "~", "-x"
EVIDENCE_BODY_CAP = 2000
MAX_STEP1_BODY_BYTES = 4096
# A human has to be able to read the whole request before confirming it (see state_change_confirm).
MAX_STEP_URL_CHARS = 300
_MISSING = object()
# A body that differs between two fetches by the SAME identity (timestamps, request ids) may be
# compared with those fields masked. Either way the owner's object must carry real content before
# "the other identity got the same thing" can mean anything: an API that answers a non-owner with
# a filtered-empty 200 ({"orders": []}) would otherwise mirror an owner whose own collection is
# empty. "Informative" = a non-blank string or non-zero number (not null/bool/0/""/[]/{}).
MIN_INFORMATIVE_LEAVES = 2
MIN_TEXT_CHARS = 8  # same idea for a body that is not JSON


class RequestBlocked(Exception):
    """Raised by a scope_check / budget callback to stop the run before a request is sent."""


@dataclass(frozen=True)
class Workflow:
    step1_url: str
    carried_path: str
    step2_url_template: str
    step1_method: str = "GET"
    step2_method: str = "GET"
    # Optional JSON body for step 1 only (create-then-read: POST makes an object, the response carries
    # its id). Agent-supplied, so it is validated, never stored or returned (only a hash), and a step
    # with a body must be a state-changing method -- i.e. behind the human gate.
    step1_body: str | None = None


@dataclass
class AuthzResult:
    verdict: str
    detail: str = ""
    carried_id: str | None = None
    requests: list[dict] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict, "detail": self.detail, "carried_id": self.carried_id,
            "request_count": len(self.requests), "requests": self.requests,
            "evidence": self.evidence,
        }


class _Stop(Exception):
    def __init__(self, verdict: str, detail: str) -> None:
        super().__init__(detail)
        self.verdict, self.detail = verdict, detail


# --- pure helpers ---------------------------------------------------------

def normalize_body(body: str) -> str | None:
    """Canonical form for exact comparison: JSON re-serialized with sorted keys, else
    whitespace-collapsed text. None for an empty body."""
    if not body or not body.strip():
        return None
    try:
        return json.dumps(json.loads(body), sort_keys=True, separators=(",", ":"))
    except (ValueError, RecursionError):  # not JSON, or nested past the parser's limit
        return " ".join(body.split())


def extract_carried_id(body: str, path: str) -> str | None:
    """Walks a dotted path (dict keys / list indexes) through a JSON body; returns the
    str/int leaf as a string, else None. Does NOT judge safety -- see is_safe_carried_id."""
    try:
        node = json.loads(body)
    except (ValueError, RecursionError):
        return None
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isascii() and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return None
    if isinstance(node, bool) or not isinstance(node, (str, int)):
        return None
    return str(node)


def is_safe_carried_id(value: str | None) -> bool:
    return bool(value) and _CARRIED_RE.fullmatch(value) is not None and ".." not in value


def redact_body(body: str) -> str:
    try:
        parsed = loads_for_redaction(body)
    except ValueError:
        return redact_text(body)
    except RecursionError:
        return "[withheld: body nested too deeply to redact safely]"
    try:
        return json.dumps(redact_structured(parsed), sort_keys=True)
    except RecursionError:
        return "[withheld: body nested too deeply to redact safely]"


def _credential_fragments(headers: dict) -> set[str]:
    """Substrings of the identities' credential values to scrub from anything stored or returned:
    the whole header value, a Bearer token, and -- for a Cookie -- the pieces whose NAME looks
    secret (so a harmless `theme=darkmode` cookie never makes "darkmode" vanish from evidence)."""
    frags: set[str] = set()
    for name, value in headers.items():
        if not isinstance(value, str):
            continue
        value = value.strip()
        frags.add(value)
        if value.lower().startswith("bearer "):
            frags.add(value[7:].strip())
        if isinstance(name, str) and name.lower() == "cookie":
            for piece in value.split(";"):
                piece = piece.strip()
                cname, _, cval = piece.partition("=")
                if cval and is_secret_key(cname.strip()):
                    frags.update((piece, cval.strip()))
    return {f for f in frags if len(f) >= 6}


class _Scrubber:
    """Exact-value scrub for one run: both identities' credentials, plus any carried id that
    arrived under a secret-looking key. Built once and reused for every stored/returned string."""

    def __init__(self, *header_sets: dict) -> None:
        self._frags: set[str] = set()
        for headers in header_sets:
            self._frags |= _credential_fragments(headers)

    def add(self, fragment: str) -> None:
        if len(fragment) >= 6:
            self._frags.add(fragment)

    def scrub(self, text: str) -> str:
        for frag in sorted(self._frags, key=len, reverse=True):
            text = text.replace(frag, "[REDACTED]")
        return text


def _has_control_chars(text: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 for c in text)


def _json_leaves(body: str) -> dict | None:
    """{path: [type_tag, value]} for every leaf of a JSON body, or None if the body is not JSON
    (or nested too deeply to walk). The path is the JSON-encoded list of segments -- "k:<key>" for
    an object key, an int for a list index -- so a key containing "/" or "0" can never collide with
    nesting or an index. Empty objects/arrays are leaves too ("{}" / "[]"), so presence and shape
    are never lost, and the tag keeps str/number/bool/null apart."""
    try:
        node = json.loads(body)
    except (ValueError, RecursionError):
        return None
    out: dict = {}

    def walk(n, path):
        if isinstance(n, dict):
            if not n:
                out[json.dumps(path)] = ["{}", None]
            for k, v in n.items():
                walk(v, [*path, f"k:{k}"])
        elif isinstance(n, list):
            if not n:
                out[json.dumps(path)] = ["[]", None]
            for i, v in enumerate(n):
                walk(v, [*path, i])
        elif n is None:
            out[json.dumps(path)] = ["null", None]
        elif isinstance(n, bool):
            out[json.dumps(path)] = ["bool", n]
        elif isinstance(n, (int, float)):
            out[json.dumps(path)] = ["num", n]
        else:
            out[json.dumps(path)] = ["str", n]

    try:
        walk(node, [])
    except RecursionError:
        return None
    return out


def _to_pointer(path: str) -> str:
    """Human-readable RFC 6901 JSON pointer for an internal path, for evidence."""
    segs = json.loads(path)
    return "".join("/" + (str(s)[2:] if isinstance(s, str) else str(s)).replace("~", "~0").replace("/", "~1")
                   for s in segs)


def _masked_dump(leaves: dict, volatile: frozenset) -> str:
    return json.dumps({p: v for p, v in leaves.items() if p not in volatile}, sort_keys=True)


def _informative_count(leaves: dict, volatile: frozenset = frozenset()) -> int:
    return sum(1 for p, (tag, val) in leaves.items()
               if p not in volatile and ((tag == "str" and val.strip()) or (tag == "num" and val != 0)))


def _comparable(body: str, volatile: frozenset) -> str | None:
    """Canonical comparison form. With no volatile paths this is exactly normalize_body();
    with some, the JSON leaves minus those paths."""
    if not volatile:
        return normalize_body(body)
    leaves = _json_leaves(body)
    return None if leaves is None else _masked_dump(leaves, volatile)


_NOT_OWNERS_OBJECT = (
    "other identity got 200 but NOT the owner's object (different content: a caller-scoped "
    "view, a soft-deny body, or another resource) -- not a leak")


def _mask_per_request_fields(l1, owner2, test):
    """The owner's body differs between two fetches. Work out which JSON paths vary per request
    and compare the other identity's body with only those masked. Returns
    ((volatile_paths, owner_view), None) to continue, or (None, (verdict, detail)) to stop. The
    mask only ever hides a VALUE: every volatile path the owner always has must still exist in
    the other body with the same JSON type, empty containers count as content, and at least
    MIN_INFORMATIVE_LEAVES informative unmasked fields must remain."""
    l2, lt = _json_leaves(owner2.body), _json_leaves(test.body)
    if l1 is None or l2 is None or lt is None:
        return None, ("DIFFERENT", _NOT_OWNERS_OBJECT + " (bodies also vary per fetch but are not maskable JSON)")
    volatile = frozenset(p for p in l1.keys() | l2.keys() if l1.get(p, _MISSING) != l2.get(p, _MISSING))
    if _informative_count(l1, volatile) < MIN_INFORMATIVE_LEAVES:
        detail = ("the owner's body varies per fetch in almost every field; fewer than "
                  f"{MIN_INFORMATIVE_LEAVES} informative stable fields remain to compare")
        return None, ("INCONCLUSIVE", detail)
    for path in volatile:
        if path in l1 and path in l2 and (path not in lt or lt[path][0] != l1[path][0]):
            return None, ("DIFFERENT", _NOT_OWNERS_OBJECT
                          + " (a per-request field the owner always has is missing or has another type)")
    owner_view = _masked_dump(l1, volatile)
    if _masked_dump(lt, volatile) != owner_view:
        return None, ("DIFFERENT", _NOT_OWNERS_OBJECT)
    return (volatile, owner_view), None


def structural_error(wf: Workflow, owner_headers: dict, other_headers: dict) -> tuple[str, str] | None:
    """(verdict, reason) if the workflow is malformed (ERROR), else None. Checks only shape --
    the human method gate is separate, so a caller can reject a bad workflow BEFORE spending a
    human-issued approval on it."""
    if wf.step1_url.count(CARRIED_PLACEHOLDER) or wf.step2_url_template.count(CARRIED_PLACEHOLDER) != 1:
        return "ERROR", f"step 2 template must contain exactly one {CARRIED_PLACEHOLDER} and step 1 none"
    try:
        s1, s2 = urlsplit(wf.step1_url), urlsplit(wf.step2_url_template)
    except ValueError as e:
        return "ERROR", f"unparseable workflow URL ({e})"
    if CARRIED_PLACEHOLDER in s2.netloc or not s1.netloc or s1.netloc != s2.netloc or s1.scheme != s2.scheme:
        return "ERROR", "step 1 and step 2 must share one origin, with the carried id only in the path/query"
    if len(wf.step1_url) > MAX_STEP_URL_CHARS or len(wf.step2_url_template) > MAX_STEP_URL_CHARS:
        return "ERROR", (f"step URLs are limited to {MAX_STEP_URL_CHARS} characters: a long URL could hide "
                         "what a human is asked to confirm")
    if s1.username is not None or s1.password is not None or "@" in s1.netloc or "@" in s2.netloc:
        return "ERROR", "workflow URLs must not contain userinfo (user:password@host)"
    if not _valid_host_and_port(s1) or not _valid_host_and_port(s2):
        return "ERROR", "workflow URL host/port is malformed (allowed: DNS name or IP literal, optional numeric port)"
    if _normalized_credentials(owner_headers) == _normalized_credentials(other_headers):
        return "ERROR", "the owner and other identities carry the same credentials -- a differential needs two different identities"
    for headers in (owner_headers, other_headers):
        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, str) or _has_control_chars(name + value):
                return "ERROR", f"identity header {str(name)[:40]!r} is not a plain string or contains control characters"
    for method in (wf.step1_method, wf.step2_method):
        m = normalize_method(method)
        if m not in CEM_READ_ONLY_METHODS and m not in CEM_APPROVABLE_METHODS:
            return "ERROR", (f"step method {str(method)[:20]!r} is neither read-only (GET/HEAD/OPTIONS) nor an "
                             "approvable state-changing method (POST/PUT/PATCH/DELETE)")
    return _step1_body_error(wf)


_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


def _reject_json_constant(name: str):
    raise ValueError(f"non-standard JSON constant {name}")


def _step1_body_error(wf: Workflow) -> tuple[str, str] | None:
    body = wf.step1_body
    if body is None:
        return None
    if not isinstance(body, str) or not body.strip():
        return "ERROR", "step1_body must be a non-empty JSON string (or omitted)"
    if normalize_method(wf.step1_method) not in _BODY_METHODS:
        return "ERROR", "step1_body is only allowed on a POST/PUT/PATCH step 1"
    try:
        size = len(body.encode("utf-8"))
    except UnicodeEncodeError:
        return "ERROR", "step1_body is not valid UTF-8 text (unpaired surrogate)"
    if size > MAX_STEP1_BODY_BYTES:
        return "ERROR", f"step1_body is larger than {MAX_STEP1_BODY_BYTES} bytes"
    if CARRIED_PLACEHOLDER in body:
        return "ERROR", "step1_body cannot reference the carried id (it does not exist yet at step 1)"
    try:
        json.loads(body, parse_constant=_reject_json_constant)  # strict JSON: no NaN / Infinity
    except (ValueError, RecursionError):
        return "ERROR", "step1_body is not valid (strict) JSON"
    return None


def _body_digest(wf: Workflow) -> str | None:
    return hashlib.sha256(wf.step1_body.encode("utf-8", "replace")).hexdigest() if wf.step1_body is not None else None


def _identity_tag(headers: dict | None) -> str | None:
    """Stable hash of an identity's normalized credentials (never the credentials themselves)."""
    if headers is None:
        return None
    material = "huntmcp-identity:" + json.dumps(sorted(_normalized_credentials(headers).items()))
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()


def workflow_fingerprint(wf: Workflow, owner_headers: dict | None = None,
                         other_headers: dict | None = None) -> str:
    """128-bit (32 hex) digest of exactly what a state-changing run would send: both step methods and
    URLs, the carried path, the step-1 body HASH and the two identities (as credential hashes). A
    human confirmation bound to this cannot be reused by the agent for another path, method, body or
    pair of accounts on the same host -- and 128 bits is out of reach of a birthday collision."""
    material = json.dumps({
        "m1": normalize_method(wf.step1_method), "u1": wf.step1_url,
        "m2": normalize_method(wf.step2_method), "u2": wf.step2_url_template,
        "c": wf.carried_path, "b": _body_digest(wf),
        "o": _identity_tag(owner_headers), "x": _identity_tag(other_headers),
    }, sort_keys=True)
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:32]


def workflow_summary(wf: Workflow, owner_headers: dict | None = None, other_headers: dict | None = None) -> str:
    """What a human is being asked to authorize, for the confirmation prompt. The security-critical
    facts come FIRST in a fixed order (methods, host, accounts) so nothing can push them out of view;
    the body is shown only as size + hash, never its text (it may carry secrets); URLs are redacted."""
    m1, m2 = normalize_method(wf.step1_method), normalize_method(wf.step2_method)
    head = f"{'+'.join(sorted({m1, m2}))} on {approval_host(wf.step1_url)}"
    if owner_headers is not None and other_headers is not None:
        head += f"; owner id {_identity_tag(owner_headers)[:8]}, other id {_identity_tag(other_headers)[:8]}"
    body = ""
    if wf.step1_body is not None:
        body = (f" with a JSON body of {len(wf.step1_body.encode('utf-8', 'replace'))} bytes "
                f"(sha256:{_body_digest(wf)[:16]})")
    note = ""
    if m1 not in CEM_READ_ONLY_METHODS:
        note = "; a state-changing step 1 is sent by the owner and again by the other identity when the controls run"
    return (f"{head}; step 1: {m1} {redact_text(wf.step1_url)}{body}; "
            f"step 2: {m2} {redact_text(wf.step2_url_template)}{note}")


_HOSTNAME_RE = re.compile(r"[a-z0-9]([a-z0-9._-]*[a-z0-9])?")


def _valid_host_and_port(parts) -> bool:
    """A DNS name ([a-z0-9._-], no shell/space characters) or an IP literal, and a numeric port in range."""
    try:
        host = (parts.hostname or "").lower()
        parts.port  # noqa: B018 -- raises ValueError for a non-numeric or out-of-range port
    except ValueError:
        return False
    if not host:
        return False
    if _HOSTNAME_RE.fullmatch(host):
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _normalized_credentials(headers: dict) -> dict:
    return {str(k).strip().lower(): str(v).strip() for k, v in headers.items()}


def approval_host(url: str) -> str:
    """The host a human confirmation is bound to: lowercase hostname plus an explicit port (IPv6 in
    brackets), never userinfo -- the same host notion scope checks use. "" if the URL has no valid
    host/port (structural_error rejects those first)."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return ""
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{port}" if port else host


def scope_precheck(wf: Workflow) -> str | None:
    """Refusal text if either workflow URL is out of scope / blocked by outbound policy, else None.
    No network; lets a caller refuse BEFORE it spends a human-issued approval."""
    check = make_default_scope_check()
    for url in (wf.step1_url, wf.step2_url_template.replace(CARRIED_PLACEHOLDER, "x")):
        try:
            check(url)
        except RequestBlocked as e:
            return str(e)
    return None


def _carried_is_secret(wf: Workflow) -> bool:
    """The carried id is a secret if it arrives under a secret-named JSON key, or is placed in the
    step-2 URL under a secret-named query parameter."""
    if any(is_secret_key(seg) for seg in wf.carried_path.split(".")):
        return True
    query = urlsplit(wf.step2_url_template).query
    return any(CARRIED_PLACEHOLDER in value and is_secret_key(name)
               for name, value in parse_qsl(query, keep_blank_values=True))


def state_changing_methods(wf: Workflow) -> list[str]:
    """Normalized methods of this workflow's steps that are NOT read-only (GET/HEAD/OPTIONS)."""
    methods = {normalize_method(m) for m in (wf.step1_method, wf.step2_method)}
    return sorted(m for m in methods if m not in CEM_READ_ONLY_METHODS)


def _validate_workflow(wf: Workflow, owner_headers: dict, other_headers: dict,
                       approval) -> tuple[str, str] | None:
    """None if the workflow may run, else (verdict, reason): ERROR for a structurally bad
    workflow, BLOCKED for a human-gate refusal. The verdict is chosen here, not inferred
    from the message text."""
    bad = structural_error(wf, owner_headers, other_headers)
    if bad:
        return bad
    # The full per-request check (verb AND method-override headers) cem_engine itself uses, for
    # every identity that will send each step.
    for method in (wf.step1_method, wf.step2_method):
        for headers in (owner_headers, other_headers):
            refusal = check_request_allowed(method, headers, approval)
            if refusal:
                return "BLOCKED", refusal
    return None


def make_default_scope_check() -> Callable[[str], None]:
    """Outbound policy + engagement scope, fail-closed. Same sources of truth as the
    PreToolUse hook and case-mcp's per-trial check. The engagement is resolved ONCE per run
    (lazily, on the first request) and cached -- a load failure is cached too, so it keeps
    refusing instead of retrying."""
    resolver = _scope.EngagementResolver()

    def check(url: str) -> None:
        refusal = _scope.check_url(url, resolver.get)
        if refusal is None:
            return
        if refusal.kind == _scope.POLICY:
            raise RequestBlocked(f"outbound policy: {refusal.detail}")
        if refusal.kind == _scope.VERIFY_FAILED:
            raise RequestBlocked(f"scope gate could not verify {url!r} ({refusal.detail})")
        raise RequestBlocked(f"scope gate: {url!r} is not in the active engagement's in_scope list")

    return check


# --- the run ----------------------------------------------------------------

def run_two_step(wf: Workflow, owner_headers: dict[str, str], other_headers: dict[str, str], *,
                 fetch_fn: Callable | None = None, scope_check: Callable[[str], None] | None = None,
                 budget_cb: Callable[[], None] | None = None, approval=None,
                 timeout_s: float = http_probe.DEFAULT_TIMEOUT_S) -> AuthzResult:
    result = AuthzResult(verdict="ERROR")
    invalid = _validate_workflow(wf, owner_headers, other_headers, approval)
    if invalid:
        result.verdict, result.detail = invalid[0], redact_text(invalid[1])
        return result

    scrubber = _Scrubber(owner_headers, other_headers)
    fetch = fetch_fn or http_probe.fetch
    check_scope = scope_check or make_default_scope_check()
    step1_method, step2_method = normalize_method(wf.step1_method), normalize_method(wf.step2_method)

    def send(role: str, step: int, method: str, url: str, headers: dict,
             body: str | None = None) -> http_probe.FetchResult:
        try:
            check_scope(url)
            if budget_cb is not None:
                budget_cb()
        except RequestBlocked as e:
            raise _Stop("BLOCKED", str(e)) from e
        except BudgetExceeded as e:
            raise _Stop("BLOCKED", f"budget exhausted: {e}") from e
        except Exception as e:  # a crashing gate must fail closed, never open
            raise _Stop("BLOCKED", f"gate error before request: {e.__class__.__name__}") from e
        try:
            sent_headers = {**headers, "Content-Type": "application/json"} if body is not None else dict(headers)
            resp = fetch(url, method, sent_headers, body, timeout_s, allow_redirects=False)
        except Exception as e:  # e.g. InvalidURL; keep the log, report ERROR (never echo a credential)
            raise _Stop("ERROR", f"{role} step {step} request raised {e.__class__.__name__}: "
                                 f"{scrubber.scrub(str(e))}") from e
        result.requests.append({"role": role, "step": step, "method": method, "url": scrubber.scrub(redact_text(url)),
                                "status": resp.status, **({"error": scrubber.scrub(resp.error)} if resp.error else {})})
        return resp

    def step2_url(carried: str) -> str:
        return wf.step2_url_template.replace(CARRIED_PLACEHOLDER, quote(carried, safe=""))

    def carried_from(role: str, headers: dict, *, required_for: str) -> str:
        resp = send(role, 1, step1_method, wf.step1_url, headers, wf.step1_body)
        if resp.error or resp.status not in (200, 201):  # a create (POST) step 1 normally answers 201
            raise _Stop("BASELINE_FAILED" if role == "owner" else "INCONCLUSIVE",
                        f"{role}'s step 1 did not return 200 (status={resp.status}, error={resp.error!r})"
                        f" -- cannot {required_for}")
        value = extract_carried_id(resp.body, wf.carried_path)
        if not is_safe_carried_id(value):
            raise _Stop("ERROR", f"{role}'s step 1 yielded no usable carried id at {wf.carried_path!r}")
        if _carried_is_secret(wf):  # an id that is itself a secret: never store it raw
            scrubber.add(value)
        return value  # type: ignore[return-value]

    try:
        result.verdict, result.detail = _decide(wf, step2_method, owner_headers, other_headers, send,
                                                step2_url, carried_from, result, scrubber)
    except _Stop as stop:
        result.verdict, result.detail = stop.verdict, stop.detail
    except Exception as e:  # noqa: BLE001 -- any internal failure: ERROR with the request log kept
        result.verdict, result.detail = "ERROR", f"unexpected internal error: {e.__class__.__name__}"
    result.detail = scrubber.scrub(redact_text(result.detail))
    return result


def _decide(wf, step2_method, owner_headers, other_headers, send, step2_url, carried_from,
            result, scrubber) -> tuple[str, str]:
    carried_a = carried_from("owner", owner_headers, required_for="build the owner baseline")
    shown_id = redacted(carried_a, "carried-id") if _carried_is_secret(wf) else carried_a
    result.carried_id = shown_id
    url_a = step2_url(carried_a)

    owner1 = send("owner", 2, step2_method, url_a, owner_headers)
    owner_view = normalize_body(owner1.body)
    if owner1.error or owner1.status != 200 or owner_view is None:
        return "BASELINE_FAILED", (
            f"owner's own step 2 returned status={owner1.status} error={owner1.error!r} "
            "with " + ("an empty body" if owner_view is None else "a body") +
            " -- nothing to compare against; fix the baseline before trusting any verdict")

    l1 = _json_leaves(owner1.body)  # None when the owner's body is not JSON
    volatile: frozenset = frozenset()
    owner2 = None
    test = send("other", 2, step2_method, url_a, other_headers)
    if test.error:
        return "ERROR", f"other identity's request failed: {test.error}"
    if test.status in PROTECTED_STATUSES:
        return "PROTECTED", f"other identity got {test.status} for the owner's carried id -- access control holds"
    if test.status != 200:
        return "INCONCLUSIVE", f"other identity got unexpected status {test.status}"
    if normalize_body(test.body) != owner_view:
        if step2_method not in CEM_READ_ONLY_METHODS:
            return "DIFFERENT", _NOT_OWNERS_OBJECT  # never re-send a state-changing step
        # Does the body also differ between two fetches by the SAME identity (per-request fields)?
        owner2 = send("owner", 2, step2_method, url_a, owner_headers)
        if owner2.error or owner2.status != 200:
            return "INCONCLUSIVE", "could not re-fetch the owner's view to tell stable from per-request fields"
        if normalize_body(owner2.body) == owner_view:
            return "DIFFERENT", _NOT_OWNERS_OBJECT
        masked, early = _mask_per_request_fields(l1, owner2, test)
        if early:
            return early
        volatile, owner_view = masked

    if step2_method not in CEM_READ_ONLY_METHODS:
        return "INCONCLUSIVE", (
            "state-changing step 2: the other identity's request was accepted with the owner's id, but the "
            "stability, unauthenticated and own-object controls would each repeat the mutation, so they are "
            "not run and this cannot be established as LEAKED here -- confirm manually")

    # Equal -- but only meaningful if the owner's object has real content to be equal about.
    if (len(owner_view) < MIN_TEXT_CHARS) if l1 is None else _informative_count(l1, volatile) < MIN_INFORMATIVE_LEAVES:
        return "INCONCLUSIVE", (
            f"the owner's own object has fewer than {MIN_INFORMATIVE_LEAVES} informative fields (non-blank "
            "strings / non-zero numbers) -- an empty or placeholder object proves nothing: an API that "
            "filters instead of refusing would return the same empty 200 to any caller")

    # B received exactly A's object. Rule out the non-authz explanations first.
    if owner2 is None:
        owner2 = send("owner", 2, step2_method, url_a, owner_headers)
        if owner2.error or owner2.status != 200 or normalize_body(owner2.body) != owner_view:
            return "INCONCLUSIVE", "owner's own view is unstable across two fetches -- the comparison is not trustworthy"

    unauth = send("unauth", 2, step2_method, url_a, {})
    if unauth.error or unauth.status is None:
        return "INCONCLUSIVE", f"unauthenticated control failed ({unauth.error!r}) -- cannot rule out a public resource"
    if unauth.status == 200 and _comparable(unauth.body, volatile) == owner_view:
        return "PUBLIC", "an unauthenticated fetch returns the same object -- public resource, not an authorization bug"

    carried_b = carried_from("other", other_headers, required_for="build the other identity's own-object control")
    if carried_b == carried_a:
        return "INCONCLUSIVE", "both identities received the same carried id -- the replay is not cross-identity"
    own_b = send("other", 2, step2_method, step2_url(carried_b), other_headers)
    if own_b.error or own_b.status != 200:
        return "INCONCLUSIVE", f"other identity's own-object control returned status={own_b.status}"
    if _comparable(own_b.body, volatile) == owner_view:
        return "SHARED", ("the other identity's OWN object is byte-identical to the owner's -- the data is "
                          "authenticated-but-global, not owned by one identity")

    result.evidence = {
        "conditions": {"identity": "other", "step_order": [wf.step1_method + " step1", step2_method + " step2"],
                       "carried_id_source": f"owner step 1 @ {wf.carried_path}", "carried_id": shown_id,
                       **({"step1_body": "sha256:" + _body_digest(wf)[:16]} if wf.step1_body is not None else {})},
        "step1_url": scrubber.scrub(redact_text(wf.step1_url)),
        "step2_url": scrubber.scrub(redact_text(url_a)),
        "owner_view": scrubber.scrub(redact_body(owner1.body))[:EVIDENCE_BODY_CAP],
        "other_view": scrubber.scrub(redact_body(test.body))[:EVIDENCE_BODY_CAP],
        "unauth_status": unauth.status, "other_own_status": own_b.status,
        "masked_paths": sorted(scrubber.scrub(redact_text(_to_pointer(p))) for p in volatile),
        # Shape `case-mcp define_conditions` takes (no baseline_value: it would be a credential).
        # Phase-1 CEM can only DROP a header/query param, so only the swapped credential header is
        # expressible; the carried id and step order stay metadata above.
        "cem_candidate_conditions": [{"name": h, "category": "header", "perturbation": {"drop": True}}
                                     for h in other_headers if h.lower() in KNOWN_SECRET_HEADER_NAMES],
    }
    return "LEAKED", (
        "other identity received the owner's exact object using an id carried from the owner's step 1; "
        "owner view was stable, the resource is not public, and the other identity's own object differs. "
        "Candidate only -- confirm independently before CONFIRMED.")


# --- identity matrix (spec §5-VA (c)) --------------------------------------------------------

MAX_MATRIX_IDENTITIES = 5
_MATRIX_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")


class MatrixError(ValueError):
    """The matrix input is unusable; raised before any request is sent."""


@dataclass(frozen=True)
class MatrixIdentity:
    name: str
    headers: dict
    # Operator-declared access POLICY: True for an identity that is SUPPOSED to be able to read the
    # owner's object (an admin, a same-tenant colleague). Its access is then EXPECTED_ACCESS, never a leak.
    should_have_access: bool = False


@dataclass
class MatrixRow:
    name: str
    should_have_access: bool
    verdict: str
    result: AuthzResult


def matrix_error(wf: Workflow, owner_headers: dict, identities) -> str | None:
    if not isinstance(identities, (list, tuple)) or not identities:
        return "identities must be a non-empty list"
    if len(identities) > MAX_MATRIX_IDENTITIES:
        return f"at most {MAX_MATRIX_IDENTITIES} identities per matrix run"
    if state_changing_methods(wf):
        return "the identity matrix is read-only: a state-changing step is not allowed (use replay_authz_two_step)"
    names: set[str] = set()
    seen_creds: list[dict] = []
    for ident in identities:
        if not isinstance(ident, MatrixIdentity) or not isinstance(ident.name, str) \
                or not _MATRIX_NAME_RE.fullmatch(ident.name):
            return "each identity needs a name of 1-32 characters from [A-Za-z0-9_-]"
        if ident.name in names:
            return f"duplicate identity name {ident.name!r}"
        names.add(ident.name)
        if not isinstance(ident.should_have_access, bool):
            return f"should_have_access for {ident.name!r} must be true or false"
        bad = structural_error(wf, owner_headers, ident.headers)
        if bad:
            return f"identity {ident.name!r}: {bad[1]}"
        creds = _normalized_credentials(ident.headers)
        if creds in seen_creds:
            return f"identity {ident.name!r} uses the same credentials as another identity"
        seen_creds.append(creds)
    return None


def run_matrix(wf: Workflow, owner_headers: dict, identities, *, fetch_fn: Callable | None = None,
               scope_check: Callable[[str], None] | None = None, budget_cb: Callable[[], None] | None = None,
               timeout_s: float = http_probe.DEFAULT_TIMEOUT_S) -> list[MatrixRow]:
    """The two-step oracle run once per declared identity against the owner's object. Read-only. A
    LEAKED result for an identity whose policy says it should have access is EXPECTED_ACCESS. One
    scope resolver is shared by every row; a BLOCKED row (scope/budget/gate) stops the matrix."""
    err = matrix_error(wf, owner_headers, identities)
    if err:
        raise MatrixError(err)
    check = scope_check or make_default_scope_check()
    rows: list[MatrixRow] = []
    for ident in identities:
        result = run_two_step(wf, owner_headers, ident.headers, fetch_fn=fetch_fn, scope_check=check,
                              budget_cb=budget_cb, timeout_s=timeout_s)
        verdict = "EXPECTED_ACCESS" if result.verdict == "LEAKED" and ident.should_have_access else result.verdict
        rows.append(MatrixRow(ident.name, ident.should_have_access, verdict, result))
        if result.verdict == "BLOCKED":
            break
    return rows


def emit_matrix_findings(rows: list[MatrixRow], wf: Workflow, db_path: str | None = None) -> dict:
    """One DISCOVERED finding per identity that was wrongly allowed (verdict LEAKED, i.e. not
    EXPECTED_ACCESS); {identity name: emit_finding result}."""
    return {r.name: emit_finding(r.result, wf, db_path=db_path, identity=r.name)
            for r in rows if r.verdict == "LEAKED"}


def emit_finding(result: AuthzResult, wf: Workflow, db_path: str | None = None,
                 identity: str = "other") -> dict | None:
    """Records a LEAKED result in case_store as a DISCOVERED finding plus one metadata
    evidence row carrying the candidate CEM conditions (identity, step order, carried id).
    Any other verdict records nothing. Pure translation, same contract as P3-ADAPTER: it
    never advances a finding past DISCOVERED -- CONFIRMED stays behind the independent
    re-run + evidence gate (case-mcp's update_finding_status)."""
    if result.verdict != "LEAKED":
        return None
    import case_store  # local: keeps this module importable without a case.db side effect

    endpoint = redact_text(wf.step2_url_template)
    evidence = {**result.evidence,
                "conditions": {**result.evidence.get("conditions", {}), "identity": identity}}
    payload = json.dumps({**evidence, "verdict": result.verdict, "requests": result.requests})
    parameter = wf.carried_path if identity == "other" else f"{wf.carried_path}@{identity}"
    existing = case_store.find_finding("IDOR_MULTISTEP", endpoint, parameter, db_path=db_path)
    if existing:
        # A re-run, a later identity pair, or a first attempt whose evidence write failed: attach
        # the evidence if this exact content is not already on the finding.
        recorded = False
        if not case_store.has_evidence(existing["id"], hashlib.sha256(payload.encode()).hexdigest(),
                                       db_path=db_path):
            recorded = "error" not in case_store.add_evidence("metadata", payload, finding_id=existing["id"],
                                                              db_path=db_path)
        return {"finding_id": existing["id"], "status": existing["status"], "duplicate": True,
                "evidence_recorded": recorded}
    created = case_store.create_finding("IDOR_MULTISTEP", endpoint, parameter=parameter, db_path=db_path)
    if "error" in created:
        return created
    stored = case_store.add_evidence("metadata", payload, finding_id=created["id"], db_path=db_path)
    return {"finding_id": created["id"], "status": created["status"],
            "evidence_recorded": "error" not in stored}
