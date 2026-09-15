#!/usr/bin/env python3
"""Claude Code PreToolUse hook: make the scope gate structurally unskippable.

Today, scope compliance depends on each agent's system-prompt instruction to
run scripts/check-scope.sh before a Tier-2 action -- an LLM could in
principle skip that step. This hook runs the same scope_guard.py check
outside the model's control, before the tool call is allowed to execute at
all (Phase 2.8 backlog item, ARCHITECTURE.md).

Claude Code feeds {"tool_name": ..., "tool_input": {...}} on stdin before
every tool call. Exit 2 blocks the call and surfaces stderr to the agent as
the reason; exit 0 allows it.

Deliberately narrow scope, so ordinary repo development (git, go install,
pip install, editing files, curl-ing a package registry) never trips this:

- Bash commands only trigger a check when the invoked binary is one of the
  actual Tier-2 tools HuntMCP's own MCP servers shell out to (see
  mcp-servers/*/server.py's run_tool() calls), plus curl/wget -- not any
  command that merely contains a domain-looking string. curl/wget are
  included even though no dedicated MCP server wraps them, because they are
  the most direct unguarded path to a live target -- a raw `curl
  https://target.com/...` was previously invisible to this hook entirely.
- MCP tool calls only trigger a check for the Tier-2 (target-touching)
  servers -- writeup-mcp/memory-mcp/lessons-mcp/chainer-mcp operate on local
  knowledge, not a live target, and are exempt.
- WebFetch/webfetch (both harnesses' native URL-fetch tool) is
  deliberately NOT scope-gated at all, unlike Bash's curl/wget --
  briefly was (2026-08-29), then reverted the same day. curl/wget send
  attacker-controlled requests AT a target (probing, exploiting);
  WebFetch's actual use in this agent system is overwhelmingly read-only
  research (a CVE page, a writeup, vendor docs) that never touches the
  target at all, and gating it the same way as curl blocked that
  entirely -- any research URL that wasn't the target itself or on the
  dev-infra allowlist got refused as "not in scope," which isn't a
  meaningful authorization boundary for reading a public webpage the way
  it is for sending a crafted request to a target's own infrastructure.
- example.com/example.org/example.net/localhost/loopback/RFC1918 hosts, plus
  a small allowlist of known dev infrastructure (GitHub, PyPI, npm, Go
  module proxy, Debian/Ubuntu package mirrors -- see scope_guard.py's
  DEV_INFRA_HOSTS, the shared source of truth for this exemption), are
  always allowed with no engagement.yaml required -- that's normal
  development/testing, not a live engagement.
"""

from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mcp-servers"))
from audit_log import log_call as _log_call  # noqa: E402
from budget_guard import BudgetExceeded  # noqa: E402
from budget_guard import enforce as _enforce_budget  # noqa: E402
import rce_confirm  # noqa: E402
from scope_guard import NoEngagementFile, is_in_scope, load_engagement  # noqa: E402
from scope_guard import is_safe_test_host as _is_safe_test_host  # noqa: E402

# The exact binaries HuntMCP's MCP servers shell out to (mcp-servers/*/server.py
# run_tool() calls) -- the real Tier-2 boundary, not a guess. curl/wget are
# added separately below: unlike the others, they're not wrapped by any
# dedicated MCP server today, so a raw `curl https://target.com/...` was a
# genuine unguarded path to a live target, not just a defense-in-depth
# duplicate of an MCP wrapper. Found 2026-08-26 while reviewing an external
# skill library (uphiago/recon-skills) whose procedures are curl-heavy --
# adopting that style of content without this fix would have made scope
# enforcement bypassable by construction.
TIER2_BASH_TOOLS = {
    "subfinder", "httpx", "katana", "nmap", "nuclei", "sqlmap", "dalfox", "ffuf",
    "curl", "wget",
    # scripts/curl-rl.sh is a drop-in curl wrapper (adds reactive 429/
    # Retry-After backoff a PreToolUse hook has no way to provide itself --
    # a hook can only allow/block a command before it runs, it can't wrap
    # or retry the actual subprocess execution). Listed here explicitly so
    # calling it instead of raw curl is not a way to silently skip scope
    # enforcement just because the binary name changed.
    "curl-rl.sh",
}

# curl/wget also legitimately touch non-target infrastructure during ordinary
# MCP-server development -- package registries, source hosting, docs -- which
# must stay exempt the same way scope_guard.SAFE_TEST_HOSTS exempts
# example.com/localhost. That allowlist (DEV_INFRA_HOSTS) now lives in
# scope_guard.py, the one shared source of truth _is_safe_test_host uses --
# not duplicated here anymore (was, until 2026-08-29; see module docstring).
# Kept separate from content_scanner.py's KNOWN_GOOD_HOSTS (that allowlist is
# for outbound calls made BY this repo's own Python code to known service
# integrations; this one is for a human/agent curl-ing the open internet
# during development -- different concern, deliberately not shared).

# MCP servers that actually touch a live target vs. operate on local knowledge only.
TIER2_MCP_SERVERS = {
    "subfinder-mcp", "httpx-mcp", "katana-mcp", "nmap-mcp",
    "nuclei-mcp", "sqlmap-mcp", "dalfox-mcp", "ffuf-mcp", "watch-mcp",
    "waf-bypass-mcp", "browser-mcp", "playwright-mcp", "idor-mcp",
    # obscura-mcp is the same live-target-touching browser-automation role
    # as browser-mcp/playwright-mcp above -- added here so it gets the
    # identical structural scope-gate, not just the documented-convention
    # one. NOTE (corrected after initially overclaiming this): only
    # browser_navigate(url) actually carries a HOST_ARG_KEYS-matching
    # param, per obscura's real MCP tool schema -- browser_screenshot/
    # browser_evaluate/browser_click/etc. act on the already-navigated
    # page's current state and take no url, so they aren't independently
    # re-gated. This isn't a live bypass today (there's no host to check
    # on those calls), but it does mean scope enforcement for an obscura
    # session lives entirely at its one browser_navigate call -- an
    # in-page redirect or a followed link that lands somewhere out of
    # scope is not itself re-checked. connect-obscura.sh's own printed
    # instructions tell agents to always browser_navigate to the exact
    # intended URL rather than relying on in-page navigation.
    "obscura-mcp",
    # ad-recon-mcp's kerberoast_tool/asreproast_tool both take a `domain`
    # param (an AD domain, e.g. "corp.local") -- unlike aws/azure/
    # gcp-postexploit-mcp (which take a credential, not a domain, and are
    # deliberately NOT here -- see their own module docstrings), this one
    # genuinely has a hostname-shaped arg HOST_ARG_KEYS can extract and
    # check, so it gets the same real scope-gate every other domain-taking
    # Tier-2 server already does.
    "ad-recon-mcp",
}

# MIXED MCP servers: mostly local (bookkeeping / DB reads), but a NAMED subset
# of their tools touches a live target. Listing a server here instead of in
# TIER2_MCP_SERVERS means: "scope-gate ONLY these exact tool names on this
# server; treat every other tool on it as local and never scope-check it."
# Without this, a `target`/`url`-shaped arg on a purely local tool (e.g.
# case-mcp's log_experiment(target=...) / check_experiment_exists(target=...),
# which only write/read a SQLite row) would be mistaken for a network
# destination and blocked. A future mixed server adds one entry here; the
# whole-server TIER2_MCP_SERVERS path is unchanged for every server on it.
#
# IMPORTANT -- for case-mcp's two senders this hook's host extraction from
# their `url` arg is only a cheap EARLY FILTER, not the security boundary.
# The URL cem_engine.run_intervention actually fetches is
# meta["base_request"]["url"], which is stored engagement state this hook
# cannot see without coupling to the CEM schema. The DEFINITIVE, decoupling-
# proof scope check for those sends lives in mcp-servers/case-mcp/server.py
# (_scope_or_error, reusing scope_guard) and runs before run_intervention.
TIER2_MCP_TOOLS: dict[str, frozenset[str]] = {
    "case-mcp": frozenset({"determinism_gate", "run_counterfactual"}),
}

HOST_ARG_KEYS = ("domains", "domain", "target", "targets", "url", "host", "hosts")

HOSTNAME_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

URL_RE = re.compile(r"https?://[^\s\"'<>]+")

# Matches a whole email address (local-part@domain), so it can be blanked
# out of a command BEFORE the HOSTNAME_RE fallback scan runs -- reported
# live, independently, across two engagements: a curl call whose JSON
# request body or header value contained a free-text email address was
# blocked as "host not in scope" even though the actual request target
# (matched separately, via URL_RE, before this fallback regex ever runs)
# was fully in scope. An email domain is data being sent IN a request, not
# a destination the request is being sent TO -- it was never a real scope
# violation to begin with, so this loses no genuine detection.
#
# Deliberately a whole-span removal (same pattern as URL_RE's span removal
# below), NOT a bare `(?<!@)` lookbehind on HOSTNAME_RE itself -- a
# lookbehind only blocks a match from STARTING immediately after "@", but
# HOSTNAME_RE's own label pattern allows hyphens inside a label, so for a
# hyphenated domain (e.g. "tester@my-mail-host.example.org") the regex
# engine can still re-enter and match a bogus PARTIAL suffix like
# "mail-host.example.org" starting right after the hyphen -- confirmed by
# hand: `(?<!@)`-only left "corp.com" leaking out of
# "tester@realtarget-corp.com". Removing the whole matched email span
# first closes that; there's no substring left for HOSTNAME_RE to
# re-enter on.
EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}"
)

# SAFE_TEST_HOSTS/DEV_INFRA_HOSTS/NON_TLD_FILE_EXTENSIONS and the
# is_safe_test_host() check itself moved to scope_guard.py 2026-08-29 -- it's
# the shared authority scripts/check-scope.sh's CLI also needs (that script
# used to have NO such exemption at all, so an agent following its own
# "run check-scope.sh before touching any host" instruction would self-block
# on example.com/github.com the moment any unrelated engagement.yaml
# existed, something this hook itself never actually required). Imported
# as _is_safe_test_host above.

# Deliberately kept local, NOT part of scope_guard.is_safe_test_host(): these
# are for filtering candidates out of this hook's own blanket command-text
# regex scan specifically, not for deciding whether a host is authorized.
# `curl ... -H "Origin: https://evil.com"` has evil.com as a header VALUE,
# not the host actually being contacted -- but if evil.com were ever the
# actual target argument to a real Tier-2 tool, it still needs a genuine
# in_scope entry like any other domain (someone could really own it).
_ATTACKER_PLACEHOLDER_HOSTS = {"evil.com", "attacker.com", "malicious.com"}


def _is_candidate_exempt(host: str) -> bool:
    return _is_safe_test_host(host) or host.lower().strip(".") in _ATTACKER_PLACEHOLDER_HOSTS


def _first_word(command: str) -> str:
    stripped = command.strip()
    return stripped.split()[0].rsplit("/", 1)[-1] if stripped else ""


# Splits a bash command on the shell operators that start a new sub-command
# (chaining, piping, subshells, newlines) so a blocked command can't be
# smuggled in as the second half of `curl ... && rm -rf data/`. Deliberately
# NOT a blanket `\brm\b` substring scan -- that would also flag an unrelated
# file literally named `rm.log` in a redirect. Matching Bash(rm *)/Bash(rm)
# prefix semantics per sub-command is the same rule .claude/settings.json
# already enforces, just extended across `;`/`&&`/`|`/`$(`.
#
# Deliberately excludes a bare `)` as a split point -- regex can't balance
# parens, so treating every `)` as "end of a $(...) subshell" would also
# split on a stray `)` from unrelated command text (e.g. a Python literal
# passed via `python3 -c "..."`), putting whatever text follows it into its
# own piece and false-positive-blocking on an unrelated "rm" that appears
# later in the same command line, not at a real sub-command boundary.
#
# Also deliberately excludes a bare backtick -- confirmed live 2026-08-26:
# writing a PR body via `gh pr create --body "$(cat <<'EOF' ... EOF)"` with
# markdown inline code like `` `rm -f scratch-file.txt` `` in the body text
# tripped this exact check, because a lone backtick was treated as opening a
# command substitution and everything after it (starting with "rm") became
# its own piece. Backtick substitution is legacy syntax modern agents rarely
# use for real chaining, and this codebase writes a lot of markdown-heavy
# commit/PR-body text through Bash -- the false-positive cost of keeping it
# outweighs the real-smuggling coverage it would add on top of `$(`.
_CHAIN_SPLIT_RE = re.compile(r"&&|\|\||[;&|\n]|\$\(")


# Shared by _is_rm_command() and _reads_env_file() -- both need "the real
# invoked binary, past any sudo/env wrapper" as their first word, and used
# to each re-derive this independently (found in code review: two copies
# of the same security-relevant matching rule that could silently drift).
# Loops rather than a single unwrap: `sudo env cat .env` previously only
# stripped "sudo", leaving "env" (itself unrecognized) as the first word --
# a doubled-wrapper bypass found live in code review.
def _strip_prefix_words(words: list[str]) -> list[str]:
    while len(words) > 1 and words[0].rsplit("/", 1)[-1] in ("sudo", "env"):
        words = words[1:]
    return words


def _is_rm_command(command: str) -> bool:
    for piece in _CHAIN_SPLIT_RE.split(command):
        words = _strip_prefix_words(piece.split())
        if not words:
            continue
        if words[0].rsplit("/", 1)[-1] == "rm":
            return True
    return False


# S3 (secrets scoped out of untrusted execution): there is no legitimate
# reason an agent's own Bash tool call ever needs to read .env's raw
# contents -- every real consumer reads a credential via
# dotenv_loader.get_secret() inside a trusted MCP server process, never
# via a shell command. Same blanket "never run, never ask" category as
# the rm-block above, independent of scope/engagement state.
#
# Gated on the SUB-COMMAND'S OWN FIRST WORD being one of these read/
# interpreter-shaped binaries, same precedent as _is_rm_command() only
# checking the first word of each piece -- not a scan of every word
# anywhere in the command. Necessary, found live: _CHAIN_SPLIT_RE splits
# on newlines too (so a real multi-line shell script's separate commands
# are each checked independently, same as rm's), but that also means a
# heredoc's own multi-line TEXT BODY (e.g. `git commit -m "$(cat <<'EOF'
# ...prose mentioning the word .env...  EOF)"`) gets torn into one
# "piece" per line of prose -- scanning every word of a prose line for a
# bare ".env" token false-positive-blocks on ordinary documentation text
# that merely mentions the filename, not an actual read of it. Requiring
# the line's own first word to already be a recognized read command
# closes that: a commit-message prose line's first word is essentially
# never "cat"/"grep"/"python3"/etc.
_ENV_FILE_READ_COMMANDS = {
    "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep",
    "awk", "sed", "strings", "xxd", "hexdump", "od",
    "vim", "vi", "nano", "emacs", "bat",
    "python3", "python", "node", "perl", "ruby", "php",
    # Copy/transfer/archive commands -- staging exfiltration (`cp .env
    # /tmp/x`) doesn't itself print contents into the agent's visible
    # transcript the way `cat` does, but it's the same "get .env's
    # contents somewhere retrievable" move, one step removed. Found live
    # in code review: `cp .env /tmp/x && cat /tmp/x` bypassed the block
    # entirely -- neither half individually named `.env` as a read target.
    "cp", "mv", "rsync", "tar", "cpio", "scp", "install", "dd", "base64",
}


def _reads_env_file(command: str) -> bool:
    for piece in _CHAIN_SPLIT_RE.split(command):
        try:
            words = shlex.split(piece)
        except ValueError:
            words = piece.split()
        words = _strip_prefix_words(words)
        if not words:
            continue
        first = words[0].rsplit("/", 1)[-1]
        if first not in _ENV_FILE_READ_COMMANDS:
            continue
        for word in words[1:]:
            # .rstrip(")") handles $(cat .env)'s unclosed-by-this-regex
            # trailing paren (found live in code review): _CHAIN_SPLIT_RE
            # splits on the opening "$(" but can't balance the matching
            # close (same documented regex limitation as the rm-block's
            # own bare-')' exclusion), so the argument word is ".env)"
            # rather than ".env" -- strip it before comparing.
            if word.rsplit("/", 1)[-1].rstrip(")") == ".env":
                return True
    return False


# S4 (persistent-RCE / state-changing confirmation tier): sqlmap's own
# --os-shell/--os-pwn/--os-cmd/--os-bof flags escalate a confirmed SQLi
# finding into actual OS-level command execution on the target -- a much
# bigger step than the read-only injection testing every other sqlmap flag
# performs, and until now nothing distinguished it from an ordinary sqlmap
# call. Blanket "never run without an explicit human confirm on file" rule,
# same category as the rm-block and .env-block above (independent of
# scope/engagement state -- being in-scope doesn't itself authorize this).
# See mcp-servers/rce_confirm.py's own module docstring for why the "ask"
# side of this has to be a separate, human-run interactive script rather
# than a declarative bash permission (same reason as the rm-block's own
# comment above: opencode.jsonc's declarative "ask"/deny was empirically
# not enforced under `opencode run --auto`).
_PERSISTENT_RCE_FLAGS = {"--os-shell", "--os-pwn", "--os-cmd", "--os-bof"}


def _is_persistent_rce_command(command: str) -> bool:
    if "sqlmap" not in command:
        # Cheap short-circuit before any parsing -- this runs on every
        # single Bash call (git status, file edits reaching Bash, ...),
        # and the overwhelming majority never mention sqlmap at all.
        return False
    for piece in _CHAIN_SPLIT_RE.split(command):
        try:
            words = shlex.split(piece)
        except ValueError:
            words = piece.split()
        words = _strip_prefix_words(words)
        if not words:
            continue
        # Regression (code-review finding, CONFIRMED, found by 2
        # independent review angles): checking only words[0] missed any
        # wrapper that puts other words first -- `timeout 600 sqlmap -u x
        # --os-shell` or `xargs -I{} sqlmap {} --os-shell` both evaded
        # detection entirely, since "sqlmap" was never in first-word
        # position. Scan every word in the piece for "sqlmap" (as its own
        # basename-stripped token, not a substring of some other word) and
        # for a persistent-RCE flag, and require both to co-occur in the
        # SAME piece -- this still won't parse an opaque nested command
        # string (`bash -c "sqlmap ... --os-shell"`, a python3 -c
        # subprocess call), the same acknowledged gap the rm-block and
        # .env-block already carry for the identical reason (see this
        # file's own module docstring): closing that would mean actually
        # parsing arbitrary shell/interpreter syntax, not a cheap
        # word-scan.
        basenames = [w.rsplit("/", 1)[-1] for w in words]
        if "sqlmap" not in basenames:
            continue
        for word in words:
            # sqlmap accepts both "--os-cmd whoami" and "--os-cmd=whoami" --
            # match on the flag prefix before any "=", not exact equality,
            # or the "=" form would silently slip through.
            flag = word.split("=", 1)[0]
            if flag in _PERSISTENT_RCE_FLAGS:
                return True
    return False


def _extract_hosts_from_bash(command: str) -> list[str]:
    if _first_word(command) not in TIER2_BASH_TOOLS:
        return []

    # Prefer real URL parsing over blanket regex where a scheme is present --
    # this is what actually distinguishes "the host curl is contacting" from
    # a same-looking substring in the URL's own path (curl .../main/file.txt
    # regex-matches "file.txt" as if it were a second hostname otherwise).
    hosts: list[str] = []
    seen_spans: list[tuple[int, int]] = []
    for m in URL_RE.finditer(command):
        seen_spans.append(m.span())
        host = urlsplit(m.group(0)).hostname
        if host:
            hosts.append(host)

    # Remove matched URL spans before the fallback bare-hostname scan, so a
    # URL's own path/query never gets double-scanned by HOSTNAME_RE.
    remainder = command
    for start, end in sorted(seen_spans, reverse=True):
        remainder = remainder[:start] + " " + remainder[end:]

    # Also remove whole email-address spans (see EMAIL_RE's own comment for
    # why this has to be a full-span removal, not a lookbehind on
    # HOSTNAME_RE itself) before the fallback scan.
    remainder = EMAIL_RE.sub(" ", remainder)

    hosts.extend(HOSTNAME_RE.findall(remainder))
    return [h for h in hosts if not _is_candidate_exempt(h)]


def _extract_hosts_from_tool_input(tool_input: dict) -> list[str]:
    hosts: list[str] = []
    for key in HOST_ARG_KEYS:
        val = tool_input.get(key)
        if not isinstance(val, str):
            continue
        for piece in re.split(r"[,\s]+", val):
            piece = piece.strip()
            if not piece:
                continue
            found = HOSTNAME_RE.findall(piece)
            candidate = found[0] if found else piece
            if not _is_candidate_exempt(candidate):
                hosts.append(candidate)
    return hosts


def _mcp_server_name(tool_name: str) -> str:
    # Claude Code MCP tool names are "mcp__<server>__<tool>"
    parts = tool_name.split("__")
    return parts[1] if len(parts) >= 2 else ""


def _mcp_tool_name(tool_name: str) -> str:
    # "mcp__<server>__<tool>" -- the tool part may itself contain "__".
    parts = tool_name.split("__")
    return "__".join(parts[2:]) if len(parts) >= 3 else ""



def _block(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 2


def main() -> int:
    # S1 (fail-closed target-touching scope behavior): malformed stdin means
    # this hook cannot even determine which tool call it's guarding -- it
    # might be a raw Tier-2 curl/nuclei/etc. call to an out-of-scope host,
    # which is exactly what this hook exists to catch. Previously returned 0
    # here ("fail open, never break the session over this"); that let a
    # corrupted/tampered hook invocation silently allow the one class of
    # call this hook is the sole enforcement point for. Block instead --
    # this stops only the ONE gated tool call that produced the malformed
    # payload (exit 2, clear stderr reason), not the session itself. In real
    # operation Claude Code/OpenCode construct this JSON themselves from the
    # tool call already in flight, so this is not expected to fire on
    # ordinary Read/Edit/git-status traffic.
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return _block(
            "BLOCKED by scope gate: could not parse the hook's own stdin "
            "payload (malformed JSON). Failing closed rather than silently "
            "allowing a tool call this hook could not inspect -- retry the "
            "tool call; if this persists, the hook invocation itself is "
            "broken and needs a human look."
        )

    # Syntactically valid JSON that isn't shaped like {"tool_name": ...,
    # "tool_input": {...}} (a bare null/list/string/number, or a dict whose
    # tool_name isn't a string) leaves this hook just as unable to identify
    # the tool call as the parse-failure case above -- same reasoning, same
    # fail-closed response. Found live during review: e.g. `echo null |
    # ...` previously crashed on payload.get() with an uncaught
    # AttributeError (exit 1), which both real callers (.claude/
    # settings.json's PreToolUse dispatch and .opencode/plugin/
    # scope-gate.ts's `exitCode === 2` check) treat as an implicit allow --
    # the exact fail-open gap S1 exists to close, just reachable one step
    # earlier than the Tier-2 evaluation below.
    if not isinstance(payload, dict):
        return _block(
            "BLOCKED by scope gate: hook payload is not a JSON object. "
            "Failing closed rather than silently allowing a tool call this "
            "hook could not inspect."
        )

    tool_name = payload.get("tool_name", "")
    if not isinstance(tool_name, str):
        return _block(
            "BLOCKED by scope gate: hook payload's tool_name is not a "
            "string. Failing closed rather than silently allowing a tool "
            "call this hook could not inspect."
        )

    # Decided purely from tool_name, before tool_input is ever touched --
    # this is what keeps the fail-closed shape-checks below from widening
    # the gate to non-Tier2 tools. A malformed/unexpected tool_input on a
    # tool this hook was never going to gate (Read, Grep, WebFetch, ...)
    # must still pass straight through untouched.
    if tool_name != "Bash" and not tool_name.startswith("mcp__"):
        return 0

    tool_input = payload.get("tool_input", {})
    if tool_input is None:
        tool_input = {}
    if not isinstance(tool_input, dict):
        return _block(
            f"BLOCKED by scope gate: {tool_name!r} call's tool_input is not "
            "a JSON object. Failing closed rather than silently allowing a "
            "tool call this hook could not inspect."
        )

    command = tool_input.get("command", "")
    if tool_name == "Bash" and not isinstance(command, str):
        return _block(
            "BLOCKED by scope gate: this Bash call's command is not a "
            "string. Failing closed rather than silently allowing a tool "
            "call this hook could not inspect."
        )

    # Blanket rm block -- unconditional, independent of scope/engagement
    # state entirely (this is a "never run rm, never ask" rule, not a
    # target-scope rule). .claude/settings.json's `Bash(rm *)`/`Bash(rm)`
    # permissions.deny already enforces this for Claude Code before the
    # call even reaches this hook; this check is what makes it real for
    # OpenCode too (via .opencode/plugin/scope-gate.ts, which invokes this
    # same script for every Bash call) -- opencode.jsonc's declarative
    # `permission.bash` glob deny (`"rm **": "deny"` alongside `"*":
    # "allow"`) was tested live and did not actually block rm across
    # several pattern/ordering attempts, so this hook is the real
    # enforcement point on that harness, same as it already is for scope.
    if tool_name == "Bash" and _is_rm_command(command):
        return _block(
            "BLOCKED: rm is disabled by default in this repo (both Claude "
            "Code and OpenCode) -- ask the user to delete the file "
            "themselves, or move it aside instead of removing it."
        )

    # S3 (secrets scoped out of untrusted execution) -- same blanket,
    # unconditional category as the rm-block above. See _reads_env_file()'s
    # own comment for what this does and doesn't catch.
    if tool_name == "Bash" and _reads_env_file(command):
        return _block(
            "BLOCKED: reading .env directly is disabled by default in this "
            "repo -- every real credential consumer reads it via "
            "dotenv_loader.get_secret() inside a trusted MCP server "
            "process, never via a shell command. If you need to verify a "
            "key is set, ask the user, or check via an MCP tool that "
            "already reads it server-side."
        )

    # S4 (persistent-RCE / state-changing confirmation tier) -- same
    # blanket, unconditional category as the rm-block and .env-block
    # above (fires regardless of whether a host was extractable from the
    # command text, so a `sqlmap -r request.txt --os-shell` invocation
    # with no literal host in the command is still gated). See
    # _is_persistent_rce_command()'s own comment for what this matches and
    # rce_confirm.py for how the human-confirm/target-binding side works.
    #
    # Needs the active engagement's target to bind the confirmation token
    # to (see rce_confirm.check_and_consume()) and does real file I/O
    # (rce_confirm.check_and_consume() itself) -- wrapped in its own
    # fail-closed try/except, same discipline as the Tier-2 net below.
    # Regression (code-review finding, CONFIRMED): this used to sit
    # unguarded outside any try/except -- an internal error here (a
    # permissions/disk error reading the token) would propagate uncaught
    # out of main(), and since only exit 2 is this harness's documented
    # block signal, both real callers would treat that as an implicit
    # ALLOW, letting a persistent-RCE command through on an internal
    # error -- exactly the fail-open class S1 exists to close, reopened
    # one check later in the same function.
    if tool_name == "Bash" and _is_persistent_rce_command(command):
        try:
            try:
                rce_engagement = load_engagement()
            except (NoEngagementFile, RuntimeError):
                return _block(
                    "BLOCKED by scope gate: no engagement.yaml found, but "
                    "this command requests a persistent OS-shell / "
                    "state-changing sqlmap action. Write engagement.yaml "
                    "first, then get explicit human confirmation via "
                    "scripts/confirm-os-shell.sh."
                )
            if not rce_confirm.check_and_consume(rce_engagement.target):
                return _block(
                    "BLOCKED: this sqlmap call requests a persistent "
                    "OS-shell / state-changing action (--os-shell/"
                    "--os-pwn/--os-cmd/--os-bof) against "
                    f"{rce_engagement.target!r}. This needs an explicit, "
                    "interactive human confirm before it runs -- being "
                    "in-scope is not enough on its own. Ask the user to "
                    f"run `scripts/confirm-os-shell.sh {rce_engagement.target}` "
                    "themselves, in their own terminal (it refuses if not "
                    "run interactively), then retry this exact command."
                )
        except Exception as exc:  # noqa: BLE001 -- deliberate fail-closed net, see comment above
            return _block(
                "BLOCKED by scope gate: internal error while evaluating "
                f"the persistent-RCE confirmation gate ({exc!r}). Failing "
                "closed rather than silently allowing a call this hook "
                "could not verify."
            )
        # Confirmed and allowed -- the one action this whole gate exists
        # for must leave an audit trail. Unlike curl/wget below, a raw
        # Bash sqlmap call has no OTHER audit_log wiring anywhere in this
        # file (sqlmap is normally assumed to be audited via sqlmap-mcp's
        # own run_tool(), which a raw Bash call never goes through).
        try:
            rce_args = shlex.split(command)[1:]
        except ValueError:
            rce_args = []
        _log_call("sqlmap-os-shell-confirmed", rce_args, returncode=None, duration_ms=0.0, block=None)

    # S1 (fail-closed target-touching scope behavior): everything in this
    # try -- binary/server narrowing, host extraction from tool_input,
    # engagement load, in-scope check -- is the Tier-2 (target-touching)
    # evaluation this hook exists to perform. A `return 0` for a tool this
    # hook has determined is NOT Tier-2 (non-Tier-2 MCP server, a
    # locally-scoped tool on a mixed server) is an ordinary, intentional
    # exit from inside the try -- returning doesn't raise, so it never
    # reaches the except below, and this does NOT widen the gate to
    # non-Tier2 tools. What the except DOES catch is any unexpected
    # exception raised while evaluating a call already identified as
    # Tier-2 (a malformed engagement.yaml, a bug in host extraction, etc.)
    # -- previously such an exception propagated uncaught, and since only
    # exit 2 is this harness's documented block signal, that silently
    # allowed the call through. Block instead. load_engagement()'s own two
    # documented exceptions still get their own specific message via a
    # small nested try immediately around that one call (see below); this
    # outer except is the generic net for everything else.
    try:
        if tool_name == "Bash":
            candidates = _extract_hosts_from_bash(command)
        else:
            server = _mcp_server_name(tool_name)
            if server in TIER2_MCP_SERVERS:
                candidates = _extract_hosts_from_tool_input(tool_input)
            elif server in TIER2_MCP_TOOLS:
                # Mixed server: only the named network tools are gated; every
                # other tool on it is local and passes straight through.
                if _mcp_tool_name(tool_name) not in TIER2_MCP_TOOLS[server]:
                    return 0
                candidates = _extract_hosts_from_tool_input(tool_input)
            else:
                return 0

        if not candidates:
            return 0

        # load_engagement()'s own two documented exceptions get a nested,
        # specific try/except here rather than sharing the outer except
        # below -- `candidates` is only guaranteed bound by this point (the
        # `if not candidates: return 0` above already ran), so the
        # candidates[0] reference in this message would be unsafe if
        # NoEngagementFile/RuntimeError could somehow be raised any
        # earlier. Nesting keeps that guarantee explicit instead of relying
        # on "the extraction helpers happen not to raise those two types."
        try:
            engagement = load_engagement()
        except (NoEngagementFile, RuntimeError):
            return _block(
                "BLOCKED by scope gate: no engagement.yaml found, but this call "
                f"names a real-looking target host ({candidates[0]!r}). Write "
                "engagement.yaml at Phase 0 before any Tier-2 action, or use a "
                "known test host (example.com/localhost) for MCP server dev work."
            )

        for host in candidates:
            if not is_in_scope(host, engagement):
                return _block(
                    f"BLOCKED by scope gate: {host!r} is not in engagement.yaml's "
                    f"in_scope list for {engagement.target!r}. Refusing this tool "
                    "call -- do not work around this."
                )
    except Exception as exc:  # noqa: BLE001 -- deliberate fail-closed net, see comment above
        return _block(
            "BLOCKED by scope gate: internal error while evaluating this "
            f"Tier-2 call ({exc!r}). Failing closed rather than silently "
            "allowing a call this hook could not verify -- do not work "
            "around this; fix the underlying error (e.g. a malformed "
            "engagement.yaml) instead."
        )

    # curl/wget/curl-rl.sh have no dedicated MCP wrapper (see the module
    # docstring/TIER2_BASH_TOOLS comment above), so nothing else in this
    # codebase ever routes them through tool_resolver.run_tool() -- meaning
    # nothing else ever calls budget_guard.enforce()/audit_log.log_call()
    # for them either. Wire both in here, once scope has genuinely passed
    # for a real in-scope host (not for the other TIER2_BASH_TOOLS members --
    # those already get budgeted/audited exactly once via their own MCP
    # server's run_tool() call, so doing it here too would double-count
    # every raw-Bash nmap/nuclei/etc. invocation that's also MCP-wrapped).
    # This is a PreToolUse hook -- the command hasn't run yet, so there's no
    # real returncode/duration/WAF-block classification available the way
    # run_tool() has after the fact; logged as None/0.0/None. That still
    # captures the primary audit value (exact command + args + timestamp of
    # every real Tier-2 curl/wget/curl-rl.sh attempt) without the
    # schema-risk of correlating a second PostToolUse hook by callID.
    if tool_name == "Bash" and _first_word(command) in ("curl", "wget", "curl-rl.sh"):
        name = _first_word(command)
        try:
            _enforce_budget(name)
        except BudgetExceeded as e:
            print(f"BLOCKED by scope gate: Tier-2 budget exceeded ({e}).", file=sys.stderr)
            return 2
        try:
            args = shlex.split(command)[1:]
        except ValueError:
            args = []
        _log_call(name, args, returncode=None, duration_ms=0.0, block=None)

    return 0


if __name__ == "__main__":
    sys.exit(main())
