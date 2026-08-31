"""Local privilege-escalation vector analysis MCP server -- see
local_privesc.py's module docstring for the full design rationale (why
this is analysis of operator-supplied command output, not remote
command execution -- HuntMCP has no C2/remote-shell capability of its
own).

Deliberately NOT wired to budget_guard.py/audit_log.py, unlike every
other Tier-2-adjacent tool in this repo -- these functions never touch
the network or spawn a subprocess, they parse a string the caller
already has. That's pure local computation, not a Tier-2 action in the
sense scope_guard.py/budget_guard.py exist to gate; wiring them in here
would just be noise, the same reasoning idor_sweep.py's own internal
_classify() helper (vs. the real network-touching _fetch()) already
follows.
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])

import local_privesc
from mcp.server.fastmcp import FastMCP

app = FastMCP("local-privesc-mcp")


@app.tool()
def analyze_sudo_l(output: str) -> str:
    """Parses the raw output of `sudo -l` (run by the operator via
    whatever shell access they already have -- SSH, a confirmed RCE
    webshell, an established reverse shell) for NOPASSWD entries naming
    a well-known shell-escape-capable binary (GTFOBins-style: vim, find,
    python, docker, tar, and more) -- the single highest-value manual
    check in Linux/macOS privesc enumeration, automated. A flagged entry
    is a strong lead, not automatic confirmation -- verify the exact
    escape technique against the real binary/version/arguments allowed
    before treating it as a confirmed privesc path."""
    result = local_privesc.analyze_sudo_l(output)
    if not result["nopasswd_lines"]:
        return "No NOPASSWD entries found in this sudo -l output."
    lines = [f"{len(result['nopasswd_lines'])} NOPASSWD entr{'y' if len(result['nopasswd_lines'])==1 else 'ies'} found:"]
    if result["flagged"]:
        lines.append(f"  🔴 {len(result['flagged'])} flagged (known GTFOBins-style binary):")
        for f in result["flagged"]:
            lines.append(f"      {f['binary']}: {f['line']}")
    unflagged = [l for l in result["nopasswd_lines"] if not any(f["line"] == l for f in result["flagged"])]
    if unflagged:
        lines.append(f"  ⚪ {len(unflagged)} not on the known-dangerous list (not confirmed safe, just not flagged):")
        lines.extend(f"      {l}" for l in unflagged)
    return "\n".join(lines)


@app.tool()
def analyze_suid_binaries(output: str) -> str:
    """Parses a one-path-per-line SUID binary listing (e.g. `find / -perm
    -4000 -type f 2>/dev/null`, run by the operator via existing shell
    access) against the same GTFOBins-style dangerous-binary list.
    Non-default SUID binaries not on that list are ALSO flagged
    separately as "unusual" -- a custom/third-party SUID binary is often
    the more interesting finding than a well-known one, so it's
    surfaced rather than silently dropped just for not matching the
    curated list."""
    result = local_privesc.analyze_suid_binaries(output)
    if not result["flagged"] and not result["unusual_non_default_suid"]:
        return "No flagged or unusual SUID binaries found in this listing."
    lines = []
    if result["flagged"]:
        lines.append(f"🔴 {len(result['flagged'])} known-dangerous SUID binar{'y' if len(result['flagged'])==1 else 'ies'}:")
        for f in result["flagged"]:
            lines.append(f"    {f['path']}")
    if result["unusual_non_default_suid"]:
        lines.append(f"⚪ {len(result['unusual_non_default_suid'])} unusual (non-default) SUID binar{'y' if len(result['unusual_non_default_suid'])==1 else 'ies'} worth a manual look:")
        lines.extend(f"    {p}" for p in result["unusual_non_default_suid"])
    return "\n".join(lines)


@app.tool()
def analyze_windows_privileges(output: str) -> str:
    """Parses `whoami /priv` output (run by the operator via existing
    shell access) for enabled dangerous privileges -- SeImpersonate/
    SeAssignPrimaryToken (Potato-family exploits, one of the most common
    real-world Windows service-account privescs), SeBackup/SeRestore
    (ACL-bypassing file read/write), SeDebug (SYSTEM process token
    theft), SeLoadDriver, SeTakeOwnership, SeCreateToken, SeTcb. Only
    privileges shown as Enabled are flagged."""
    result = local_privesc.analyze_windows_privileges(output)
    if not result["flagged"]:
        return "No dangerous enabled privileges found in this whoami /priv output."
    lines = [f"🔴 {len(result['flagged'])} dangerous enabled privilege(s):"]
    for f in result["flagged"]:
        lines.append(f"  {f['privilege']}: {f['reason']}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("local-privesc-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
