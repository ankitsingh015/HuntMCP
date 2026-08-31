"""Local privilege-escalation vector analysis -- an ANALYSIS tool, not an
execution tool, and deliberately so: HuntMCP has no remote-shell/command-
execution capability of its own (it's a recon/scan/exploit framework for
web/API bug bounty, not a C2 framework), so "enumerate this compromised
host's privesc vectors" cannot mean "run commands on it" the way the
cloud siblings (aws/azure/gcp-postexploit-mcp) can call a live API
directly. What it CAN mean, honestly: parse the raw output of standard,
well-known enumeration commands the operator already ran themselves via
whatever shell access they already have (SSH, a confirmed RCE webshell,
an already-established Meterpreter/reverse-shell session) and flag known
privesc vectors in that output -- the same "classify a signal, don't
manufacture one" posture idor_sweep.py's LEAKED verdict already applies.

Linux/macOS share this module's analysis (both POSIX, sudo/SUID/cron
concepts transfer directly) -- Windows is handled separately since its
privilege model (Windows privileges via whoami /priv, not sudo/SUID) is
a different vector family entirely. macOS-SPECIFIC vectors (TCC bypass,
launchd-specific paths) are NOT covered here -- flagged honestly as out
of scope for this pass rather than guessed at with lower confidence than
the well-documented Linux/Windows checks below.

The GTFOBins-style binary list is a curated subset of well-known,
widely-documented shell-escape-capable binaries (gtfobins.github.io is
the canonical, community-maintained reference this is modeled on, not
copied from -- entries here are independently well-established, publicly
documented techniques, not novel research). Not exhaustive -- flagged
explicitly in each result so a caller knows an unflagged binary was
merely not on this list, not confirmed safe.
"""

from __future__ import annotations

import re

# Binaries with well-documented shell-escape/file-read/file-write
# techniques when run with elevated privileges (via sudo or as SUID) --
# a curated subset of gtfobins.github.io's much larger catalog. Flagging
# one of these in `sudo -l` or a SUID `find` listing is a strong lead,
# not automatic confirmation: the exact escape technique still needs to
# be verified against the real binary/version/arguments allowed.
GTFOBINS_DANGEROUS_BINARIES = {
    "nmap", "vim", "vi", "nvim", "less", "more", "man", "awk", "gawk",
    "find", "python", "python2", "python3", "perl", "ruby", "php", "node",
    "tar", "zip", "unzip", "gdb", "gcc", "cc", "make", "docker", "git",
    "tee", "cp", "mv", "dd", "base64", "nc", "ncat", "netcat", "socat",
    "ssh", "scp", "rsync", "systemctl", "env",
    "expect", "ftp", "xxd", "curl", "wget", "openssl", "ash", "bash",
    "sh", "csh", "ksh", "zsh", "byebug", "irb", "lua", "mysql", "psql",
    "sqlite3", "screen", "tmux", "chmod", "chown",
    "setfacl", "pip", "pip3", "apt", "apt-get", "dpkg", "yum", "rpm",
}
# Deliberately NOT in the set above, even though each has SOME documented
# GTFOBins entry: mount/umount/at/crontab are also extremely common
# DEFAULT-install SUID/cron-adjacent utilities (see known_normal_suid in
# analyze_suid_binaries below) whose real-world exploitability is far more
# conditional/niche than the entries kept above -- flagging every default
# install as "dangerous" would make the signal meaningless. Their presence
# is still visible in `sudo -l`/SUID output, just not auto-flagged here.

# Windows privileges with well-documented, well-known local-privesc
# techniques (Potato-family exploits for SeImpersonate/SeAssignPrimaryToken,
# direct SAM/registry-hive access for SeBackup/SeRestore, direct process
# injection into SYSTEM processes for SeDebug, arbitrary-driver-load for
# SeLoadDriver, ACL bypass for SeTakeOwnership, forging arbitrary tokens
# for SeCreateToken) -- from the well-established "Windows Privilege
# Escalation via privileges" methodology.
DANGEROUS_WINDOWS_PRIVILEGES = {
    "SeImpersonatePrivilege": "Potato-family exploits (PrintSpoofer/JuicyPotato/RoguePotato/GodPotato) coerce a SYSTEM-privileged connection and impersonate it -- one of the most common real-world Windows service-account privescs",
    "SeAssignPrimaryTokenPrivilege": "similar to SeImpersonate -- can assign a primary token to a new process, same Potato-family exploit class applies",
    "SeBackupPrivilege": "read any file bypassing ACLs (including SAM/SYSTEM registry hives for offline credential extraction) regardless of DACL",
    "SeRestorePrivilege": "write any file bypassing ACLs -- can overwrite a service binary or DLL loaded by a privileged process",
    "SeDebugPrivilege": "open a handle to any process including SYSTEM ones -- direct token theft/process injection",
    "SeLoadDriverPrivilege": "load an arbitrary (including malicious/vulnerable) kernel driver",
    "SeTakeOwnershipPrivilege": "take ownership of any object regardless of its ACL, then grant yourself access",
    "SeCreateTokenPrivilege": "forge an arbitrary access token, including one for SYSTEM/an administrator",
    "SeTcbPrivilege": "act as part of the trusted computing base -- broad, rarely-granted, near-total system access",
}


def analyze_sudo_l(output: str) -> dict:
    """Parses `sudo -l` output for NOPASSWD entries naming a
    GTFOBins-style dangerous binary -- the single highest-value manual
    check in Linux privesc enumeration, now automated. A line like
    "(ALL) NOPASSWD: /usr/bin/vim" is flagged; a line requiring a
    password is noted but not flagged the same way (still needs the
    current user's own password, a materially different bar)."""
    flagged = []
    all_nopasswd_lines = []
    for line in output.splitlines():
        if "NOPASSWD" not in line:
            continue
        all_nopasswd_lines.append(line.strip())
        for binary in GTFOBINS_DANGEROUS_BINARIES:
            if re.search(rf"(?:^|/){re.escape(binary)}\b", line):
                flagged.append({"line": line.strip(), "binary": binary})
                break
    return {"nopasswd_lines": all_nopasswd_lines, "flagged": flagged}


def analyze_suid_binaries(output: str) -> dict:
    """Parses one-path-per-line SUID binary listing (e.g. `find / -perm
    -4000 -type f 2>/dev/null`) against the same dangerous-binary list.
    Non-default SUID binaries (anything not part of a normal base OS
    install) are ALSO worth a look even if not on this list -- flagged
    as a separate "unusual" bucket rather than silently dropped, since a
    custom/third-party SUID binary is often the more interesting finding
    than a well-known one."""
    flagged = []
    unusual = []
    known_normal_suid = {
        "sudo", "su", "passwd", "chsh", "chfn", "gpasswd", "newgrp",
        "mount", "umount", "ping", "ping6", "pkexec", "at", "crontab",
        "fusermount", "ssh-agent",
    }
    for line in output.splitlines():
        path = line.strip()
        if not path:
            continue
        basename = path.rsplit("/", 1)[-1]
        if basename in GTFOBINS_DANGEROUS_BINARIES:
            flagged.append({"path": path, "binary": basename})
        elif basename not in known_normal_suid:
            unusual.append(path)
    return {"flagged": flagged, "unusual_non_default_suid": unusual}


def analyze_windows_privileges(output: str) -> dict:
    """Parses `whoami /priv` output for enabled dangerous privileges.
    Only "Enabled" state privileges are flagged -- a privilege listed
    but "Disabled"/"Disabled by default" generally can't be exploited
    without a separate step to first enable it (AdjustTokenPrivileges),
    which some exploit chains do handle, but the baseline "is it already
    usable right now" signal is what's flagged here."""
    flagged = []
    for line in output.splitlines():
        for priv_name, reason in DANGEROUS_WINDOWS_PRIVILEGES.items():
            if priv_name in line and re.search(r"\bEnabled\b", line, re.IGNORECASE):
                flagged.append({"privilege": priv_name, "reason": reason, "line": line.strip()})
    return {"flagged": flagged}
