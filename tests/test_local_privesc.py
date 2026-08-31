import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "local_privesc", os.path.join(ROOT, "mcp-servers", "local-privesc-mcp", "local_privesc.py"),
)
local_privesc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(local_privesc)


# ---------------------------------------------------------------------------
# analyze_sudo_l
# ---------------------------------------------------------------------------

def test_analyze_sudo_l_flags_known_dangerous_binary():
    output = "User www-data may run the following commands:\n    (ALL) NOPASSWD: /usr/bin/vim"
    result = local_privesc.analyze_sudo_l(output)
    assert len(result["flagged"]) == 1
    assert result["flagged"][0]["binary"] == "vim"


def test_analyze_sudo_l_ignores_non_nopasswd_lines():
    output = "User alice may run the following commands:\n    (root) /usr/bin/systemctl restart nginx"
    result = local_privesc.analyze_sudo_l(output)
    assert result["nopasswd_lines"] == []
    assert result["flagged"] == []


def test_analyze_sudo_l_nopasswd_but_no_known_binary():
    output = "    (ALL) NOPASSWD: /opt/mycompany/internal-tool"
    result = local_privesc.analyze_sudo_l(output)
    assert len(result["nopasswd_lines"]) == 1
    assert result["flagged"] == []


def test_analyze_sudo_l_does_not_false_positive_on_substring():
    # "find" must not match inside an unrelated word like "findcustomtool"
    output = "    (ALL) NOPASSWD: /opt/findcustomtool"
    result = local_privesc.analyze_sudo_l(output)
    assert result["flagged"] == []


def test_analyze_sudo_l_multiple_entries_mixed():
    output = (
        "    (ALL) NOPASSWD: /usr/bin/vim\n"
        "    (ALL) NOPASSWD: /opt/mycompany/internal-tool\n"
        "    (ALL) NOPASSWD: /usr/bin/docker\n"
    )
    result = local_privesc.analyze_sudo_l(output)
    assert len(result["nopasswd_lines"]) == 3
    assert len(result["flagged"]) == 2
    flagged_binaries = {f["binary"] for f in result["flagged"]}
    assert flagged_binaries == {"vim", "docker"}


# ---------------------------------------------------------------------------
# analyze_suid_binaries
# ---------------------------------------------------------------------------

def test_analyze_suid_binaries_flags_known_dangerous():
    output = "/usr/bin/find\n/usr/bin/passwd\n"
    result = local_privesc.analyze_suid_binaries(output)
    assert len(result["flagged"]) == 1
    assert result["flagged"][0]["binary"] == "find"


def test_analyze_suid_binaries_known_normal_suid_not_flagged_either_way():
    output = "/usr/bin/passwd\n/usr/bin/sudo\n/bin/mount\n"
    result = local_privesc.analyze_suid_binaries(output)
    assert result["flagged"] == []
    assert result["unusual_non_default_suid"] == []


def test_analyze_suid_binaries_flags_unusual_third_party_binary():
    output = "/opt/vendor/custom-suid-tool\n"
    result = local_privesc.analyze_suid_binaries(output)
    assert result["flagged"] == []
    assert result["unusual_non_default_suid"] == ["/opt/vendor/custom-suid-tool"]


def test_analyze_suid_binaries_ignores_blank_lines():
    output = "/usr/bin/passwd\n\n\n/bin/mount\n"
    result = local_privesc.analyze_suid_binaries(output)
    assert result["flagged"] == []
    assert result["unusual_non_default_suid"] == []


def test_analyze_suid_binaries_empty_output():
    result = local_privesc.analyze_suid_binaries("")
    assert result["flagged"] == []
    assert result["unusual_non_default_suid"] == []


# ---------------------------------------------------------------------------
# analyze_windows_privileges
# ---------------------------------------------------------------------------

def test_analyze_windows_privileges_flags_enabled_seimpersonate():
    output = (
        "PRIVILEGES INFORMATION\n"
        "----------------------\n\n"
        "Privilege Name               Description                    State\n"
        "============================= ============================== ========\n"
        "SeImpersonatePrivilege       Impersonate a client...        Enabled\n"
    )
    result = local_privesc.analyze_windows_privileges(output)
    assert len(result["flagged"]) == 1
    assert result["flagged"][0]["privilege"] == "SeImpersonatePrivilege"


def test_analyze_windows_privileges_does_not_flag_disabled():
    output = "SeImpersonatePrivilege       Impersonate a client...        Disabled\n"
    result = local_privesc.analyze_windows_privileges(output)
    assert result["flagged"] == []


def test_analyze_windows_privileges_flags_multiple():
    output = (
        "SeImpersonatePrivilege       Impersonate a client...        Enabled\n"
        "SeDebugPrivilege              Debug programs                 Enabled\n"
        "SeChangeNotifyPrivilege       Bypass traverse checking        Enabled\n"
    )
    result = local_privesc.analyze_windows_privileges(output)
    flagged_privs = {f["privilege"] for f in result["flagged"]}
    assert flagged_privs == {"SeImpersonatePrivilege", "SeDebugPrivilege"}


def test_analyze_windows_privileges_no_dangerous_privileges():
    output = "SeChangeNotifyPrivilege       Bypass traverse checking        Enabled\n"
    result = local_privesc.analyze_windows_privileges(output)
    assert result["flagged"] == []


def test_analyze_windows_privileges_empty_output():
    result = local_privesc.analyze_windows_privileges("")
    assert result["flagged"] == []
