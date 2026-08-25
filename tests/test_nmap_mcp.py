import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "nmap_mcp_server", os.path.join(ROOT, "mcp-servers", "nmap-mcp", "server.py")
)
nmap_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nmap_server)


def test_parse_nmap_grepable_reports_service_not_version():
    # nmap -oG's port field is port/state/proto/owner/service/rpc_info/version.
    # This used to read the version field (group 7) as the service name.
    raw = "Host: 10.0.0.1 ()\tStatus: Up\tPorts: 21/open/tcp//ftp//vsFTPd 2.3.4/\n"
    hosts = nmap_server._parse_nmap_grepable(raw)
    assert len(hosts) == 1
    port = hosts[0]["ports"][0]
    assert port["port"] == 21
    assert port["service"] == "ftp"


def test_parse_nmap_grepable_defaults_to_unknown_service():
    raw = "Host: 10.0.0.1 ()\tPorts: 8080/open/tcp/////\n"
    hosts = nmap_server._parse_nmap_grepable(raw)
    assert hosts[0]["ports"][0]["service"] == "unknown"


def test_parse_nmap_grepable_multiple_ports():
    raw = "Host: 10.0.0.1 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.2/, 80/open/tcp//http//nginx 1.18/\n"
    hosts = nmap_server._parse_nmap_grepable(raw)
    ports = hosts[0]["ports"]
    assert [p["service"] for p in ports] == ["ssh", "http"]
