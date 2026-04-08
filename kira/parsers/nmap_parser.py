"""
kira/parsers/nmap_parser.py
============================
Parses nmap XML output (-oX) into structured Python dicts.

Feeds directly into:
  - StateManager.update(open_ports=..., services=..., os_guess=...)
  - KnowledgeBase via auto-generated Findings for notable NSE results
  - LLM planner context via get_context_summary()

Public API:
    from kira.parsers.nmap_parser import parse_nmap_xml, extract_state_fields

    result   = parse_nmap_xml("/sessions/scan/raw/nmap_20260406.xml")
    fields   = extract_state_fields(result)
    state.update(**fields)

Output shape of parse_nmap_xml():
    {
      "scan_info": { "type": "syn", "protocol": "tcp", "num_services": "1000" },
      "hosts": [
        {
          "ip":        "10.10.10.5",
          "hostname":  "target.local",
          "state":     "up",
          "os_guess":  "Linux 4.15",
          "os_accuracy": 95,
          "ports": [
            {
              "port":     80,
              "protocol": "tcp",
              "state":    "open",
              "reason":   "syn-ack",
              "service":  "http",
              "product":  "Apache httpd",
              "version":  "2.4.49",
              "extra":    "(Debian)",
              "full_version": "Apache httpd 2.4.49 (Debian)",
              "tunnel":   "",
              "scripts":  {
                "http-title":  "Apache2 Ubuntu Default Page",
                "http-server-headers": "Apache/2.4.49 (Debian)"
              }
            }
          ],
          "os_ports_used": [{ "proto": "tcp", "portid": "22" }]
        }
      ],
      "raw_xml_path": "/sessions/.../nmap_....xml"
    }
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional


# ── NSE scripts whose output is worth surfacing in findings ───────────────────

NOTABLE_SCRIPTS = {
    "http-title",
    "http-server-headers",
    "http-auth-finder",
    "http-methods",
    "http-robots.txt",
    "ssh-hostkey",
    "ssh-auth-methods",
    "ftp-anon",               # anonymous FTP — instant critical finding
    "ftp-bounce",
    "smb-security-mode",
    "smb2-security-mode",
    "smb-vuln-ms17-010",      # EternalBlue
    "smb-vuln-ms08-067",
    "ssl-cert",
    "ssl-dh-params",
    "mysql-info",
    "mysql-empty-password",   # unauthenticated MySQL — critical
    "ms-sql-info",
    "rdp-enum-encryption",
    "vnc-info",
}

# Ports → canonical service name used in state["services"] keys
PORT_SERVICE_HINTS = {
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    25:   "smtp",
    53:   "dns",
    80:   "http",
    110:  "pop3",
    111:  "rpcbind",
    135:  "msrpc",
    139:  "netbios-ssn",
    143:  "imap",
    443:  "https",
    445:  "microsoft-ds",
    993:  "imaps",
    995:  "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    27017:"mongodb",
}


# ── Main parser ────────────────────────────────────────────────────────────────

def parse_nmap_xml(xml_path: str) -> dict:
    """
    Parse an nmap XML file into a structured dict.

    Parameters
    ----------
    xml_path : path to the .xml file written by nmap -oX

    Returns
    -------
    dict  (see module docstring for full shape)

    Raises
    ------
    FileNotFoundError  if the XML file does not exist
    ValueError         if the file is not valid nmap XML
    """
    path = Path(xml_path)
    if not path.exists():
        raise FileNotFoundError(f"nmap XML not found: {xml_path}")

    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        raise ValueError(f"Failed to parse nmap XML at {xml_path}: {e}") from e

    root = tree.getroot()

    if root.tag != "nmaprun":
        raise ValueError(
            f"Not an nmap XML file — root tag is '{root.tag}', expected 'nmaprun'"
        )

    result = {
        "scan_info":    _parse_scan_info(root),
        "hosts":        [],
        "raw_xml_path": str(path.resolve()),
    }

    for host_elem in root.findall("host"):
        host = _parse_host(host_elem)
        if host:
            result["hosts"].append(host)

    return result


# ── State helper ───────────────────────────────────────────────────────────────

def extract_state_fields(parsed: dict) -> dict:
    """
    Flatten a parse_nmap_xml() result into the exact keyword arguments
    that StateManager.update() expects.

    Usage:
        state.update(**extract_state_fields(parse_nmap_xml(xml_path)))

    Returns dict with keys:
        open_ports  : sorted list of open port numbers  [22, 80, 443]
        services    : {"80": "Apache httpd 2.4.49", ...}
        os_guess    : "Linux 4.15" or None
        hostnames   : ["target.local"]
    """
    open_ports: list[int]  = []
    services:   dict       = {}
    os_guess:   Optional[str] = None
    hostnames:  list[str]  = []

    for host in parsed.get("hosts", []):
        if host.get("state") != "up":
            continue

        # Hostnames
        hn = host.get("hostname")
        if hn and hn not in hostnames:
            hostnames.append(hn)

        # OS guess — take highest-accuracy result across all hosts
        if host.get("os_guess") and (
            os_guess is None
            or host.get("os_accuracy", 0) > _current_os_accuracy(os_guess, parsed)
        ):
            os_guess = host["os_guess"]

        # Ports and services
        for port in host.get("ports", []):
            if port["state"] != "open":
                continue

            portnum = port["port"]
            if portnum not in open_ports:
                open_ports.append(portnum)

            # Build a human-readable version string for the services dict
            full_ver = port.get("full_version") or ""
            if not full_ver:
                parts = [p for p in [
                    port.get("product", ""),
                    port.get("version", ""),
                    port.get("extra",   ""),
                ] if p]
                full_ver = " ".join(parts).strip()

            if not full_ver:
                full_ver = port.get("service") or PORT_SERVICE_HINTS.get(portnum, "unknown")

            services[str(portnum)] = full_ver

    return {
        "open_ports": sorted(open_ports),
        "services":   services,
        "os_guess":   os_guess,
        "hostnames":  hostnames,
    }


def get_notable_script_findings(parsed: dict) -> list[dict]:
    """
    Scan all NSE script outputs for immediately actionable findings.
    Returns a list of partial Finding dicts (title, severity, port,
    service, description) ready to pass to KnowledgeBase.add().

    Handles: anonymous FTP, MySQL empty password, EternalBlue,
             HTTP auth required, weak SSH, exposed robots.txt.
    """
    findings = []

    for host in parsed.get("hosts", []):
        for port_info in host.get("ports", []):
            if port_info["state"] != "open":
                continue

            port    = port_info["port"]
            service = port_info.get("service", "")
            scripts = port_info.get("scripts", {})

            for script_id, output in scripts.items():
                finding = _script_to_finding(script_id, output, port, service)
                if finding:
                    findings.append(finding)

    return findings


def open_ports(parsed: dict) -> list[dict]:
    """
    Extract a flat list of all open ports across all hosts.
    Returns list of dicts with {ip, port, protocol, service, product, version}.
    """
    ports = []
    for host in parsed.get("hosts", []):
        for p in host.get("ports", []):
            if p["state"] == "open":
                ports.append({
                    "ip": host["ip"],
                    "port": p["port"],
                    "protocol": p["protocol"],
                    "service": p["service"],
                    "product": p["product"],
                    "version": p["version"],
                })
    return ports

    def services_by_name(self, name: str) -> list[dict]:
        """Find all instances of a service by name (e.g. 'http', 'ssh')."""
        return [p for p in self.open_ports() if p["service"] == name]

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def summary(self) -> str:
        """Compact summary string for LLM context injection (~200 tokens)."""
        lines = [f"Scan: {self.command}"]
        for host in self.hosts:
            lines.append(f"\nHost: {host.ip} ({host.hostname}) — {host.state}")
            if host.os_matches:
                top_os = host.os_matches[0]
                lines.append(f"  OS: {top_os['name']} ({top_os['accuracy']}% confidence)")
            open_svcs = [s for s in host.services if s.state == "open"]
            for svc in open_svcs:
                version_str = f"{svc.product} {svc.version}".strip()
                lines.append(
                    f"  {svc.port}/{svc.protocol}  {svc.name:<12}  {version_str}"
                )
                for script_id, output in svc.scripts.items():
                    if isinstance(output, dict):
                        raw = output.get("output", "")
                    else:
                        raw = output
                        short = str(raw).strip().replace("\n", " ")[:120]
                        lines.append(f"    [NSE:{script_id}] {short}")
        return "\n".join(lines)


# ── Internal: host parsing ─────────────────────────────────────────────────────

def _parse_host(host_elem: ET.Element) -> Optional[dict]:
    """Parse a single <host> element."""

    # Skip hosts that are down
    status = host_elem.find("status")
    state  = status.attrib.get("state", "unknown") if status is not None else "unknown"

    # IP address
    ip = None
    for addr in host_elem.findall("address"):
        if addr.attrib.get("addrtype") == "ipv4":
            ip = addr.attrib.get("addr")
            break
    if not ip:
        # Try IPv6
        for addr in host_elem.findall("address"):
            if addr.attrib.get("addrtype") == "ipv6":
                ip = addr.attrib.get("addr")
                break

    if not ip:
        return None

    # Hostname (first PTR or user record)
    hostname = _parse_hostname(host_elem)

    # OS detection
    os_guess, os_accuracy = _parse_os(host_elem)

    # Ports
    ports = _parse_ports(host_elem)

    # OS ports used (helps verify OS guess)
    os_ports_used = []
    os_elem = host_elem.find("os")
    if os_elem is not None:
        for pu in os_elem.findall("portused"):
            os_ports_used.append({
                "proto":  pu.attrib.get("proto", ""),
                "portid": pu.attrib.get("portid", ""),
                "state":  pu.attrib.get("state", ""),
            })

    # Uptime
    uptime = None
    uptime_elem = host_elem.find("uptime")
    if uptime_elem is not None:
        uptime = {
            "seconds":  uptime_elem.attrib.get("seconds"),
            "lastboot": uptime_elem.attrib.get("lastboot"),
        }

    return {
        "ip":           ip,
        "hostname":     hostname,
        "state":        state,
        "os_guess":     os_guess,
        "os_accuracy":  os_accuracy,
        "os_ports_used": os_ports_used,
        "ports":        ports,
        "uptime":       uptime,
    }


def _parse_hostname(host_elem: ET.Element) -> Optional[str]:
    """Extract the best available hostname."""
    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is None:
        return None

    # Prefer "PTR" (reverse DNS) over "user" entries
    ptr  = None
    user = None
    for hn in hostnames_elem.findall("hostname"):
        hn_type = hn.attrib.get("type", "")
        hn_name = hn.attrib.get("name", "").strip()
        if not hn_name:
            continue
        if hn_type == "PTR" and ptr is None:
            ptr = hn_name
        elif hn_type == "user" and user is None:
            user = hn_name

    return ptr or user


def _parse_os(host_elem: ET.Element) -> tuple[Optional[str], int]:
    """
    Return (os_name, accuracy_percent) for the highest-confidence OS match.
    Returns (None, 0) if no OS detection data is present.
    """
    os_elem = host_elem.find("os")
    if os_elem is None:
        return None, 0

    best_match   = None
    best_accuracy = 0

    for osmatch in os_elem.findall("osmatch"):
        accuracy = int(osmatch.attrib.get("accuracy", "0"))
        name     = osmatch.attrib.get("name", "").strip()
        if accuracy > best_accuracy and name:
            best_accuracy = accuracy
            best_match    = name

    return best_match, best_accuracy


def _parse_ports(host_elem: ET.Element) -> list[dict]:
    """Parse all <port> elements under <ports>."""
    ports_elem = host_elem.find("ports")
    if ports_elem is None:
        return []

    ports = []
    for port_elem in ports_elem.findall("port"):
        port = _parse_single_port(port_elem)
        if port:
            ports.append(port)

    return ports


def _parse_single_port(port_elem: ET.Element) -> Optional[dict]:
    """Parse a single <port> element including service and NSE scripts."""

    portnum   = int(port_elem.attrib.get("portid", 0))
    protocol  = port_elem.attrib.get("protocol", "tcp")

    # State
    state_elem = port_elem.find("state")
    if state_elem is None:
        return None
    state  = state_elem.attrib.get("state",  "unknown")
    reason = state_elem.attrib.get("reason", "")

    # Service fingerprint
    product  = ""
    version  = ""
    extra    = ""
    service  = PORT_SERVICE_HINTS.get(portnum, "")
    tunnel   = ""
    cpe_list = []

    svc_elem = port_elem.find("service")
    if svc_elem is not None:
        service  = svc_elem.attrib.get("name",    service)
        product  = svc_elem.attrib.get("product", "").strip()
        version  = svc_elem.attrib.get("version", "").strip()
        extra    = svc_elem.attrib.get("extrainfo","").strip()
        tunnel   = svc_elem.attrib.get("tunnel",  "")

        # CPE identifiers (e.g. cpe:/a:apache:http_server:2.4.49)
        for cpe_elem in svc_elem.findall("cpe"):
            cpe_text = (cpe_elem.text or "").strip()
            if cpe_text:
                cpe_list.append(cpe_text)

    # Build a clean, human-readable version string
    parts = [p for p in [product, version, extra] if p]
    full_version = " ".join(parts).strip()

    # NSE script results
    scripts = _parse_scripts(port_elem)

    return {
        "port":         portnum,
        "protocol":     protocol,
        "state":        state,
        "reason":       reason,
        "service":      service,
        "product":      product,
        "version":      version,
        "extra":        extra,
        "full_version": full_version,
        "tunnel":       tunnel,
        "cpe":          cpe_list,
        "scripts":      scripts,
    }


def _parse_scripts(parent_elem: ET.Element) -> dict:
    """
    Parse all <script> children of a port or host element.
    Returns {script_id: output_string} for NOTABLE_SCRIPTS,
    plus any script whose output contains useful keywords.
    """
    scripts = {}
    for script_elem in parent_elem.findall("script"):
        script_id = script_elem.attrib.get("id", "")
        output    = script_elem.attrib.get("output", "").strip()

        # Always capture notable scripts
        if script_id in NOTABLE_SCRIPTS:
            scripts[script_id] = _clean_script_output(output)
            continue

        # Also capture any script with interesting keywords in output
        lower = output.lower()
        if any(kw in lower for kw in (
            "vulnerable", "exploitable", "anonymous",
            "allowed", "enabled", "weak", "cve-",
        )):
            scripts[script_id] = _clean_script_output(output)

    return scripts


def _clean_script_output(raw: str) -> str:
    """Collapse excessive whitespace from NSE script output."""
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    return " | ".join(lines[:5])   # cap at 5 lines to avoid bloating state


# ── Internal: scan info ────────────────────────────────────────────────────────

def _parse_scan_info(root: ET.Element) -> dict:
    """Parse the <scaninfo> element."""
    si = root.find("scaninfo")
    if si is None:
        return {}
    return {
        "type":         si.attrib.get("type", ""),
        "protocol":     si.attrib.get("protocol", ""),
        "num_services": si.attrib.get("numservices", ""),
        "scanner_args": root.attrib.get("args", ""),
        "scan_start":   root.attrib.get("startstr", ""),
    }


# ── Internal: OS accuracy helper ──────────────────────────────────────────────

def _current_os_accuracy(current_guess: str, parsed: dict) -> int:
    """Find the accuracy of the currently stored os_guess."""
    for host in parsed.get("hosts", []):
        if host.get("os_guess") == current_guess:
            return host.get("os_accuracy", 0)
    return 0


# ── Internal: NSE → Finding mapper ────────────────────────────────────────────

def _script_to_finding(
    script_id: str,
    output:    str,
    port:      int,
    service:   str,
) -> Optional[dict]:
    """
    Map a known NSE script result to a partial Finding dict.
    Returns None if the script output doesn't indicate a vulnerability.
    """

    out_lower = output.lower()

    # ── Anonymous FTP ─────────────────────────────────────────────────────────
    if script_id == "ftp-anon" and "anonymous ftp login allowed" in out_lower:
        return {
            "title":             "Anonymous FTP Login Allowed",
            "severity":          "critical",
            "port":              port,
            "service":           "ftp",
            "cvss":              9.8,
            "cve":               "",
            "exploit_available": True,
            "description":       (
                f"FTP server on port {port} allows unauthenticated anonymous "
                f"login. Output: {output[:200]}"
            ),
            "remediation":       (
                "Disable anonymous FTP access. If required, restrict to "
                "read-only on a dedicated chroot directory."
            ),
        }

    # ── MySQL empty password ───────────────────────────────────────────────────
    if script_id == "mysql-empty-password" and (
        "root account has empty password" in out_lower
        or "login possible" in out_lower
    ):
        return {
            "title":             "MySQL Root Empty Password",
            "severity":          "critical",
            "port":              port,
            "service":           "mysql",
            "cvss":              9.8,
            "cve":               "",
            "exploit_available": True,
            "description":       (
                f"MySQL on port {port} accepts root login with no password. "
                f"Output: {output[:200]}"
            ),
            "remediation":       (
                "Set a strong root password immediately: "
                "ALTER USER 'root'@'localhost' IDENTIFIED BY '<strong_pass>';"
            ),
        }

    # ── EternalBlue ───────────────────────────────────────────────────────────
    if script_id == "smb-vuln-ms17-010" and "vulnerable" in out_lower:
        return {
            "title":             "MS17-010 EternalBlue (SMB RCE)",
            "severity":          "critical",
            "port":              port,
            "service":           "smb",
            "cvss":              9.3,
            "cve":               "CVE-2017-0144",
            "exploit_available": True,
            "description":       (
                "Host is vulnerable to EternalBlue — unauthenticated remote "
                f"code execution via SMB. Output: {output[:200]}"
            ),
            "remediation":       (
                "Apply MS17-010 patch immediately. Disable SMBv1: "
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false"
            ),
        }

    # ── MS08-067 ──────────────────────────────────────────────────────────────
    if script_id == "smb-vuln-ms08-067" and "vulnerable" in out_lower:
        return {
            "title":             "MS08-067 NetAPI Stack Overflow (RCE)",
            "severity":          "critical",
            "port":              port,
            "service":           "smb",
            "cvss":              10.0,
            "cve":               "CVE-2008-4250",
            "exploit_available": True,
            "description":       (
                "Host is vulnerable to MS08-067 — unauthenticated RCE via "
                f"NetAPI. Output: {output[:200]}"
            ),
            "remediation":       "Apply MS08-067 patch. Block SMB at network boundary.",
        }

    # ── SSH weak host key ─────────────────────────────────────────────────────
    if script_id == "ssh-auth-methods":
        if "password" in out_lower and "publickey" not in out_lower:
            return {
                "title":             "SSH Password Authentication Enabled",
                "severity":          "medium",
                "port":              port,
                "service":           "ssh",
                "cvss":              5.3,
                "cve":               "",
                "exploit_available": False,
                "description":       (
                    f"SSH on port {port} allows password authentication, "
                    "increasing brute-force risk."
                ),
                "remediation":       (
                    "Disable password auth in sshd_config: "
                    "PasswordAuthentication no"
                ),
            }

    # ── SSL/TLS weak DH params ────────────────────────────────────────────────
    if script_id == "ssl-dh-params" and (
        "logjam" in out_lower or "weak" in out_lower or "vulnerable" in out_lower
    ):
        return {
            "title":             "Weak SSL/TLS Diffie-Hellman Parameters (LOGJAM)",
            "severity":          "high",
            "port":              port,
            "service":           service,
            "cvss":              7.4,
            "cve":               "CVE-2015-4000",
            "exploit_available": False,
            "description":       (
                f"Port {port} uses weak DH parameters vulnerable to LOGJAM. "
                f"Output: {output[:200]}"
            ),
            "remediation":       (
                "Generate DH params ≥2048 bits: "
                "openssl dhparam -out dhparam.pem 2048"
            ),
        }

    # ── HTTP auth exposed ─────────────────────────────────────────────────────
    if script_id == "http-auth-finder" and "basic" in out_lower:
        return {
            "title":             "HTTP Basic Authentication Detected",
            "severity":          "medium",
            "port":              port,
            "service":           "http",
            "cvss":              5.4,
            "cve":               "",
            "exploit_available": False,
            "description":       (
                f"Port {port} uses HTTP Basic Auth — credentials transmitted "
                "base64-encoded without TLS are trivially decodable."
            ),
            "remediation":       "Migrate to HTTPS and use modern auth (OAuth2, JWT).",
        }

    return None


# ── Pretty printer (dev/debug) ─────────────────────────────────────────────────

def pretty_print(parsed: dict) -> None:
    """Print a human-readable summary of parse_nmap_xml() output."""
    try:
        from rich.console import Console
        from rich.table   import Table
        from rich         import box as rbox
        c = Console()
    except ImportError:
        _plain_print(parsed)
        return

    info = parsed.get("scan_info", {})
    c.print(f"\n[bold]Nmap scan[/bold]  {info.get('scanner_args','')}")
    c.print(f"Started: {info.get('scan_start','')}  |  "
            f"Services scanned: {info.get('num_services','?')}\n")

    for host in parsed.get("hosts", []):
        c.print(
            f"[bold green]{host['ip']}[/bold green]"
            + (f"  ({host['hostname']})" if host.get("hostname") else "")
            + f"  [{host['state']}]"
        )
        if host.get("os_guess"):
            c.print(
                f"  OS: [yellow]{host['os_guess']}[/yellow]"
                f"  (accuracy {host['os_accuracy']}%)"
            )

        open_ports_list = [p for p in host["ports"] if p["state"] == "open"]
        if not open_ports_list:
            c.print("  [dim]No open ports found[/dim]")
            continue

        tbl = Table(box=rbox.SIMPLE, show_header=True, header_style="bold dim")
        tbl.add_column("Port",    style="cyan",  no_wrap=True)
        tbl.add_column("State",   style="green", no_wrap=True)
        tbl.add_column("Service", no_wrap=True)
        tbl.add_column("Version")
        tbl.add_column("Scripts", overflow="fold")

        for p in open_ports_list:
            script_summary = "  ".join(
                f"[{sid}] {out[:60]}"
                for sid, out in list(p["scripts"].items())[:3]
            )
            tbl.add_row(
                f"{p['port']}/{p['protocol']}",
                p["state"],
                p["service"],
                p["full_version"] or "-",
                script_summary or "-",
            )
        c.print(tbl)

        findings = get_notable_script_findings({"hosts": [host]})
        if findings:
            c.print(f"  [bold red]Auto-findings ({len(findings)}):[/bold red]")
            for f in findings:
                sev_color = {
                    "critical": "red", "high": "orange3",
                    "medium": "yellow", "low": "blue", "info": "dim",
                }.get(f["severity"], "white")
                c.print(
                    f"  [{sev_color}][{f['severity'].upper()}][/{sev_color}]"
                    f" port {f['port']} — {f['title']}"
                )
        c.print()


def _plain_print(parsed: dict) -> None:
    """Fallback printer when rich is not installed."""
    for host in parsed.get("hosts", []):
        print(f"\nHost: {host['ip']}  hostname={host.get('hostname')}  "
              f"os={host.get('os_guess')}")
        for p in host["ports"]:
            if p["state"] == "open":
                print(f"  {p['port']}/{p['protocol']}  {p['service']}"
                      f"  {p['full_version']}")
                for sid, out in p["scripts"].items():
                    print(f"    [{sid}] {out[:80]}")


# ── Smoke test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import tempfile
    import textwrap

    print("=== nmap_parser.py smoke test ===\n")

    # ── Build a realistic synthetic nmap XML ──────────────────────────────────
    SAMPLE_XML = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE nmaprun>
    <nmaprun scanner="nmap" args="nmap -sV -sC --open 10.10.10.5"
             startstr="Sun Apr  6 12:00:00 2026" version="7.94">
      <scaninfo type="syn" protocol="tcp" numservices="1000"/>
      <host starttime="1234567890" endtime="1234567900">
        <status state="up" reason="echo-reply"/>
        <address addr="10.10.10.5" addrtype="ipv4"/>
        <hostnames>
          <hostname name="target.local" type="PTR"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="21">
            <state state="open" reason="syn-ack"/>
            <service name="ftp" product="vsftpd" version="2.3.4"/>
            <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/>
          </port>
          <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="7.2p2" extrainfo="Ubuntu 4ubuntu2.8">
              <cpe>cpe:/a:openbsd:openssh:7.2p2</cpe>
            </service>
            <script id="ssh-hostkey" output="2048 ab:cd:ef:12 (RSA)"/>
            <script id="ssh-auth-methods" output="Supported: password publickey"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache httpd" version="2.4.49" extrainfo="(Debian)">
              <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
            </service>
            <script id="http-title" output="Apache2 Ubuntu Default Page: It works"/>
            <script id="http-server-headers" output="Server: Apache/2.4.49 (Debian)"/>
          </port>
          <port protocol="tcp" portid="139">
            <state state="open" reason="syn-ack"/>
            <service name="netbios-ssn" product="Samba smbd" version="3.X - 4.X"/>
          </port>
          <port protocol="tcp" portid="445">
            <state state="open" reason="syn-ack"/>
            <service name="microsoft-ds" product="Samba smbd" version="4.7.6"/>
            <script id="smb-security-mode"
              output="account_used: guest | authentication_level: user | challenge_response: supported"/>
            <script id="smb-vuln-ms17-010"
              output="VULNERABLE: Risk factor: HIGH | CVE-2017-0144 | State: VULNERABLE"/>
          </port>
          <port protocol="tcp" portid="3306">
            <state state="open" reason="syn-ack"/>
            <service name="mysql" product="MySQL" version="5.7.34"/>
            <script id="mysql-empty-password" output="root account has empty password"/>
          </port>
          <port protocol="tcp" portid="8080">
            <state state="filtered" reason="no-response"/>
            <service name="http-proxy"/>
          </port>
        </ports>
        <os>
          <osmatch name="Linux 4.15" accuracy="95"/>
          <osmatch name="Linux 3.x"  accuracy="85"/>
          <portused state="open" proto="tcp" portid="22"/>
        </os>
        <uptime seconds="86400" lastboot="Sat Apr  5 12:00:00 2026"/>
      </host>
    </nmaprun>
    """)

    with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", delete=False) as f:
        f.write(SAMPLE_XML)
        xml_path = f.name

    # ── 1. Basic parse ─────────────────────────────────────────────────────────
    print("[1] parse_nmap_xml()")
    parsed = parse_nmap_xml(xml_path)
    assert len(parsed["hosts"]) == 1,           "Should find 1 host"
    host = parsed["hosts"][0]
    assert host["ip"] == "10.10.10.5",          "IP mismatch"
    assert host["hostname"] == "target.local",  "Hostname mismatch"
    assert host["os_guess"] == "Linux 4.15",    "OS guess mismatch"
    assert host["os_accuracy"] == 95,           "OS accuracy mismatch"
    print(f"    host: {host['ip']}  hostname: {host['hostname']}  os: {host['os_guess']}")

    # ── 2. Open ports ──────────────────────────────────────────────────────────
    print("\n[2] Open ports")
    parsed_open_ports = open_ports(parsed)
    port_nums  = [p["port"] for p in parsed_open_ports]
    assert 21  in port_nums, "FTP not detected"
    assert 22  in port_nums, "SSH not detected"
    assert 80  in port_nums, "HTTP not detected"
    assert 445 in port_nums, "SMB not detected"
    assert 3306 in port_nums,"MySQL not detected"
    assert 8080 not in port_nums, "Filtered port should not appear"
    print(f"    open ports: {sorted(port_nums)}")

    # ── 3. Service versions ────────────────────────────────────────────────────
    print("\n[3] Service version strings")
    port_map = {p["port"]: p for p in host["ports"]}
    assert port_map[80]["product"]  == "Apache httpd",       "Apache product mismatch"
    assert port_map[80]["version"]  == "2.4.49",             "Apache version mismatch"
    assert port_map[80]["full_version"] == "Apache httpd 2.4.49 (Debian)", "Full version mismatch"
    assert "cpe:/a:apache:http_server:2.4.49" in port_map[80]["cpe"], "CPE missing"
    print(f"    port 80: {port_map[80]['full_version']}")
    print(f"    port 22: {port_map[22]['full_version']}")
    print(f"    port 21: {port_map[21]['full_version']}")

    # ── 4. NSE scripts ─────────────────────────────────────────────────────────
    print("\n[4] NSE script capture")
    assert "ftp-anon"      in port_map[21]["scripts"],  "ftp-anon script missing"
    assert "http-title"    in port_map[80]["scripts"],  "http-title script missing"
    assert "smb-vuln-ms17-010" in port_map[445]["scripts"], "EternalBlue script missing"
    assert "mysql-empty-password" in port_map[3306]["scripts"], "MySQL script missing"
    print(f"    ftp-anon:          {port_map[21]['scripts']['ftp-anon']}")
    print(f"    http-title:        {port_map[80]['scripts']['http-title']}")
    print(f"    smb-vuln-ms17-010: {port_map[445]['scripts']['smb-vuln-ms17-010'][:60]}")

    # ── 5. extract_state_fields ────────────────────────────────────────────────
    print("\n[5] extract_state_fields()")
    fields = extract_state_fields(parsed)
    assert fields["open_ports"] == [21, 22, 80, 139, 445, 3306], \
        f"Port list mismatch: {fields['open_ports']}"
    assert fields["services"]["80"] == "Apache httpd 2.4.49 (Debian)", \
        f"Service string wrong: {fields['services']['80']}"
    assert fields["os_guess"] == "Linux 4.15", "OS guess missing from fields"
    assert "target.local" in fields["hostnames"], "Hostname missing from fields"
    print(f"    open_ports: {fields['open_ports']}")
    print(f"    services[80]: {fields['services']['80']}")
    print(f"    services[3306]: {fields['services']['3306']}")
    print(f"    os_guess: {fields['os_guess']}")

    # ── 6. Auto-findings from NSE ──────────────────────────────────────────────
    print("\n[6] get_notable_script_findings()")
    findings = get_notable_script_findings(parsed)
    titles   = [f["title"] for f in findings]
    print(f"    {len(findings)} findings generated:")
    for f in findings:
        print(f"    [{f['severity'].upper():8s}] port {f['port']:5} | {f['title']}")
    assert any("Anonymous FTP"   in t for t in titles), "FTP finding missing"
    assert any("EternalBlue"     in t for t in titles), "MS17-010 finding missing"
    assert any("MySQL Root"      in t for t in titles), "MySQL finding missing"

    # ── 7. Error cases ─────────────────────────────────────────────────────────
    print("\n[7] Error handling")
    try:
        parse_nmap_xml("/nonexistent/path.xml")
        assert False, "Should have raised FileNotFoundError"
    except FileNotFoundError as e:
        print(f"    FileNotFoundError: OK — {e}")

    with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", delete=False) as f:
        f.write("<notanmap><junk/></notanmap>")
        bad_path = f.name
    try:
        parse_nmap_xml(bad_path)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"    ValueError: OK — {e}")

    # ── 8. Pretty print ────────────────────────────────────────────────────────
    print("\n[8] pretty_print():")
    pretty_print(parsed)

    import os
    os.unlink(xml_path)
    os.unlink(bad_path)
    print("All tests passed.")