"""
kira/parsers/nmap_parser.py
============================
Parses nmap XML output (-oX) into structured Python dicts.

Feeds directly into:
  - StateManager.update(open_ports=..., services=..., os_guess=...)
  - KnowledgeBase via auto-generated Findings for notable NSE results
  - LLM planner context via NmapResult.summary() or get_context_summary()

──────────────────────────────────────────────────────────────
PUBLIC API — dict-based (KIRA pipeline, backward-compatible)
──────────────────────────────────────────────────────────────
    from kira.parsers.nmap_parser import parse_nmap_xml, extract_state_fields

    result  = parse_nmap_xml("/sessions/scan/raw/nmap_20260406.xml")
    fields  = extract_state_fields(result)
    state.update(**fields)

    findings = get_notable_script_findings(result)
    ports    = open_ports(result)

──────────────────────────────────────────────────────────────
PUBLIC API — typed OOP wrapper (standalone / LLM injection)
──────────────────────────────────────────────────────────────
    from kira.parsers.nmap_parser import NmapParser

    parser  = NmapParser("output.xml")
    result  = parser.parse()          # returns NmapResult dataclass
    print(result.summary())           # compact ~200-token LLM context string
    print(result.to_json())           # full JSON dump

Output shape of parse_nmap_xml():
    {
      "scan_info": { "type": "syn", "protocol": "tcp", "num_services": "1000",
                     "scanner_args": "nmap -sV -sC ...", "scan_start": "..." },
      "hosts": [
        {
          "ip":           "10.10.10.5",
          "hostname":     "target.local",
          "state":        "up",
          "os_guess":     "Linux 4.15",
          "os_accuracy":  95,
          "os_ports_used": [{ "proto": "tcp", "portid": "22", "state": "open" }],
          "uptime":       { "seconds": "86400", "lastboot": "..." },
          "traceroute":   ["192.168.1.1", "10.0.0.1"],
          "ports": [
            {
              "port":         80,
              "protocol":     "tcp",
              "state":        "open",
              "reason":       "syn-ack",
              "service":      "http",
              "product":      "Apache httpd",
              "version":      "2.4.49",
              "extra":        "(Debian)",
              "full_version": "Apache httpd 2.4.49 (Debian)",
              "tunnel":       "",
              "cpe":          ["cpe:/a:apache:http_server:2.4.49"],
              "scripts": {
                "http-title":  "Apache2 Ubuntu Default Page",
                "http-server-headers": "Apache/2.4.49 (Debian)"
              },
              "scripts_structured": {
                "some-script": [{"key": "value"}]
              }
            }
          ]
        }
      ],
      "raw_xml_path": "/sessions/.../nmap_....xml"
    }
"""

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
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
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    53:    "dns",
    80:    "http",
    110:   "pop3",
    111:   "rpcbind",
    135:   "msrpc",
    139:   "netbios-ssn",
    143:   "imap",
    443:   "https",
    445:   "microsoft-ds",
    993:   "imaps",
    995:   "pop3s",
    1433:  "ms-sql-s",
    1521:  "oracle",
    2049:  "nfs",
    3306:  "mysql",
    3389:  "ms-wbt-server",
    5432:  "postgresql",
    5900:  "vnc",
    6379:  "redis",
    8080:  "http-proxy",
    8443:  "https-alt",
    9200:  "elasticsearch",
    27017: "mongodb",
}


# ══════════════════════════════════════════════════════════════════════════════
# TYPED DATACLASS LAYER  (used by NmapParser — does not affect dict-based API)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Service:
    port:         int
    protocol:     str           # tcp / udp
    state:        str           # open / closed / filtered
    name:         str           # e.g. "http", "ssh", "smb"
    product:      str           # e.g. "Apache httpd"
    version:      str           # e.g. "2.4.51"
    extra_info:   str           # extra banner info
    tunnel:       str           # e.g. "ssl"
    reason:       str           # e.g. "syn-ack"
    full_version: str           # product + version + extra joined
    cpe:          list[str]     = field(default_factory=list)
    scripts:      dict          = field(default_factory=dict)   # id → cleaned str
    scripts_structured: dict    = field(default_factory=dict)   # id → parsed tables


@dataclass
class Host:
    ip:           str
    hostname:     str
    state:        str           # up / down
    os_matches:   list[dict]    = field(default_factory=list)   # [{name, accuracy}]
    services:     list[Service] = field(default_factory=list)
    traceroute:   list[str]     = field(default_factory=list)
    os_ports_used: list[dict]   = field(default_factory=list)
    uptime:       Optional[dict] = None                         # {seconds, lastboot}


@dataclass
class NmapResult:
    command:    str
    scan_start: str
    scan_end:   str
    hosts:      list[Host] = field(default_factory=list)

    # ── Convenience accessors ─────────────────────────────────────────────────

    def open_ports(self) -> list[dict]:
        """Flat list of all open ports across all hosts."""
        ports = []
        for host in self.hosts:
            for svc in host.services:
                if svc.state == "open":
                    ports.append({
                        "ip":       host.ip,
                        "port":     svc.port,
                        "protocol": svc.protocol,
                        "service":  svc.name,
                        "product":  svc.product,
                        "version":  svc.version,
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
            for svc in (s for s in host.services if s.state == "open"):
                lines.append(
                    f"  {svc.port}/{svc.protocol}  {svc.name:<12}  {svc.full_version}"
                )
                for script_id, output in svc.scripts.items():
                    # output is already a cleaned string at this point
                    short = str(output).strip().replace("\n", " ")[:120]
                    lines.append(f"    [NSE:{script_id}] {short}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# OOP PARSER  (wraps the dict-based parser into typed dataclasses)
# ══════════════════════════════════════════════════════════════════════════════

class NmapParser:
    """
    Typed OOP wrapper around parse_nmap_xml().

    Usage:
        parser = NmapParser("output.xml")
        result = parser.parse()   # returns NmapResult
    """

    def __init__(self, xml_path: str):
        self.xml_path = xml_path

    def parse(self) -> NmapResult:
        raw = parse_nmap_xml(self.xml_path)
        info = raw.get("scan_info", {})
        result = NmapResult(
            command=info.get("scanner_args", ""),
            scan_start=info.get("scan_start", ""),
            scan_end=self._get_scan_end(),
        )
        for h in raw.get("hosts", []):
            host = Host(
                ip=h["ip"],
                hostname=h.get("hostname") or "",
                state=h["state"],
                os_matches=[
                    {"name": h["os_guess"], "accuracy": h["os_accuracy"]}
                ] if h.get("os_guess") else [],
                traceroute=h.get("traceroute", []),
                os_ports_used=h.get("os_ports_used", []),
                uptime=h.get("uptime"),
            )
            for p in h.get("ports", []):
                svc = Service(
                    port=p["port"],
                    protocol=p["protocol"],
                    state=p["state"],
                    name=p["service"],
                    product=p["product"],
                    version=p["version"],
                    extra_info=p["extra"],
                    tunnel=p["tunnel"],
                    reason=p["reason"],
                    full_version=p["full_version"],
                    cpe=p["cpe"],
                    scripts=p["scripts"],
                    scripts_structured=p.get("scripts_structured", {}),
                )
                host.services.append(svc)
            result.hosts.append(host)
        return result

    def _get_scan_end(self) -> str:
        try:
            tree = ET.parse(self.xml_path)
            runstats = tree.getroot().find("runstats/finished")
            if runstats is not None:
                return runstats.attrib.get("timestr", "")
        except Exception:
            pass
        return ""


# ══════════════════════════════════════════════════════════════════════════════
# DICT-BASED API  (primary KIRA pipeline interface — backward-compatible)
# ══════════════════════════════════════════════════════════════════════════════

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


def extract_state_fields(parsed: dict) -> dict:
    """
    Flatten a parse_nmap_xml() result into the exact keyword arguments
    that StateManager.update() expects.

    Usage:
        state.update(**extract_state_fields(parse_nmap_xml(xml_path)))

    Returns dict with keys:
        open_ports  : sorted list of open port numbers  [22, 80, 443]
        services    : {"80": "Apache httpd 2.4.49 (Debian)", ...}
        os_guess    : "Linux 4.15" or None
        hostnames   : ["target.local"]
    """
    open_port_nums: list[int]     = []
    services:       dict          = {}
    os_guess:       Optional[str] = None
    os_accuracy:    int           = 0
    hostnames:      list[str]     = []

    for host in parsed.get("hosts", []):
        if host.get("state") != "up":
            continue

        hn = host.get("hostname")
        if hn and hn not in hostnames:
            hostnames.append(hn)

        # Track highest-accuracy OS guess across all hosts
        if host.get("os_guess") and host.get("os_accuracy", 0) > os_accuracy:
            os_guess   = host["os_guess"]
            os_accuracy = host["os_accuracy"]

        for port in host.get("ports", []):
            if port["state"] != "open":
                continue

            portnum = port["port"]
            if portnum not in open_port_nums:
                open_port_nums.append(portnum)

            full_ver = port.get("full_version", "").strip()
            if not full_ver:
                full_ver = port.get("service") or PORT_SERVICE_HINTS.get(portnum, "unknown")

            services[str(portnum)] = full_ver

    return {
        "open_ports": sorted(open_port_nums),
        "services":   services,
        "os_guess":   os_guess,
        "hostnames":  hostnames,
    }


def get_notable_script_findings(parsed: dict) -> list[dict]:
    """
    Scan all NSE script outputs for immediately actionable findings.
    Returns a list of partial Finding dicts (title, severity, port,
    service, cvss, cve, exploit_available, description, remediation)
    ready to pass to KnowledgeBase.add().
    """
    findings = []
    for host in parsed.get("hosts", []):
        for port_info in host.get("ports", []):
            if port_info["state"] != "open":
                continue
            port    = port_info["port"]
            service = port_info.get("service", "")
            for script_id, output in port_info.get("scripts", {}).items():
                finding = _script_to_finding(script_id, output, port, service)
                if finding:
                    findings.append(finding)
    return findings


def open_ports(parsed: dict) -> list[dict]:
    """
    Extract a flat list of all open ports across all hosts.
    Returns list of dicts: {ip, port, protocol, service, product, version}.
    """
    ports = []
    for host in parsed.get("hosts", []):
        for p in host.get("ports", []):
            if p["state"] == "open":
                ports.append({
                    "ip":       host["ip"],
                    "port":     p["port"],
                    "protocol": p["protocol"],
                    "service":  p["service"],
                    "product":  p["product"],
                    "version":  p["version"],
                })
    return ports


# ══════════════════════════════════════════════════════════════════════════════
# INTERNAL PARSERS
# ══════════════════════════════════════════════════════════════════════════════

def _parse_scan_info(root: ET.Element) -> dict:
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


def _parse_host(host_elem: ET.Element) -> Optional[dict]:
    """Parse a single <host> element into a dict."""
    status = host_elem.find("status")
    state  = status.attrib.get("state", "unknown") if status is not None else "unknown"

    # IP address — prefer IPv4, fall back to IPv6
    ip = None
    for addrtype in ("ipv4", "ipv6"):
        for addr in host_elem.findall("address"):
            if addr.attrib.get("addrtype") == addrtype:
                ip = addr.attrib.get("addr")
                break
        if ip:
            break

    if not ip:
        return None

    hostname      = _parse_hostname(host_elem)
    os_guess, os_accuracy = _parse_os(host_elem)
    ports         = _parse_ports(host_elem)
    traceroute    = _parse_traceroute(host_elem)

    # OS ports used
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
        "ip":            ip,
        "hostname":      hostname,
        "state":         state,
        "os_guess":      os_guess,
        "os_accuracy":   os_accuracy,
        "os_ports_used": os_ports_used,
        "uptime":        uptime,
        "traceroute":    traceroute,
        "ports":         ports,
    }


def _parse_hostname(host_elem: ET.Element) -> Optional[str]:
    """Extract the best hostname — PTR preferred over user entries."""
    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is None:
        return None
    ptr = user = None
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
    """Return (os_name, accuracy_percent) for the highest-confidence OS match."""
    os_elem = host_elem.find("os")
    if os_elem is None:
        return None, 0
    best_name, best_acc = None, 0
    for osmatch in os_elem.findall("osmatch"):
        acc  = int(osmatch.attrib.get("accuracy", "0"))
        name = osmatch.attrib.get("name", "").strip()
        if acc > best_acc and name:
            best_acc  = acc
            best_name = name
    return best_name, best_acc


def _parse_traceroute(host_elem: ET.Element) -> list[str]:
    """Extract ordered hop IPs from <trace> if present."""
    trace_elem = host_elem.find("trace")
    if trace_elem is None:
        return []
    hops = []
    for hop in trace_elem.findall("hop"):
        hop_ip = hop.attrib.get("ipaddr", "")
        if hop_ip:
            hops.append(hop_ip)
    return hops


def _parse_ports(host_elem: ET.Element) -> list[dict]:
    ports_elem = host_elem.find("ports")
    if ports_elem is None:
        return []
    return [
        p for p in (
            _parse_single_port(pe) for pe in ports_elem.findall("port")
        ) if p is not None
    ]


def _parse_single_port(port_elem: ET.Element) -> Optional[dict]:
    """Parse a single <port> element including service fingerprint and NSE scripts."""
    portnum  = int(port_elem.attrib.get("portid", 0))
    protocol = port_elem.attrib.get("protocol", "tcp")

    state_elem = port_elem.find("state")
    if state_elem is None:
        return None
    state  = state_elem.attrib.get("state",  "unknown")
    reason = state_elem.attrib.get("reason", "")

    product = version = extra = tunnel = ""
    service  = PORT_SERVICE_HINTS.get(portnum, "")
    cpe_list = []

    svc_elem = port_elem.find("service")
    if svc_elem is not None:
        service = svc_elem.attrib.get("name",     service)
        product = svc_elem.attrib.get("product",  "").strip()
        version = svc_elem.attrib.get("version",  "").strip()
        extra   = svc_elem.attrib.get("extrainfo","").strip()
        tunnel  = svc_elem.attrib.get("tunnel",   "")
        cpe_list = [
            c.text.strip() for c in svc_elem.findall("cpe") if c.text
        ]

    full_version = " ".join(p for p in [product, version, extra] if p).strip()

    scripts, scripts_structured = _parse_scripts(port_elem)

    return {
        "port":               portnum,
        "protocol":           protocol,
        "state":              state,
        "reason":             reason,
        "service":            service,
        "product":            product,
        "version":            version,
        "extra":              extra,
        "full_version":       full_version,
        "tunnel":             tunnel,
        "cpe":                cpe_list,
        "scripts":            scripts,
        "scripts_structured": scripts_structured,
    }


def _parse_scripts(parent_elem: ET.Element) -> tuple[dict, dict]:
    """
    Parse all <script> children.

    Returns
    -------
    scripts            : {script_id: cleaned_output_string}
                         Captured for NOTABLE_SCRIPTS or if output contains
                         actionable keywords.
    scripts_structured : {script_id: parsed_table_list}
                         Only populated when <table> sub-elements are present.
    """
    scripts: dict    = {}
    structured: dict = {}

    for script_elem in parent_elem.findall("script"):
        script_id = script_elem.attrib.get("id", "")
        raw_out   = script_elem.attrib.get("output", "").strip()

        # Determine if this script is worth capturing
        is_notable = script_id in NOTABLE_SCRIPTS
        is_interesting = not is_notable and any(
            kw in raw_out.lower() for kw in (
                "vulnerable", "exploitable", "anonymous",
                "allowed", "enabled", "weak", "cve-",
            )
        )

        if not (is_notable or is_interesting):
            continue

        scripts[script_id] = _clean_script_output(raw_out)

        # Also capture recursive structured table output when present
        tables = script_elem.findall("table")
        if tables:
            structured[script_id] = _parse_script_tables(tables)

    return scripts, structured


def _parse_script_tables(tables: list[ET.Element]) -> list[dict]:
    """Recursively parse NSE <table> elements into Python dicts."""
    result = []
    for table in tables:
        entry: dict = {}
        for elem in table.findall("elem"):
            key   = elem.attrib.get("key", "")
            value = elem.text or ""
            if key:
                entry[key] = value
            else:
                entry.setdefault("_values", []).append(value)
        nested = _parse_script_tables(table.findall("table"))
        if nested:
            entry["_tables"] = nested
        if entry:
            result.append(entry)
    return result


def _clean_script_output(raw: str) -> str:
    """Collapse whitespace from NSE output; cap at 5 lines to avoid bloating state."""
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    return " | ".join(lines[:5])


# ══════════════════════════════════════════════════════════════════════════════
# NSE → FINDING MAPPER
# ══════════════════════════════════════════════════════════════════════════════

def _script_to_finding(
    script_id: str,
    output:    str,
    port:      int,
    service:   str,
) -> Optional[dict]:
    """
    Map a known NSE script result to a partial Finding dict.
    Returns None if the output doesn't indicate a vulnerability.
    """
    out_lower = output.lower()

    if script_id == "ftp-anon" and "anonymous ftp login allowed" in out_lower:
        return {
            "title":             "Anonymous FTP Login Allowed",
            "severity":          "critical",
            "port":              port,
            "service":           "ftp",
            "cvss":              9.8,
            "cve":               "",
            "exploit_available": True,
            "description": (
                f"FTP server on port {port} allows unauthenticated anonymous "
                f"login. Output: {output[:200]}"
            ),
            "remediation": (
                "Disable anonymous FTP access. If required, restrict to "
                "read-only on a dedicated chroot directory."
            ),
        }

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
            "description": (
                f"MySQL on port {port} accepts root login with no password. "
                f"Output: {output[:200]}"
            ),
            "remediation": (
                "Set a strong root password immediately: "
                "ALTER USER 'root'@'localhost' IDENTIFIED BY '<strong_pass>';"
            ),
        }

    if script_id == "smb-vuln-ms17-010" and "vulnerable" in out_lower:
        return {
            "title":             "MS17-010 EternalBlue (SMB RCE)",
            "severity":          "critical",
            "port":              port,
            "service":           "smb",
            "cvss":              9.3,
            "cve":               "CVE-2017-0144",
            "exploit_available": True,
            "description": (
                "Host is vulnerable to EternalBlue — unauthenticated remote "
                f"code execution via SMB. Output: {output[:200]}"
            ),
            "remediation": (
                "Apply MS17-010 patch immediately. Disable SMBv1: "
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false"
            ),
        }

    if script_id == "smb-vuln-ms08-067" and "vulnerable" in out_lower:
        return {
            "title":             "MS08-067 NetAPI Stack Overflow (RCE)",
            "severity":          "critical",
            "port":              port,
            "service":           "smb",
            "cvss":              10.0,
            "cve":               "CVE-2008-4250",
            "exploit_available": True,
            "description": (
                "Host is vulnerable to MS08-067 — unauthenticated RCE via "
                f"NetAPI. Output: {output[:200]}"
            ),
            "remediation": "Apply MS08-067 patch. Block SMB at network boundary.",
        }

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
                "description": (
                    f"SSH on port {port} allows password authentication, "
                    "increasing brute-force risk."
                ),
                "remediation": (
                    "Disable password auth in sshd_config: "
                    "PasswordAuthentication no"
                ),
            }

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
            "description": (
                f"Port {port} uses weak DH parameters vulnerable to LOGJAM. "
                f"Output: {output[:200]}"
            ),
            "remediation": (
                "Generate DH params ≥2048 bits: "
                "openssl dhparam -out dhparam.pem 2048"
            ),
        }

    if script_id == "http-auth-finder" and "basic" in out_lower:
        return {
            "title":             "HTTP Basic Authentication Detected",
            "severity":          "medium",
            "port":              port,
            "service":           "http",
            "cvss":              5.4,
            "cve":               "",
            "exploit_available": False,
            "description": (
                f"Port {port} uses HTTP Basic Auth — credentials transmitted "
                "base64-encoded without TLS are trivially decodable."
            ),
            "remediation": "Migrate to HTTPS and use modern auth (OAuth2, JWT).",
        }

    return None


# ══════════════════════════════════════════════════════════════════════════════
# PRETTY PRINTER  (dev / debug)
# ══════════════════════════════════════════════════════════════════════════════

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
    c.print(f"\n[bold]Nmap scan[/bold]  {info.get('scanner_args', '')}")
    c.print(
        f"Started: {info.get('scan_start', '')}  |  "
        f"Services scanned: {info.get('num_services', '?')}\n"
    )

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

        open_list = [p for p in host["ports"] if p["state"] == "open"]
        if not open_list:
            c.print("  [dim]No open ports found[/dim]")
            continue

        tbl = Table(box=rbox.SIMPLE, show_header=True, header_style="bold dim")
        tbl.add_column("Port",    style="cyan",  no_wrap=True)
        tbl.add_column("State",   style="green", no_wrap=True)
        tbl.add_column("Service", no_wrap=True)
        tbl.add_column("Version")
        tbl.add_column("Scripts", overflow="fold")

        for p in open_list:
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
        print(
            f"\nHost: {host['ip']}  hostname={host.get('hostname')}  "
            f"os={host.get('os_guess')}"
        )
        for p in host["ports"]:
            if p["state"] == "open":
                print(f"  {p['port']}/{p['protocol']}  {p['service']}  {p['full_version']}")
                for sid, out in p["scripts"].items():
                    print(f"    [{sid}] {out[:80]}")


# ══════════════════════════════════════════════════════════════════════════════
# SMOKE TEST
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os
    import sys
    import tempfile
    import textwrap

    print("=== nmap_parser.py smoke test ===\n")

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
        <trace>
          <hop ipaddr="192.168.1.1"/>
          <hop ipaddr="10.0.0.1"/>
        </trace>
      </host>
      <runstats>
        <finished timestr="Sun Apr  6 12:05:00 2026"/>
      </runstats>
    </nmaprun>
    """)

    with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", delete=False) as f:
        f.write(SAMPLE_XML)
        xml_path = f.name

    # ── 1. Basic parse ────────────────────────────────────────────────────────
    print("[1] parse_nmap_xml()")
    parsed = parse_nmap_xml(xml_path)
    host   = parsed["hosts"][0]
    assert host["ip"]       == "10.10.10.5",   "IP mismatch"
    assert host["hostname"] == "target.local",  "Hostname mismatch"
    assert host["os_guess"] == "Linux 4.15",    "OS mismatch"
    assert host["os_accuracy"] == 95,           "OS accuracy mismatch"
    print(f"    host: {host['ip']}  os: {host['os_guess']}  uptime: {host['uptime']}")

    # ── 2. Traceroute ─────────────────────────────────────────────────────────
    print("\n[2] Traceroute")
    assert host["traceroute"] == ["192.168.1.1", "10.0.0.1"], "Traceroute mismatch"
    print(f"    hops: {host['traceroute']}")

    # ── 3. Open ports (dict API) ──────────────────────────────────────────────
    print("\n[3] open_ports()")
    op = open_ports(parsed)
    port_nums = [p["port"] for p in op]
    assert sorted(port_nums) == [21, 22, 80, 139, 445, 3306], f"Port list wrong: {port_nums}"
    assert 8080 not in port_nums, "Filtered port should not appear"
    print(f"    open: {sorted(port_nums)}")

    # ── 4. Full version strings ───────────────────────────────────────────────
    print("\n[4] full_version strings")
    port_map = {p["port"]: p for p in host["ports"]}
    assert port_map[80]["full_version"] == "Apache httpd 2.4.49 (Debian)"
    assert port_map[22]["full_version"] == "OpenSSH 7.2p2 Ubuntu 4ubuntu2.8"
    assert "cpe:/a:apache:http_server:2.4.49" in port_map[80]["cpe"]
    print(f"    port 80: {port_map[80]['full_version']}")
    print(f"    port 22: {port_map[22]['full_version']}")

    # ── 5. NSE scripts ────────────────────────────────────────────────────────
    print("\n[5] NSE scripts")
    assert "ftp-anon"          in port_map[21]["scripts"]
    assert "smb-vuln-ms17-010" in port_map[445]["scripts"]
    assert "mysql-empty-password" in port_map[3306]["scripts"]
    print(f"    ftp-anon:          {port_map[21]['scripts']['ftp-anon']}")
    print(f"    smb-vuln-ms17-010: {port_map[445]['scripts']['smb-vuln-ms17-010'][:60]}")

    # ── 6. extract_state_fields ───────────────────────────────────────────────
    print("\n[6] extract_state_fields()")
    fields = extract_state_fields(parsed)
    assert fields["open_ports"] == [21, 22, 80, 139, 445, 3306]
    assert fields["services"]["80"] == "Apache httpd 2.4.49 (Debian)"
    assert fields["os_guess"] == "Linux 4.15"
    assert "target.local" in fields["hostnames"]
    print(f"    open_ports: {fields['open_ports']}")
    print(f"    services[80]: {fields['services']['80']}")

    # ── 7. Auto-findings ──────────────────────────────────────────────────────
    print("\n[7] get_notable_script_findings()")
    findings = get_notable_script_findings(parsed)
    titles   = [f["title"] for f in findings]
    for f in findings:
        print(f"    [{f['severity'].upper():8s}] port {f['port']:5} | {f['title']}")
    assert any("Anonymous FTP" in t for t in titles)
    assert any("EternalBlue"   in t for t in titles)
    assert any("MySQL Root"    in t for t in titles)

    # ── 8. OOP NmapParser wrapper ─────────────────────────────────────────────
    print("\n[8] NmapParser (OOP layer)")
    result = NmapParser(xml_path).parse()
    assert result.command    == "nmap -sV -sC --open 10.10.10.5"
    assert result.scan_end   == "Sun Apr  6 12:05:00 2026"
    assert len(result.hosts) == 1
    h = result.hosts[0]
    assert h.ip       == "10.10.10.5"
    assert h.hostname == "target.local"
    assert h.traceroute == ["192.168.1.1", "10.0.0.1"]
    assert h.uptime is not None
    open_svcs = [s for s in h.services if s.state == "open"]
    assert len(open_svcs) == 6
    assert result.services_by_name("http")[0]["port"] == 80
    summary = result.summary()
    assert "10.10.10.5" in summary
    assert "ftp-anon"   in summary
    json_out = result.to_json()
    data = json.loads(json_out)
    assert data["hosts"][0]["ip"] == "10.10.10.5"
    print(f"    command:   {result.command}")
    print(f"    scan_end:  {result.scan_end}")
    print(f"    open svcs: {[s.port for s in open_svcs]}")

    # ── 9. Error handling ─────────────────────────────────────────────────────
    print("\n[9] Error handling")
    try:
        parse_nmap_xml("/nonexistent/path.xml")
    except FileNotFoundError as e:
        print(f"    FileNotFoundError: OK — {e}")

    with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", delete=False) as f:
        f.write("<notanmap/>")
        bad_path = f.name
    try:
        parse_nmap_xml(bad_path)
    except ValueError as e:
        print(f"    ValueError: OK — {e}")

    # ── 10. Pretty print ──────────────────────────────────────────────────────
    print("\n[10] pretty_print():")
    pretty_print(parsed)

    os.unlink(xml_path)
    os.unlink(bad_path)
    print("\nAll tests passed.")