"""
kira/parsers/vuln_scanner.py — Vulnerability scanner output parsers
====================================================================
Parsers for searchsploit and other vulnerability scanning tool outputs.

Usage:
    from vuln_scanner import parse_searchsploit_json
    
    findings = parse_searchsploit_json(json_output_string)
"""

import json
from typing import Any


def parse_searchsploit_json(json_str: str) -> list[dict]:
    """
    Parse searchsploit --json output and extract exploit findings.
    
    Parameters
    ----------
    json_str : str
        Raw JSON output from: searchsploit --json <query>
    
    Returns
    -------
    list[dict]
        List of Finding-shaped dicts with keys:
        - title: exploit name
        - severity: "high" / "medium" / "low" 
        - port: inferred from context or 0
        - service: inferred service name
        - cvss: optional CVSS score
        - cve: CVE identifier
        - exploit_available: True if Metasploit module exists
        - description: brief description
        - remediation: mitigation advice
    
    Gracefully returns [] on parse errors.
    """
    findings = []
    
    try:
        data = json.loads(json_str)
    except (json.JSONDecodeError, ValueError):
        return []
    
    # searchsploit --json returns: {"results": [...]}
    results = data.get("results", [])
    if not isinstance(results, list):
        return []
    
    for result in results:
        if not isinstance(result, dict):
            continue
        
        title = result.get("Title", "")
        if not title:
            continue
        
        # Extract CVE and exploit type
        cve = _extract_cve(title)
        has_msf = _has_metasploit_module(result)
        
        # Infer severity from title keywords and available exploits
        severity = _infer_severity(title, has_msf)
        
        finding = {
            "title": title,
            "severity": severity,
            "port": 0,  # Will be inferred from service
            "service": _infer_service(title),
            "cvss": 0.0,
            "cve": cve,
            "exploit_available": has_msf,
            "description": f"Vulnerability in {_infer_service(title)}: {title}",
            "remediation": "Apply available patches and monitor official security advisories.",
        }
        findings.append(finding)
    
    return findings


def _extract_cve(title: str) -> str:
    """Extract CVE identifier from title string."""
    import re
    match = re.search(r"CVE-\d{4}-\d{4,}", title, re.IGNORECASE)
    return match.group(0) if match else ""


def _has_metasploit_module(result: dict) -> bool:
    """Check if result indicates a Metasploit module is available."""
    # searchsploit JSON includes "Type" field indicating exploit type
    # "type": "Metasploit" or similar
    type_field = result.get("Type", "").lower()
    return "metasploit" in type_field or "msf" in type_field


def _infer_severity(title: str, has_exploit: bool) -> str:
    """Infer finding severity from title and exploit availability."""
    title_lower = title.lower()
    
    # Critical indicators
    if any(x in title_lower for x in ["rce", "remote code execution", "critical"]):
        return "critical"
    
    # High indicators
    if any(x in title_lower for x in ["privilege escalation", "privesc", "sudo", "suid", "high"]):
        return "high"
    
    # Medium
    if has_exploit or any(x in title_lower for x in ["sql injection", "xss", "authentication bypass"]):
        return "medium"
    
    return "low"


def _infer_service(title: str) -> str:
    """Infer service name from vulnerability title."""
    title_lower = title.lower()
    
    services = {
        "http": ["apache", "nginx", "iis", "lighttpd", "tomcat", "wordpress", "joomla"],
        "ssh": ["openssh", "libssh"],
        "ftp": ["vsftpd", "pro-ftpd"],
        "smb": ["samba", "windows", "cifs"],
        "mysql": ["mysql", "mariadb"],
        "postgres": ["postgresql", "postgres"],
        "mongodb": ["mongodb", "mongo"],
        "redis": ["redis"],
        "ldap": ["ldap", "openldap"],
        "dns": ["bind", "dns", "dnsmasq"],
    }
    
    for service, keywords in services.items():
        if any(kw in title_lower for kw in keywords):
            return service
    
    return "unknown"
