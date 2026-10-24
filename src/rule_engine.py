"""
rule_engine.py
Threat detection rules. Each rule is a (pattern, severity, event_type) triple.
Rules are evaluated in order — first match wins.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    pattern: re.Pattern
    severity: str      # CRITICAL | HIGH | MEDIUM | LOW | INFO
    event_type: str
    description: str = ""


# ── Severity ranking ──────────────────────────────────────────────────────────
SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH":     4,
    "MEDIUM":   3,
    "LOW":      2,
    "INFO":     1,
}


def _r(pattern: str, severity: str, event_type: str, description: str = "") -> Rule:
    return Rule(re.compile(pattern, re.IGNORECASE), severity, event_type, description)


# Rules are checked top-to-bottom; first match wins.
RULES: list[Rule] = [
    # ── CRITICAL ──────────────────────────────────────────────────────────────
    _r(
        r"Failed password for (root|admin|administrator)",
        "CRITICAL", "Brute Force",
        "Repeated failed login against privileged account",
    ),
    _r(
        r"EXECVE.*\bnc\b.*-e.*\bbash\b|EXECVE.*\bbash\b.*-i|reverse.?shell",
        "CRITICAL", "Malware/C2",
        "Reverse shell execution detected",
    ),
    _r(
        r"curl\s+https?://\S+shell|wget\s+https?://\S+shell|EXECVE.*curl.*malicious",
        "CRITICAL", "Malware/C2",
        "Download of suspected remote shell script",
    ),
    _r(
        r"(ransomware|cryptolocker|wannacry|petya|lockbit)",
        "CRITICAL", "Ransomware",
        "Known ransomware family name detected",
    ),

    # ── HIGH ──────────────────────────────────────────────────────────────────
    _r(
        r"Failed password|authentication failure|invalid user",
        "HIGH", "Auth Failure",
        "Failed authentication attempt",
    ),
    _r(
        r"sudo.*command not allowed|sudo.*COMMAND=.*/bin/bash|sudo.*COMMAND=.*/bin/sh",
        "HIGH", "Priv Escalation",
        "Attempted privilege escalation via sudo",
    ),
    _r(
        r"GET\s+.*\.(env|bak|sql|conf|config|ini|xml|yml|yaml)\b|GET\s+.*/wp-admin|GET\s+.*/admin/config",
        "HIGH", "Web Recon",
        "Suspicious web request targeting sensitive paths",
    ),
    _r(
        r"DPT=3389|port\s+3389|rdp",
        "HIGH", "RDP Attempt",
        "Remote Desktop Protocol connection attempt",
    ),
    _r(
        r"DPT=445|port\s+445|smb",
        "HIGH", "SMB Scan",
        "SMB port scan or connection attempt",
    ),
    _r(
        r"sql\s*injection|union\s+select|OR\s+1=1|'--|\bxss\b|<script>",
        "HIGH", "Web Attack",
        "Web application attack pattern detected",
    ),
    _r(
        r"EXECVE.*curl|EXECVE.*wget|EXECVE.*python.*-c|EXECVE.*perl.*-e",
        "HIGH", "Suspicious Exec",
        "Suspicious command execution via auditd",
    ),

    # ── MEDIUM ────────────────────────────────────────────────────────────────
    _r(
        r"UFW BLOCK|iptables.*DROP|firewall.*deny|pf.*block",
        "MEDIUM", "Firewall Block",
        "Packet blocked by host firewall",
    ),
    _r(
        r"sudo.*COMMAND",
        "MEDIUM", "Sudo Usage",
        "Elevated command executed via sudo",
    ),
    _r(
        r"port\s+scan|nmap|masscan|zmap",
        "MEDIUM", "Port Scan",
        "Port scanning tool activity detected",
    ),
    _r(
        r"GET\s+.*\.\.(\/|%2F)|path\s+traversal|\.\./\.\.",
        "MEDIUM", "Path Traversal",
        "Directory traversal attempt detected",
    ),

    # ── LOW ───────────────────────────────────────────────────────────────────
    _r(
        r"Accepted password|Accepted publickey",
        "LOW", "Auth Success",
        "Successful SSH authentication",
    ),
    _r(
        r"session opened|session closed",
        "LOW", "Session Event",
        "User session started or ended",
    ),

    # ── INFO ──────────────────────────────────────────────────────────────────
    _r(
        r"CRON|systemd.*[Ss]tarted|apt|dpkg|yum|dnf",
        "INFO", "System Event",
        "Routine system or package management activity",
    ),
    _r(
        r".*",
        "INFO", "Generic",
        "No specific threat pattern matched",
    ),
]


def classify(line: str) -> tuple[str, str]:
    """Return (severity, event_type) for a log line."""
    for rule in RULES:
        if rule.pattern.search(line):
            return rule.severity, rule.event_type
    return "INFO", "Generic"


def get_rule_descriptions() -> list[dict]:
    """Return human-readable rule descriptions for documentation."""
    seen = set()
    result = []
    for rule in RULES:
        key = (rule.severity, rule.event_type)
        if key not in seen and rule.event_type != "Generic":
            seen.add(key)
            result.append({
                "severity": rule.severity,
                "type": rule.event_type,
                "description": rule.description,
            })
    return result
