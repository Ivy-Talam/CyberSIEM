"""
log_parser.py
Parses raw log lines into structured LogEvent objects.
Supports: syslog, auth.log, Apache/Nginx access logs, UFW, auditd.
"""

import re
from dataclasses import dataclass, field
from typing import Optional

# ── Timestamp patterns ────────────────────────────────────────────────────────
_TS_PATTERNS = [
    re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"),                    # ISO 8601
    re.compile(r"((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),  # syslog
    re.compile(r"\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\]"),        # Apache CLF
]

# ── IP address pattern ────────────────────────────────────────────────────────
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# ── Hostname/service pattern (syslog field 3) ─────────────────────────────────
_HOST_RE = re.compile(r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)")


@dataclass
class LogEvent:
    raw: str
    timestamp: Optional[str] = None
    hostname: Optional[str] = None
    source_ips: list = field(default_factory=list)
    severity: str = "INFO"
    event_type: str = "Generic"
    message: str = ""

    def __str__(self):
        ips = ", ".join(self.source_ips) if self.source_ips else "—"
        return (
            f"[{self.severity:<8}] [{self.event_type:<18}] "
            f"ts={self.timestamp or '—':<30} ip={ips:<15} | {self.message[:80]}"
        )


def _extract_timestamp(line: str) -> Optional[str]:
    for pattern in _TS_PATTERNS:
        m = pattern.search(line)
        if m:
            return m.group(1)
    return None


def _extract_ips(line: str) -> list[str]:
    return list(dict.fromkeys(_IP_RE.findall(line)))  # unique, order-preserved


def _extract_hostname(line: str) -> Optional[str]:
    m = _HOST_RE.match(line)
    if m:
        return m.group(1)
    # ISO syslog: "2024-01-15T09:05:00Z hostname service: ..."
    parts = line.split()
    if len(parts) >= 2 and "T" in parts[0] and parts[0].endswith("Z"):
        return parts[1]
    return None


def parse_line(line: str) -> Optional[LogEvent]:
    """Parse a single log line. Returns None for blank lines."""
    line = line.strip()
    if not line:
        return None

    return LogEvent(
        raw=line,
        timestamp=_extract_timestamp(line),
        hostname=_extract_hostname(line),
        source_ips=_extract_ips(line),
        message=line,
    )


def parse_file(path: str) -> list[LogEvent]:
    """Read a log file and return a list of LogEvent objects (blanks skipped)."""
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            event = parse_line(line)
            if event:
                events.append(event)
    return events


def parse_text(text: str) -> list[LogEvent]:
    """Parse a multi-line string of logs."""
    events = []
    for line in text.splitlines():
        event = parse_line(line)
        if event:
            events.append(event)
    return events
