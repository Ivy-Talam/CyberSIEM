"""
analyzer.py
LogAnalyzer ties together the parser and rule engine.
Produces a structured AnalysisResult ready for reporting.
"""

from collections import Counter
from dataclasses import dataclass, field

from log_parser import LogEvent, parse_file, parse_text
from rule_engine import classify, SEVERITY_RANK


@dataclass
class AnalysisResult:
    events: list[LogEvent] = field(default_factory=list)
    severity_counts: Counter = field(default_factory=Counter)
    event_type_counts: Counter = field(default_factory=Counter)
    ip_counts: Counter = field(default_factory=Counter)
    total_lines: int = 0

    @property
    def threat_level(self) -> str:
        if self.severity_counts.get("CRITICAL", 0) > 0:
            return "CRITICAL"
        if self.severity_counts.get("HIGH", 0) > 0:
            return "HIGH"
        if self.severity_counts.get("MEDIUM", 0) > 0:
            return "MEDIUM"
        return "CLEAN"

    def top_ips(self, n: int = 5) -> list[tuple[str, int]]:
        return self.ip_counts.most_common(n)

    def top_event_types(self, n: int = 5) -> list[tuple[str, int]]:
        return self.event_type_counts.most_common(n)

    def filter_by_severity(self, min_severity: str) -> list[LogEvent]:
        """Return events at or above the given severity."""
        min_rank = SEVERITY_RANK.get(min_severity, 0)
        return [e for e in self.events if SEVERITY_RANK.get(e.severity, 0) >= min_rank]


class LogAnalyzer:
    """Main analysis class. Feed it a file path or raw text."""

    def analyze_file(self, path: str) -> AnalysisResult:
        events = parse_file(path)
        return self._analyze(events)

    def analyze_text(self, text: str) -> AnalysisResult:
        events = parse_text(text)
        return self._analyze(events)

    def _analyze(self, events: list[LogEvent]) -> AnalysisResult:
        result = AnalysisResult(total_lines=len(events))

        for event in events:
            sev, etype = classify(event.raw)
            event.severity = sev
            event.event_type = etype

            result.severity_counts[sev] += 1
            result.event_type_counts[etype] += 1
            for ip in event.source_ips:
                result.ip_counts[ip] += 1

        # Sort events: most severe first, then by original order
        result.events = sorted(
            events,
            key=lambda e: -SEVERITY_RANK.get(e.severity, 0),
        )
        return result
