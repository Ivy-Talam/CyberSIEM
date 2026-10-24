"""
report.py
Formats an AnalysisResult as a human-readable terminal report.
Uses only stdlib — no third-party dependencies.
"""

from analyzer import AnalysisResult

# ── ANSI colour codes ─────────────────────────────────────────────────────────
_COLOURS = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH":     "\033[93m",  # bright yellow
    "MEDIUM":   "\033[94m",  # bright blue
    "LOW":      "\033[92m",  # bright green
    "INFO":     "\033[37m",  # light grey
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
    "CYAN":     "\033[96m",
    "WHITE":    "\033[97m",
}

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _c(text: str, colour: str, use_colour: bool = True) -> str:
    if not use_colour:
        return text
    code = _COLOURS.get(colour, "")
    reset = _COLOURS["RESET"]
    return f"{code}{text}{reset}"


def _bar(count: int, max_count: int, width: int = 20) -> str:
    if max_count == 0:
        return " " * width
    filled = round(count / max_count * width)
    return "█" * filled + "░" * (width - filled)


def print_report(result: AnalysisResult, use_colour: bool = True, min_severity: str = "INFO") -> None:
    C = lambda text, col: _c(text, col, use_colour)
    BOLD = _COLOURS["BOLD"] if use_colour else ""
    RESET = _COLOURS["RESET"] if use_colour else ""

    width = 72

    # ── Header ────────────────────────────────────────────────────────────────
    print()
    print(C("=" * width, "CYAN"))
    print(C(f"  {'CYBERSIEM — THREAT ANALYSIS REPORT':^68}", "WHITE"))
    print(C("=" * width, "CYAN"))
    print()

    # ── Threat level banner ───────────────────────────────────────────────────
    level = result.threat_level
    banner_colour = level if level != "CLEAN" else "LOW"
    print(C(f"  OVERALL THREAT LEVEL: {level}", banner_colour))
    print(C(f"  Total log lines parsed: {result.total_lines}", "DIM"))
    print()

    # ── Severity summary ──────────────────────────────────────────────────────
    print(C("  SEVERITY BREAKDOWN", "CYAN"))
    print(C("  " + "─" * 40, "DIM"))
    max_sev = max((result.severity_counts.get(s, 0) for s in _SEV_ORDER), default=1)
    for sev in _SEV_ORDER:
        count = result.severity_counts.get(sev, 0)
        bar = _bar(count, max_sev)
        label = f"  {sev:<10}"
        print(f"{C(label, sev)}  {bar}  {C(str(count), sev)}")
    print()

    # ── Top source IPs ────────────────────────────────────────────────────────
    top_ips = result.top_ips(8)
    if top_ips:
        print(C("  TOP SOURCE IPs", "CYAN"))
        print(C("  " + "─" * 40, "DIM"))
        max_ip = top_ips[0][1]
        for ip, count in top_ips:
            bar = _bar(count, max_ip, width=16)
            print(f"  {C(ip, 'MEDIUM'):<28}  {bar}  {count}")
        print()

    # ── Top event types ───────────────────────────────────────────────────────
    top_types = result.top_event_types(8)
    if top_types:
        print(C("  EVENT TYPE BREAKDOWN", "CYAN"))
        print(C("  " + "─" * 40, "DIM"))
        max_type = top_types[0][1]
        for etype, count in top_types:
            bar = _bar(count, max_type, width=16)
            print(f"  {etype:<22}  {bar}  {count}")
        print()

    # ── Event table ───────────────────────────────────────────────────────────
    print(C("  FLAGGED EVENTS", "CYAN"))
    print(C("  " + "─" * 68, "DIM"))
    header = f"  {'SEV':<10}  {'TYPE':<18}  {'SOURCE IP':<16}  {'MESSAGE'}"
    print(C(header, "WHITE"))
    print(C("  " + "─" * 68, "DIM"))

    from rule_engine import SEVERITY_RANK
    min_rank = SEVERITY_RANK.get(min_severity, 0)
    shown = [e for e in result.events if SEVERITY_RANK.get(e.severity, 0) >= min_rank]

    if not shown:
        print(C("  No events at or above the selected severity threshold.", "DIM"))
    else:
        for event in shown:
            sev_label = C(f"  {event.severity:<10}", event.severity)
            type_label = f"  {event.event_type:<18}"
            ip = event.source_ips[0] if event.source_ips else "—"
            ip_label = f"  {ip:<16}"
            msg = event.raw
            if len(msg) > 50:
                msg = msg[:47] + "..."
            print(f"{sev_label}{type_label}{ip_label}  {C(msg, 'DIM')}")

    print()
    print(C("=" * width, "CYAN"))
    print()
