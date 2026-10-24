"""
main.py — CyberSIEM CLI
Usage:
    python main.py <logfile>               Analyze a log file (shows INFO+)
    python main.py <logfile> --min HIGH    Show only HIGH and above
    python main.py <logfile> --no-colour   Plain output (great for piping)
    python main.py --rules                 List all detection rules
"""

import argparse
import sys
import os

# Allow running from project root with `python main.py`
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from analyzer import LogAnalyzer
from report import print_report
from rule_engine import get_rule_descriptions, SEVERITY_RANK


def cmd_analyze(args: argparse.Namespace) -> None:
    if not os.path.isfile(args.logfile):
        print(f"[ERROR] File not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    analyzer = LogAnalyzer()
    print(f"  Analyzing: {args.logfile} …")
    result = analyzer.analyze_file(args.logfile)

    print_report(
        result,
        use_colour=not args.no_colour,
        min_severity=args.min.upper(),
    )

    # Exit with non-zero code if threats detected (useful in CI/CD pipelines)
    threat = result.threat_level
    if threat == "CRITICAL":
        sys.exit(2)
    if threat == "HIGH":
        sys.exit(1)


def cmd_rules(_args: argparse.Namespace) -> None:
    print("\n  CyberSIEM — Detection Rules\n")
    print(f"  {'SEVERITY':<10}  {'TYPE':<20}  DESCRIPTION")
    print("  " + "─" * 60)
    for rule in get_rule_descriptions():
        print(f"  {rule['severity']:<10}  {rule['type']:<20}  {rule['description']}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cybersiem",
        description="CyberSIEM — SIEM-style log analyzer",
    )
    subparsers = parser.add_subparsers(dest="command")

    # analyze (default command)
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a log file")
    analyze_parser.add_argument("logfile", help="Path to log file")
    analyze_parser.add_argument(
        "--min",
        default="INFO",
        choices=list(SEVERITY_RANK.keys()),
        help="Minimum severity to display (default: INFO)",
    )
    analyze_parser.add_argument(
        "--no-colour", action="store_true", help="Disable ANSI colours"
    )

    # rules
    subparsers.add_parser("rules", help="List all detection rules")

    # Allow `python main.py sample.log` without writing `analyze`
    if len(sys.argv) >= 2 and not sys.argv[1].startswith("-") and sys.argv[1] not in ("analyze", "rules"):
        sys.argv.insert(1, "analyze")

    args = parser.parse_args()

    if args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "rules":
        cmd_rules(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
