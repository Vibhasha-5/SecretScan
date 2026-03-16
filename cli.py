#!/usr/bin/env python3
"""
cli.py — Secret & API Key Detector
Entry point for command-line usage.

Usage:
    python cli.py scan ./my_project
    python cli.py scan ./my_project --format json
    python cli.py scan ./my_project --no-entropy --severity HIGH
    python cli.py scan ./my_project --output report.json
"""

import argparse
import json
import os
import sys

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.scanner.directory_scanner import DirectoryScanner
from src.report.formatter import format_findings
from src.report.json_reporter import save_json_report, generate_json_report
from config.settings import SEVERITY_LEVELS


BANNER = r"""
  ____                     _     ____       _            _             
 / ___|  ___  ___ _ __ ___| |_  |  _ \  ___| |_ ___  ___| |_ ___  _ __ 
 \___ \ / _ \/ __| '__/ _ \ __| | | | |/ _ \ __/ _ \/ __| __/ _ \| '__|
  ___) |  __/ (__| | |  __/ |_  | |_| |  __/ ||  __/ (__| || (_) | |   
 |____/ \___|\___|_|  \___|\__| |____/ \___|\__\___|\___|\__\___/|_|   

  🔐  Secret & API Key Detector  |  v1.0.0  |  DevSecOps Toolkit
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Detect hardcoded secrets, API keys, and tokens in source code.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py scan ./my_project
  python cli.py scan ./my_project --format json
  python cli.py scan ./my_project --format json --output results.json
  python cli.py scan ./my_project --no-entropy
  python cli.py scan ./my_project --severity HIGH
  python cli.py scan ./samples
        """,
    )

    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory")
    scan_parser.add_argument("path", help="File or directory path to scan")
    scan_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output file path (for JSON format)",
    )
    scan_parser.add_argument(
        "--no-entropy",
        action="store_true",
        help="Disable entropy-based detection",
    )
    scan_parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=4.5,
        help="Shannon entropy threshold (default: 4.5)",
    )
    scan_parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Minimum severity level to report",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    scan_parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if args.command != "scan":
        print(BANNER)
        print("Use: python cli.py scan <path>")
        print("     python cli.py --help")
        sys.exit(0)

    print(BANNER)

    scan_path = args.path
    if not os.path.exists(scan_path):
        print(f"❌  Error: Path does not exist: {scan_path}")
        sys.exit(1)

    print(f"🔍  Scanning: {os.path.abspath(scan_path)}")
    print(f"   Entropy detection : {'disabled' if args.no_entropy else 'enabled'}")
    print(f"   Entropy threshold : {args.entropy_threshold}")
    print(f"   Output format     : {args.format}")
    print()

    def progress(path):
        if not args.quiet:
            short = path[-60:] if len(path) > 60 else path
            print(f"\r  Scanning: {short:<62}", end="", flush=True)

    scanner = DirectoryScanner(
        enable_entropy=not args.no_entropy,
        entropy_threshold=args.entropy_threshold,
        progress_callback=progress if not args.quiet else None,
    )

    findings = scanner.scan_directory(scan_path)
    stats = scanner.get_stats()

    if not args.quiet:
        print("\r" + " " * 80 + "\r", end="")  # Clear progress line

    # Filter by severity
    if args.severity:
        min_level = SEVERITY_LEVELS.get(args.severity, 0)
        findings = [
            f for f in findings
            if SEVERITY_LEVELS.get(f.get("severity", "INFO"), 0) >= min_level
        ]

    # Output
    if args.format == "json":
        if args.output:
            output_path = args.output
            report = generate_json_report(findings, scan_path, stats)
            with open(output_path, "w") as fp:
                json.dump(report, fp, indent=2, default=str)
        else:
            output_path = save_json_report(findings, scan_path, stats)

        print(f"📄  JSON report saved: {output_path}")
        print(f"    Total findings  : {len(findings)}")
    else:
        output = format_findings(findings, stats, use_color=not args.no_color)
        print(output)

    # Exit code: 1 if any CRITICAL/HIGH findings
    critical_or_high = [
        f for f in findings
        if f.get("severity") in ("CRITICAL", "HIGH")
    ]
    sys.exit(1 if critical_or_high else 0)


if __name__ == "__main__":
    main()
