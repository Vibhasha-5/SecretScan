"""
formatter.py

Human-readable terminal output formatter for scan findings.
"""

import sys
import os
from typing import List, Dict, Any
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config.settings import SEVERITY_COLORS, SEVERITY_LEVELS


SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "⚪",
}


def _color(text: str, severity: str) -> str:
    """Wrap text in ANSI color codes for the given severity."""
    c = SEVERITY_COLORS.get(severity, "")
    reset = SEVERITY_COLORS.get("RESET", "")
    return f"{c}{text}{reset}"


def format_findings(
    findings: List[Dict[str, Any]],
    stats: Dict[str, int] = None,
    use_color: bool = True,
) -> str:
    """
    Format a list of findings into a human-readable string.
    """
    if not findings:
        return "\n✅  No secrets detected. Your codebase looks clean!\n"

    lines = []
    lines.append("\n" + "=" * 70)
    lines.append("  SECRET & API KEY DETECTOR — SCAN RESULTS")
    lines.append("=" * 70)

    # Group by file
    by_file: Dict[str, List] = defaultdict(list)
    for f in findings:
        by_file[f["file"]].append(f)

    # Sort by severity
    severity_order = lambda s: -SEVERITY_LEVELS.get(s.get("severity", "INFO"), 0)

    for file_path, file_findings in sorted(by_file.items()):
        lines.append(f"\n📁  {file_path}")
        lines.append("─" * 60)

        for finding in sorted(file_findings, key=severity_order):
            sev = finding.get("severity", "INFO")
            icon = SEVERITY_ICONS.get(sev, "⚪")
            label = f"[{sev}]"
            if use_color:
                label = _color(label, sev)

            lines.append(
                f"  {icon} {label} Line {finding.get('line', '?')} — {finding.get('description', 'Unknown')}"
            )

            if finding.get("matched"):
                lines.append(f"       Matched : {finding['matched']}")

            if finding.get("line_content"):
                snippet = finding["line_content"][:120]
                lines.append(f"       Context : {snippet}")

            if finding.get("entropy"):
                lines.append(f"       Entropy : {finding['entropy']:.4f}")

            lines.append("")

    # Summary
    lines.append("=" * 70)
    lines.append("  SUMMARY")
    lines.append("─" * 70)

    sev_counts: Dict[str, int] = defaultdict(int)
    for f in findings:
        sev_counts[f.get("severity", "INFO")] += 1

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = sev_counts.get(sev, 0)
        if count:
            icon = SEVERITY_ICONS.get(sev, "⚪")
            label = f"{sev:<10}"
            if use_color:
                label = _color(label, sev)
            lines.append(f"  {icon}  {label} : {count} finding(s)")

    lines.append(f"\n  Total findings : {len(findings)}")

    if stats:
        lines.append(f"  Files scanned  : {stats.get('scanned_files', 0)}")
        lines.append(f"  Files skipped  : {stats.get('skipped_files', 0)}")

    lines.append("=" * 70 + "\n")
    return "\n".join(lines)
