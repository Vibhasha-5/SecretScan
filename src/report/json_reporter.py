"""
json_reporter.py

Machine-readable JSON report generator. Ideal for DevSecOps pipelines,
CI/CD integrations, and SIEM tools.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any
from collections import defaultdict

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config.settings import OUTPUT_DIR


def generate_json_report(
    findings: List[Dict[str, Any]],
    scan_path: str,
    stats: Dict[str, int] = None,
) -> Dict[str, Any]:
    """Build a structured JSON report from findings."""

    sev_counts: Dict[str, int] = defaultdict(int)
    for f in findings:
        sev_counts[f.get("severity", "INFO")] += 1

    report = {
        "meta": {
            "tool": "Secret & API Key Detector",
            "version": "1.0.0",
            "scan_path": os.path.abspath(scan_path),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total_findings": len(findings),
        },
        "summary": {
            "CRITICAL": sev_counts.get("CRITICAL", 0),
            "HIGH": sev_counts.get("HIGH", 0),
            "MEDIUM": sev_counts.get("MEDIUM", 0),
            "LOW": sev_counts.get("LOW", 0),
            "INFO": sev_counts.get("INFO", 0),
        },
        "stats": stats or {},
        "findings": findings,
    }
    return report


def save_json_report(
    findings: List[Dict[str, Any]],
    scan_path: str,
    stats: Dict[str, int] = None,
    output_path: str = None,
) -> str:
    """Save JSON report to file. Returns the output file path."""
    report = generate_json_report(findings, scan_path, stats)

    if output_path is None:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(OUTPUT_DIR, f"scan_report_{timestamp}.json")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    return output_path
