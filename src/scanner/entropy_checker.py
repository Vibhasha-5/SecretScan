"""
entropy_checker.py

Detects high-entropy strings that are likely hardcoded secrets,
even when they don't match known patterns.

Shannon entropy formula:
    H = -Σ p(x) * log2(p(x))
"""

import math
import re
from dataclasses import dataclass
from typing import List, Optional

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from config.settings import (
    ENTROPY_THRESHOLD,
    ENTROPY_MIN_LENGTH,
    ENTROPY_MAX_LENGTH,
    KNOWN_PLACEHOLDERS,
)


# Character sets commonly used in secrets
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "0123456789abcdefABCDEF"
ALPHANUM_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


@dataclass
class EntropyFinding:
    file_path: str
    line_number: int
    line_content: str
    secret_candidate: str
    entropy: float
    charset: str

    def to_dict(self) -> dict:
        return {
            "type": "high_entropy_string",
            "file": self.file_path,
            "line": self.line_number,
            "entropy": round(self.entropy, 4),
            "charset": self.charset,
            "candidate": self.secret_candidate[:60] + ("..." if len(self.secret_candidate) > 60 else ""),
            "severity": "HIGH",
            "description": f"High-entropy {self.charset} string (entropy={self.entropy:.2f})",
        }


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def get_strings_of_set(line: str, charset: str) -> List[str]:
    """Extract contiguous substrings made only of chars in charset."""
    pattern = f"[{re.escape(charset)}]+"
    return re.findall(pattern, line)


def is_placeholder(value: str) -> bool:
    """Check if the value looks like a placeholder / example."""
    lower = value.lower()
    for placeholder in KNOWN_PLACEHOLDERS:
        if placeholder in lower:
            return True
    # Skip repeated characters (e.g., AAAAAAAAAAAAA)
    if len(set(value)) <= 3:
        return True
    return False


def check_line_for_entropy(
    line: str,
    file_path: str,
    line_number: int,
    threshold: float = ENTROPY_THRESHOLD,
) -> List[EntropyFinding]:
    """
    Scan a single line for high-entropy string candidates.
    Returns a list of EntropyFinding objects.
    """
    findings = []
    charsets = [
        ("base64", BASE64_CHARS),
        ("hex", HEX_CHARS),
    ]

    for charset_name, charset in charsets:
        for candidate in get_strings_of_set(line, charset):
            if ENTROPY_MIN_LENGTH <= len(candidate) <= ENTROPY_MAX_LENGTH:
                if is_placeholder(candidate):
                    continue
                entropy = shannon_entropy(candidate)
                if entropy >= threshold:
                    findings.append(EntropyFinding(
                        file_path=file_path,
                        line_number=line_number,
                        line_content=line.strip(),
                        secret_candidate=candidate,
                        entropy=entropy,
                        charset=charset_name,
                    ))
    return findings


def check_file_for_entropy(
    file_path: str,
    content: str,
    threshold: float = ENTROPY_THRESHOLD,
) -> List[EntropyFinding]:
    """
    Scan entire file content for high-entropy strings.
    """
    all_findings = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        findings = check_line_for_entropy(line, file_path, line_number, threshold)
        all_findings.extend(findings)
    return all_findings
