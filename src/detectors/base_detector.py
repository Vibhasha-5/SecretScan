"""
base_detector.py

Abstract base class for all detectors.
"""

import re
from abc import ABC, abstractmethod
from typing import List, Dict, Any

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config.settings import KNOWN_PLACEHOLDERS


class BaseDetector(ABC):
    """Base class for pattern-based secret detectors."""

    def __init__(self):
        self.patterns = self._load_patterns()

    @abstractmethod
    def _load_patterns(self) -> List[Dict]:
        """Return list of pattern dicts with keys: name, regex, severity, description."""
        pass

    def _is_placeholder(self, value: str) -> bool:
        lower = value.lower()
        for ph in KNOWN_PLACEHOLDERS:
            if ph in lower:
                return True
        return False

    def scan(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Scan content for all patterns. Returns list of finding dicts."""
        findings = []
        lines = content.splitlines()

        for pattern_info in self.patterns:
            regex = pattern_info["regex"]
            try:
                for match in re.finditer(regex, content, re.MULTILINE | re.IGNORECASE):
                    matched_value = match.group(0)

                    if self._is_placeholder(matched_value):
                        continue

                    # Find line number
                    line_number = content[:match.start()].count("\n") + 1
                    line_content = lines[line_number - 1] if line_number <= len(lines) else ""

                    # Mask the matched value in output
                    masked = self._mask_secret(matched_value)

                    findings.append({
                        "type": pattern_info["name"],
                        "file": file_path,
                        "line": line_number,
                        "line_content": line_content.strip(),
                        "matched": masked,
                        "severity": pattern_info["severity"],
                        "description": pattern_info["description"],
                    })
            except re.error:
                pass

        return findings

    def _mask_secret(self, value: str) -> str:
        """Mask most of the secret for safe display."""
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]
