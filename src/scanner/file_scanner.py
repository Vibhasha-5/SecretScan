"""
file_scanner.py

Core file scanning engine. Reads a file and runs all detectors
plus entropy analysis against it.
"""

import os
from typing import List, Dict, Any

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from config.settings import MAX_FILE_SIZE_BYTES, SCANNABLE_EXTENSIONS, SCANNABLE_FILENAMES
from src.scanner.entropy_checker import check_file_for_entropy
from src.detectors.api_key_detector import APIKeyDetector
from src.detectors.token_detector import TokenDetector
from src.detectors.secret_detector import SecretDetector
from src.utils.logger import get_logger

logger = get_logger(__name__)


class FileScanner:
    """
    Scans a single file for secrets, API keys, tokens, and high-entropy strings.
    """

    def __init__(self, enable_entropy: bool = True, entropy_threshold: float = 4.5):
        self.enable_entropy = enable_entropy
        self.entropy_threshold = entropy_threshold
        self.detectors = [
            APIKeyDetector(),
            TokenDetector(),
            SecretDetector(),
        ]

    def should_scan(self, file_path: str) -> bool:
        """Determine if a file should be scanned based on extension/name."""
        filename = os.path.basename(file_path)
        ext = os.path.splitext(filename)[1].lower()

        if filename in SCANNABLE_FILENAMES:
            return True
        if ext in SCANNABLE_EXTENSIONS:
            return True
        return False

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan a single file. Returns list of finding dicts.
        """
        findings = []

        # Skip if shouldn't scan
        if not self.should_scan(file_path):
            return findings

        # Skip if too large
        try:
            file_size = os.path.getsize(file_path)
            if file_size > MAX_FILE_SIZE_BYTES:
                logger.warning(f"Skipping large file: {file_path} ({file_size} bytes)")
                return findings
        except OSError:
            return findings

        # Read content
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (IOError, OSError) as e:
            logger.error(f"Could not read {file_path}: {e}")
            return findings

        # Run pattern detectors
        for detector in self.detectors:
            detector_findings = detector.scan(file_path, content)
            findings.extend(detector_findings)

        # Run entropy analysis
        if self.enable_entropy:
            entropy_findings = check_file_for_entropy(
                file_path, content, self.entropy_threshold
            )
            for ef in entropy_findings:
                findings.append(ef.to_dict())

        # Deduplicate by (line, description)
        seen = set()
        deduped = []
        for f in findings:
            key = (f.get("file"), f.get("line"), f.get("description"))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return deduped
