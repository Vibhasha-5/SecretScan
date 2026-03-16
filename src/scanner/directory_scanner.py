"""
directory_scanner.py

Recursively walks a directory tree and scans all eligible files
for secrets and API keys.
"""

import os
import fnmatch
from typing import List, Dict, Any, Callable, Optional

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from config.settings import IGNORED_DIRECTORIES, IGNORED_FILE_PATTERNS
from src.scanner.file_scanner import FileScanner
from src.utils.logger import get_logger

logger = get_logger(__name__)


class DirectoryScanner:
    """
    Recursively scans a directory for secrets.
    """

    def __init__(
        self,
        enable_entropy: bool = True,
        entropy_threshold: float = 4.5,
        progress_callback: Optional[Callable[[str], None]] = None,
    ):
        self.file_scanner = FileScanner(
            enable_entropy=enable_entropy,
            entropy_threshold=entropy_threshold,
        )
        self.progress_callback = progress_callback
        self.scanned_files = 0
        self.skipped_files = 0
        self.total_findings = 0

    def _should_ignore_dir(self, dirname: str) -> bool:
        return dirname in IGNORED_DIRECTORIES or dirname.startswith(".")

    def _should_ignore_file(self, filename: str) -> bool:
        for pattern in IGNORED_FILE_PATTERNS:
            if fnmatch.fnmatch(filename, pattern):
                return True
        return False

    def scan_directory(self, root_path: str) -> List[Dict[str, Any]]:
        """
        Walk a directory tree and return all findings.
        """
        all_findings = []
        root_path = os.path.abspath(root_path)

        if not os.path.exists(root_path):
            logger.error(f"Path does not exist: {root_path}")
            return all_findings

        if os.path.isfile(root_path):
            return self.file_scanner.scan_file(root_path)

        logger.info(f"Scanning directory: {root_path}")

        for dirpath, dirnames, filenames in os.walk(root_path):
            # Prune ignored directories in-place
            dirnames[:] = [
                d for d in dirnames if not self._should_ignore_dir(d)
            ]

            for filename in filenames:
                if self._should_ignore_file(filename):
                    self.skipped_files += 1
                    continue

                file_path = os.path.join(dirpath, filename)

                if self.progress_callback:
                    self.progress_callback(file_path)

                findings = self.file_scanner.scan_file(file_path)

                if findings:
                    logger.info(f"  [!] {len(findings)} finding(s) in {file_path}")
                    all_findings.extend(findings)

                self.scanned_files += 1

        self.total_findings = len(all_findings)
        logger.info(
            f"Scan complete: {self.scanned_files} files scanned, "
            f"{self.skipped_files} skipped, "
            f"{self.total_findings} findings."
        )

        return all_findings

    def get_stats(self) -> Dict[str, int]:
        return {
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "total_findings": self.total_findings,
        }
