"""
file_utils.py - File reading and path utilities.
"""

import os
from typing import Optional


def read_file_safe(path: str, max_bytes: int = 5 * 1024 * 1024) -> Optional[str]:
    """Safely read a file, returning None on error."""
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except (IOError, OSError):
        return None


def get_relative_path(path: str, base: str) -> str:
    """Return path relative to base, or absolute path if not relative."""
    try:
        return os.path.relpath(path, base)
    except ValueError:
        return path


def human_readable_size(num_bytes: int) -> str:
    """Convert bytes to human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"
