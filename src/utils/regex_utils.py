"""
regex_utils.py - Regex compilation and matching helpers.
"""

import re
from typing import List, Iterator, Match


def compile_pattern(pattern: str, flags: int = re.IGNORECASE | re.MULTILINE):
    """Compile a regex with error handling."""
    try:
        return re.compile(pattern, flags)
    except re.error as e:
        raise ValueError(f"Invalid regex pattern '{pattern}': {e}")


def find_all_matches(pattern: str, text: str) -> List[Match]:
    """Find all matches of pattern in text."""
    try:
        return list(re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE))
    except re.error:
        return []


def mask_value(value: str, show_chars: int = 4) -> str:
    """Mask a secret value for safe display."""
    if len(value) <= show_chars * 2:
        return "*" * len(value)
    return value[:show_chars] + "*" * (len(value) - show_chars * 2) + value[-show_chars:]
