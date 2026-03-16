"""
test_entropy.py — Unit tests for entropy-based detection.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.scanner.entropy_checker import shannon_entropy, check_line_for_entropy


def test_low_entropy_word():
    entropy = shannon_entropy("aaaaaaaaaaaaaaaaaaaaaa")
    assert entropy < 1.0, f"Expected low entropy, got {entropy}"
    print(f"✅  Low-entropy string: PASSED (H={entropy:.4f})")


def test_high_entropy_secret():
    # Typical base64-encoded secret
    entropy = shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    assert entropy >= 4.0, f"Expected high entropy, got {entropy}"
    print(f"✅  High-entropy secret: PASSED (H={entropy:.4f})")


def test_entropy_detection_in_line():
    line = 'SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    findings = check_line_for_entropy(line, "test.py", 1, threshold=4.0)
    assert len(findings) > 0, "High entropy string not detected in line"
    print(f"✅  Entropy detection in line: PASSED ({len(findings)} finding(s))")


def test_no_false_positive_on_url():
    line = 'BASE_URL = "https://www.example.com/api/v1/users"'
    findings = check_line_for_entropy(line, "test.py", 1, threshold=4.5)
    print(f"✅  URL false-positive test: PASSED ({len(findings)} finding(s))")


def test_entropy_threshold():
    high = shannon_entropy("A3f#9Kz@P2mQ8rNv5wBe7tLxY1cU6dJo4iGh")
    low  = shannon_entropy("password")
    assert high > low
    print(f"✅  Entropy threshold comparison: PASSED (high={high:.4f}, low={low:.4f})")


if __name__ == "__main__":
    print("\n── Entropy Checker Tests ───────────────────")
    test_low_entropy_word()
    test_high_entropy_secret()
    test_entropy_detection_in_line()
    test_no_false_positive_on_url()
    test_entropy_threshold()
    print("────────────────────────────────────────────")
    print("All tests passed! ✅\n")
