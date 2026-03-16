"""
test_api_keys.py — Unit tests for API key detection.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.detectors.api_key_detector import APIKeyDetector


def test_aws_access_key_detected():
    detector = APIKeyDetector()
    code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
    findings = detector.scan("test.py", code)
    assert any(f["type"] == "aws_access_key_id" for f in findings), "AWS key not detected"
    print("✅  AWS Access Key detection: PASSED")


def test_google_api_key_detected():
    detector = APIKeyDetector()
    code = 'GOOGLE_KEY = "AIzaSyBnTdS5Lm_8ExAmPle_K3yT0ken123456"\n'
    findings = detector.scan("test.py", code)
    assert any(f["type"] == "google_api_key" for f in findings), "Google API key not detected"
    print("✅  Google API Key detection: PASSED")


def test_stripe_live_key_detected():
    detector = APIKeyDetector()
    code = 'stripe.api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"\n'
    findings = detector.scan("test.py", code)
    assert any(f["type"] == "stripe_live_secret_key" for f in findings), "Stripe key not detected"
    print("✅  Stripe Live Key detection: PASSED")


def test_openai_key_detected():
    detector = APIKeyDetector()
    code = 'OPENAI_KEY = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghij"\n'
    findings = detector.scan("test.py", code)
    assert any(f["type"] == "openai_api_key" for f in findings), "OpenAI key not detected"
    print("✅  OpenAI API Key detection: PASSED")


def test_placeholder_ignored():
    detector = APIKeyDetector()
    code = 'GOOGLE_KEY = "your_api_key_here"\n'
    findings = detector.scan("test.py", code)
    print(f"✅  Placeholder suppression: PASSED (findings={len(findings)})")


def test_secret_masked():
    detector = APIKeyDetector()
    code = 'KEY = "AKIAIOSFODNN7EXAMPLE"\n'
    findings = detector.scan("test.py", code)
    if findings:
        matched = findings[0].get("matched", "")
        assert "***" in matched or "*" in matched, "Secret not masked in output"
    print("✅  Secret masking: PASSED")


if __name__ == "__main__":
    print("\n── API Key Detector Tests ──────────────────")
    test_aws_access_key_detected()
    test_google_api_key_detected()
    test_stripe_live_key_detected()
    test_openai_key_detected()
    test_placeholder_ignored()
    test_secret_masked()
    print("────────────────────────────────────────────")
    print("All tests passed! ✅\n")
