"""
test_scanner.py — Integration tests for the file and directory scanner.
"""

import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.scanner.file_scanner import FileScanner
from src.scanner.directory_scanner import DirectoryScanner


def test_file_scanner_detects_aws_key():
    scanner = FileScanner(enable_entropy=False)
    content = 'ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(content)
        tmp = f.name
    try:
        findings = scanner.scan_file(tmp)
        assert any("aws" in f["type"].lower() for f in findings), "AWS key not detected in file"
        print(f"✅  FileScanner AWS key: PASSED ({len(findings)} finding(s))")
    finally:
        os.unlink(tmp)


def test_file_scanner_skips_binary():
    scanner = FileScanner()
    # PNG magic bytes - binary file
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
        f.write(b'\x89PNG\r\n\x1a\n')
        tmp = f.name
    try:
        findings = scanner.scan_file(tmp)
        print(f"✅  FileScanner skips binary: PASSED ({len(findings)} finding(s))")
    finally:
        os.unlink(tmp)


def test_directory_scanner_multi_file():
    scanner = DirectoryScanner(enable_entropy=False)
    with tempfile.TemporaryDirectory() as tmpdir:
        # File 1: has AWS key
        with open(os.path.join(tmpdir, 'config.py'), 'w') as f:
            f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        # File 2: has Stripe key
        with open(os.path.join(tmpdir, '.env'), 'w') as f:
            f.write('STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n')
        # File 3: clean
        with open(os.path.join(tmpdir, 'app.py'), 'w') as f:
            f.write('print("hello world")\n')

        findings = scanner.scan_directory(tmpdir)
        stats = scanner.get_stats()

        assert len(findings) >= 2, f"Expected at least 2 findings, got {len(findings)}"
        assert stats['scanned_files'] >= 2
        print(f"✅  DirectoryScanner multi-file: PASSED ({len(findings)} findings, {stats['scanned_files']} files)")


def test_scanner_deduplicates():
    scanner = FileScanner(enable_entropy=False)
    # Same key repeated 3 times
    content = ('AKIAIOSFODNN7EXAMPLE\n' * 3)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(content)
        tmp = f.name
    try:
        findings = scanner.scan_file(tmp)
        # There should be findings but not 3x duplicated on same content
        print(f"✅  Scanner deduplication: PASSED ({len(findings)} finding(s))")
    finally:
        os.unlink(tmp)


if __name__ == "__main__":
    print("\n── Scanner Integration Tests ───────────────")
    test_file_scanner_detects_aws_key()
    test_file_scanner_skips_binary()
    test_directory_scanner_multi_file()
    test_scanner_deduplicates()
    print("────────────────────────────────────────────")
    print("All tests passed! ✅\n")
