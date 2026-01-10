from src.core.scanner import SecurityScanner


class TestSecurityScanner:
    def test_scan_file_with_vulnerabilities(self, vulnerable_code_file):
        scanner = SecurityScanner()
        findings = scanner.scan_file(str(vulnerable_code_file))

        assert len(findings) > 0
        assert any(f["type"] == "dangerous_function" for f in findings)
        assert any(f["type"] == "weak_crypto" for f in findings)
        assert any(f["type"] == "hardcoded_secret" for f in findings)

    def test_scan_clean_file(self, sample_py_file):
        scanner = SecurityScanner()
        findings = scanner.scan_file(str(sample_py_file))
        assert len(findings) == 0

    def test_scan_directory(self, temp_dir):
        file1 = temp_dir / "vuln.py"
        file1.write_text('eval("test")')

        scanner = SecurityScanner()
        results = scanner.scan_directory(str(temp_dir))

        assert len(results) >= 1
        assert any("eval" in str(findings) for findings in results.values())

    def test_nonexistent_file(self):
        scanner = SecurityScanner()
        findings = scanner.scan_file("/nonexistent/file.py")
        assert "error" in findings[0]
