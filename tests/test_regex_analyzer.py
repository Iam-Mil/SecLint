from src.core.regex_analyzer import RegexAnalyzer


class TestRegexAnalyzer:
    def test_detect_aws_key(self):
        analyzer = RegexAnalyzer()
        code = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
        findings = analyzer.analyze(code)

        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"

    def test_detect_github_token(self):
        analyzer = RegexAnalyzer()
        code = 'token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
        findings = analyzer.analyze(code)

        assert any("github" in f["subtype"].lower() for f in findings)

    def test_detect_hardcoded_password(self):
        analyzer = RegexAnalyzer()
        code = 'password = "SuperSecret123456"'
        findings = analyzer.analyze(code)

        assert len(findings) == 1
        assert "password" in findings[0]["subtype"].lower()

    def test_detect_private_key(self):
        analyzer = RegexAnalyzer()
        code = "-----BEGIN RSA PRIVATE KEY-----"
        findings = analyzer.analyze(code)

        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"

    def test_ignore_comments(self):
        analyzer = RegexAnalyzer()
        code = '# aws_key = "AKIAIOSFODNN7EXAMPLE"'
        findings = analyzer.analyze(code)

        assert len(findings) == 0

    def test_multiple_secrets(self):
        analyzer = RegexAnalyzer()
        code = """
aws_key = "AKIAIOSFODNN7EXAMPLE"
password = "MyPassword123"
"""
        findings = analyzer.analyze(code)
        assert len(findings) >= 2

    def test_clean_code(self):
        analyzer = RegexAnalyzer()
        code = 'def hello():\n    print("Hello")'
        findings = analyzer.analyze(code)

        assert len(findings) == 0
