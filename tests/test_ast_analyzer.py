from src.core.ast_analyzer import ASTAnalyzer


class TestASTAnalyzer:
    def test_detect_eval(self):
        analyzer = ASTAnalyzer()
        code = 'result = eval("1 + 1")'
        findings = analyzer.analyze(code, "test.py")

        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert "eval" in findings[0]["message"].lower()

    def test_detect_exec(self):
        analyzer = ASTAnalyzer()
        code = 'exec("import sys")'
        findings = analyzer.analyze(code, "test.py")

        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"

    def test_detect_weak_hash(self):
        analyzer = ASTAnalyzer()
        code = 'import hashlib\nhashlib.md5(b"test")'
        findings = analyzer.analyze(code, "test.py")

        assert len(findings) >= 1
        assert any("md5" in f["message"].lower() for f in findings)

    def test_detect_shell_injection(self):
        analyzer = ASTAnalyzer()
        code = 'import subprocess\nsubprocess.run("ls", shell=True)'
        findings = analyzer.analyze(code, "test.py")

        assert len(findings) == 1
        assert "shell=True" in findings[0]["message"]

    def test_detect_sql_injection(self):
        analyzer = ASTAnalyzer()
        code = 'user_id = request.GET["id"]\nquery = f"SELECT * FROM users WHERE id = {user_id}"'
        findings = analyzer.analyze(code, "test.py")

        assert len(findings) == 1
        assert findings[0]["type"] == "sql_injection"
        assert findings[0]["severity"] == "CRITICAL"

    def test_multiple_issues(self):
        analyzer = ASTAnalyzer()
        code = """
eval("test")
exec("code")
import hashlib
hashlib.md5(b"x")
"""
        findings = analyzer.analyze(code, "test.py")
        assert len(findings) >= 3

    def test_clean_code(self):
        analyzer = ASTAnalyzer()
        code = 'def hello():\n    print("Hello")\n    return True'
        findings = analyzer.analyze(code, "test.py")

        assert len(findings) == 0

    def test_shell_false_is_safe(self):
        analyzer = ASTAnalyzer()
        code = 'import subprocess\nsubprocess.run(["ls"], shell=False)'
        findings = analyzer.analyze(code, "test.py")

        assert len(findings) == 0

    def test_detect_os_system(self):
        analyzer = ASTAnalyzer()
        code = 'import os\nos.system("ls -la")'
        findings = analyzer.analyze(code, "test.py")

        assert len(findings) == 1
        assert findings[0]['type'] == 'command_injection'
        assert findings[0]['severity'] == 'CRITICAL'

    def test_detect_sql_format(self):
        analyzer = ASTAnalyzer()
        code = 'query = "SELECT * FROM users WHERE id = {}".format(user_id)'
        findings = analyzer.analyze(code, "test.py")

        assert len(findings) == 1
        assert findings[0]['type'] == 'sql_injection'
        assert 'format()' in findings[0]['message']

    def test_detect_sql_percent(self):
        analyzer = ASTAnalyzer()
        code = 'query = "DELETE FROM users WHERE name = \'%s\'" % user_name'
        findings = analyzer.analyze(code, "test.py")

        assert len(findings) == 1
        assert findings[0]['type'] == 'sql_injection'
        assert '% formatting' in findings[0]['message']
