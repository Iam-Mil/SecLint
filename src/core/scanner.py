from pathlib import Path
from typing import List, Dict
from src.core.ast_analyzer import ASTAnalyzer
from src.core.regex_analyzer import RegexAnalyzer


class SecurityScanner:
    def __init__(self):
        self.ast_analyzer = ASTAnalyzer()
        self.regex_analyzer = RegexAnalyzer()

    def scan_file(self, filepath: str) -> List[Dict]:
        filepath = Path(filepath)

        if not filepath.exists():
            return [{"error": f"File {filepath} not found"}]

        if filepath.suffix != ".py":
            return [{"error": "Only .py files supported"}]

        with open(filepath, "r", encoding="utf-8") as f:
            code = f.read()

        findings = []

        findings.extend(self.regex_analyzer.analyze(code))

        try:
            findings.extend(self.ast_analyzer.analyze(code, str(filepath)))
        except SyntaxError as e:
            findings.append(
                {
                    "type": "syntax_error",
                    "severity": "INFO",
                    "line": e.lineno or 0,
                    "message": f"Syntax error: {e.msg}",
                    "code": "",
                }
            )

        findings.sort(key=lambda x: x.get("line", 0))

        return findings

    def scan_directory(self, dirpath: str) -> Dict[str, List[Dict]]:
        dirpath = Path(dirpath)
        results = {}

        for py_file in dirpath.rglob("*.py"):
            findings = self.scan_file(str(py_file))
            if findings:
                results[str(py_file)] = findings

        return results
