from typing import List, Dict
from pathlib import Path


class ConsoleReporter:
    COLORS = {
        "CRITICAL": "\033[91m",  # red
        "HIGH": "\033[91m",  # red
        "MEDIUM": "\033[93m",  # yellow
        "LOW": "\033[94m",  # blue
        "INFO": "\033[92m",  # green
        "RESET": "\033[0m",  # reset
    }

    def report(self, results: Dict[str, List[Dict]]):
        if not results:
            print("No security issues found.")
            return

        total_issues = sum(len(issues) for issues in results.values())
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for issues in results.values():
            for issue in issues:
                severity = issue.get("severity", "LOW")
                severity_count[severity] = severity_count.get(severity, 0) + 1

        print("\n" + "=" * 80)
        print("Security Scan Results")
        print("=" * 80)
        print(f"\nTotal issues: {total_issues}")
        print(f"  Critical: {severity_count['CRITICAL']}")
        print(f"  High: {severity_count['HIGH']}")
        print(f"  Medium: {severity_count['MEDIUM']}")
        print(f"  Low: {severity_count['LOW']}")
        print()

        for filepath, issues in results.items():
            abs_path = str(Path(filepath).resolve())

            print(f"\n{abs_path}")
            print("-" * 80)

            for issue in issues:
                self._print_issue(issue, abs_path)

        print("\n" + "=" * 80)
        if severity_count["CRITICAL"] > 0 or severity_count["HIGH"] > 0:
            print("WARNING: Found critical/high severity issues")
        else:
            print("No critical issues found")
        print("=" * 80 + "\n")

    def _print_issue(self, issue: Dict, filepath: str):
        severity = issue.get("severity", "LOW")
        color = self.COLORS.get(severity, "")
        reset = self.COLORS["RESET"]

        line = issue.get("line", 0)
        clickable_link = f"{filepath}:{line}"

        print(f"\n{color}[{severity}]{reset} {issue['type']}")
        print(f"   → {clickable_link}")
        print(f"   {issue['message']}")

        if "code" in issue and issue["code"]:
            code = issue["code"]
            if len(code) > 100:
                code = code[:97] + "..."
            print(f"  Code: {self._dim(code)}")

        if "recommendation" in issue:
            print(f"  Fix: {issue['recommendation']}")

    def _dim(self, text: str) -> str:
        return f"\033[2m{text}\033[0m"
