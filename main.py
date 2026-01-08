import sys
import argparse
from pathlib import Path

from src.core.scanner import SecurityScanner
from src.reporters.console import ConsoleReporter


def main():
    parser = argparse.ArgumentParser(
        description='Security Linter - find vulnerabilities in Python code',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan myfile.py           Scan single file
  %(prog)s scan ./myproject/        Scan directory
  %(prog)s scan . --severity HIGH   Show only HIGH+ severity
        """
    )

    parser.add_argument(
        'command',
        choices=['scan'],
        help='Command to execute'
    )

    parser.add_argument(
        'target',
        help='File or directory to scan'
    )

    parser.add_argument(
        '--severity',
        choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        help='Minimum severity level to report'
    )

    args = parser.parse_args()

    if args.command == 'scan':
        scan_target(args.target, min_severity=args.severity)


def scan_target(target: str, min_severity: str = None):
    target_path = Path(target)

    if not target_path.exists():
        print(f"❌ Error: {target} does not exist")
        sys.exit(1)

    scanner = SecurityScanner()
    reporter = ConsoleReporter()

    print(f"🔍 Scanning {target}...")

    if target_path.is_file():
        findings = scanner.scan_file(str(target_path))
        results = {str(target_path): findings} if findings else {}
    else:
        results = scanner.scan_directory(str(target_path))

    if min_severity:
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        min_level = severity_order.get(min_severity, 0)

        filtered_results = {}
        for filepath, issues in results.items():
            filtered = [
                issue for issue in issues
                if severity_order.get(issue.get('severity', 'LOW'), 0) >= min_level
            ]
            if filtered:
                filtered_results[filepath] = filtered
        results = filtered_results

    reporter.report(results)

    has_critical = any(
        any(issue.get('severity') in ['CRITICAL', 'HIGH'] for issue in issues)
        for issues in results.values()
    )

    if has_critical:
        sys.exit(1)


if __name__ == '__main__':
    main()