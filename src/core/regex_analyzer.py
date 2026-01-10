import re
from typing import List, Dict
from src.core.rules.secrets import SECRET_PATTERNS
from src.core.rules.crypto import SSL_TLS_PATTERNS


class RegexAnalyzer:
    def __init__(self):
        self.patterns = {**SECRET_PATTERNS, **SSL_TLS_PATTERNS}

    def analyze(self, code: str) -> List[Dict]:
        findings = []

        for line_num, line in enumerate(code.split("\n"), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for pattern_name, pattern_data in self.patterns.items():
                regex = pattern_data["pattern"]
                match = re.search(regex, line, re.IGNORECASE)

                if match:
                    # Определяем тип находки в зависимости от источника паттерна
                    finding_type = "ssl_tls_disabled" if pattern_name in SSL_TLS_PATTERNS else "hardcoded_secret"

                    findings.append(
                        {
                            "type": finding_type,
                            "subtype": pattern_name,
                            "severity": pattern_data["severity"],
                            "line": line_num,
                            "message": pattern_data["message"],
                            "code": line.strip(),
                            "match": match.group(0),
                        }
                    )

        return findings
