import re
from typing import List, Dict
from src.core.rules.secrets import SECRET_PATTERNS


class RegexAnalyzer:

    def __init__(self):
        self.patterns = SECRET_PATTERNS

    def analyze(self, code: str) -> List[Dict]:

        findings = []

        for line_num, line in enumerate(code.split('\n'), start=1):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue

            for pattern_name, pattern_data in self.patterns.items():
                regex = pattern_data['pattern']

                match = re.search(regex, line, re.IGNORECASE)

                if match:
                    findings.append({
                        'type': 'hardcoded_secret',
                        'subtype': pattern_name,
                        'severity': pattern_data['severity'],
                        'line': line_num,
                        'message': pattern_data['message'],
                        'code': line.strip(),
                        'match': match.group(0)
                    })

        return findings