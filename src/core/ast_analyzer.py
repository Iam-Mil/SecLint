import ast
from typing import List, Dict
from src.core.rules.crypto import WEAK_CRYPTO_FUNCTIONS
from src.core.rules.injection import DANGEROUS_FUNCTIONS


class ASTAnalyzer:


    def analyze(self, code: str, filepath: str) -> List[Dict]:

        tree = ast.parse(code)

        visitor = SecurityVisitor(code, filepath)
        visitor.visit(tree)

        return visitor.issues


class SecurityVisitor(ast.NodeVisitor):


    def __init__(self, code: str, filepath: str):
        self.code = code
        self.filepath = filepath
        self.issues = []

    def visit_Call(self, node):

        if isinstance(node.func, ast.Name):
            func_name = node.func.id

            if func_name in DANGEROUS_FUNCTIONS:
                func_info = DANGEROUS_FUNCTIONS[func_name]
                self.issues.append({
                    'type': 'dangerous_function',
                    'severity': func_info['severity'],
                    'line': node.lineno,
                    'message': func_info['message'],
                    'code': self._get_source(node),
                    'recommendation': func_info['recommendation']
                })

        if isinstance(node.func, ast.Attribute):

            attr_name = node.func.attr

            if attr_name in WEAK_CRYPTO_FUNCTIONS:
                crypto_info = WEAK_CRYPTO_FUNCTIONS[attr_name]
                self.issues.append({
                    'type': 'weak_crypto',
                    'severity': crypto_info['severity'],
                    'line': node.lineno,
                    'message': crypto_info['message'],
                    'code': self._get_source(node),
                    'recommendation': crypto_info['recommendation']
                })

        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ['call', 'run', 'Popen']:
                for keyword in node.keywords:
                    if keyword.arg == 'shell':
                        if isinstance(keyword.value, ast.Constant):
                            if keyword.value.value is True:
                                self.issues.append({
                                    'type': 'command_injection',
                                    'severity': 'HIGH',
                                    'line': node.lineno,
                                    'message': 'subprocess with shell=True is dangerous',
                                    'code': self._get_source(node),
                                    'recommendation': 'Use shell=False and pass args as list'
                                })

        self.generic_visit(node)

    def visit_JoinedStr(self, node):

        text_parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                text_parts.append(value.value.upper())

        full_text = ''.join(text_parts)

        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP']
        if any(kw in full_text for kw in sql_keywords):
            self.issues.append({
                'type': 'sql_injection',
                'severity': 'CRITICAL',
                'line': node.lineno,
                'message': 'Potential SQL injection via f-string',
                'code': self._get_source(node),
                'recommendation': 'Use parameterized queries'
            })

        self.generic_visit(node)

    def _get_source(self, node):

        try:
            return ast.get_source_segment(self.code, node) or '<code unavailable>'
        except:
            return '<code unavailable>'