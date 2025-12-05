"""
Правила для опасных функций и инъекций.

eval/exec — выполнение произвольного кода
pickle / yaml.load — код при десериализации
os.system / subprocess — command injections
open(..., 'w') на пользовательском пути — риск записи произвольных файлов
"""

DANGEROUS_FUNCTIONS = {
    # --- Прямое выполнение кода ---
    'eval': {
        'severity': 'CRITICAL',
        'message': 'eval() executes arbitrary code',
        'recommendation': 'Use ast.literal_eval() for safe evaluation'
    },

    'exec': {
        'severity': 'CRITICAL',
        'message': 'exec() executes arbitrary code',
        'recommendation': 'Avoid exec(). Refactor logic'
    },

    'compile': {
        'severity': 'HIGH',
        'message': 'compile() can compile attacker-controlled code',
        'recommendation': 'Never compile untrusted code'
    },

    '__import__': {
        'severity': 'MEDIUM',
        'message': 'Dynamic import may load unsafe modules',
        'recommendation': 'Prefer static imports'
    },

    'importlib.import_module': {
        'severity': 'MEDIUM',
        'message': 'Dynamic module import detected',
        'recommendation': 'Validate input before importing modules dynamically'
    },

    # --- Python десериализация ---
    'marshal.loads': {
        'severity': 'HIGH',
        'message': 'marshal loads arbitrary code objects',
        'recommendation': 'Do not deserialize untrusted data'
    },

    'shelve.open': {
        'severity': 'HIGH',
        'message': 'shelve uses pickle under the hood',
        'recommendation': 'Never use shelve on untrusted files'
    },

    'dill.loads': {
        'severity': 'CRITICAL',
        'message': 'dill deserialization can execute arbitrary code',
        'recommendation': 'Do not use dill for untrusted data'
    },
}

# --- Опасная десериализация ---
DANGEROUS_DESERIALIZATION = {
    'pickle': {
        'functions': ['loads', 'load'],
        'severity': 'HIGH',
        'message': 'pickle deserialization may execute code',
        'recommendation': 'Use json or other safe formats'
    },

    'yaml': {
        'functions': ['load', 'load_all'],
        'severity': 'HIGH',
        'message': 'yaml.load() without SafeLoader executes code',
        'recommendation': 'Use yaml.safe_load()'
    },

    'jsonpickle': {
        'functions': ['decode'],
        'severity': 'HIGH',
        'message': 'jsonpickle can restore arbitrary Python objects',
        'recommendation': 'Avoid jsonpickle for untrusted input'
    },
}

# --- Опасные системные вызовы — командные инъекции ---
COMMAND_INJECTION_SOURCES = {
    'os.system': {
        'severity': 'CRITICAL',
        'message': 'os.system() vulnerable to command injection',
        'recommendation': 'Use subprocess.run([...]) with args list'
    },

    'os.popen': {
        'severity': 'CRITICAL',
        'message': 'os.popen() executes shell commands',
        'recommendation': 'Avoid popen(); use subprocess with list args'
    },

    'subprocess.Popen': {
        'severity': 'HIGH',
        'message': 'subprocess.Popen(shell=True) is dangerous',
        'recommendation': 'Use shell=False and argument lists'
    },

    'subprocess.run': {
        'severity': 'HIGH',
        'message': 'subprocess.run(shell=True) allows injection',
        'recommendation': 'Avoid shell=True'
    },

    'pty.spawn': {
        'severity': 'HIGH',
        'message': 'pty.spawn executes external commands',
        'recommendation': 'Validate all user-controlled commands'
    },
}

# --- SQL injection (на уровне функций) ---
SQL_INJECTION_SOURCES = {
    'cursor.execute': {
        'severity': 'HIGH',
        'message': 'Potential SQL injection in cursor.execute()',
        'recommendation': 'Use parameterized queries'
    },

    'cursor.executemany': {
        'severity': 'HIGH',
        'message': 'Potential SQL injection in bulk SQL',
        'recommendation': 'Use parameterized queries'
    },
}

# --- Опасные операции с файлами ---
FILE_OPERATION_RISKS = {
    'open_write': {
        'pattern': r'open\(.+,\s*[\'"]w[\'"]\)',
        'severity': 'MEDIUM',
        'message': 'Writing to file with dynamically formed path',
        'recommendation': 'Validate or sanitize file paths'
    },

    'open_append': {
        'pattern': r'open\(.+,\s*[\'"]a[\'"]\)',
        'severity': 'LOW',
        'message': 'Appending to file with dynamic path',
        'recommendation': 'Check path safety'
    },
}
