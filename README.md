# Python Security Linter

---

## 🚀 Установка

```bash
git clone https://github.com/yourusername/python-security-linter.git
cd python-security-linter

# Опционально создать виртуальное окружение 
python3.13 -m venv .venv  # Если нету python3.13, то его надо установить
source .venv/bin/activate  # для linux
```

## 🖥️ Использование

```bash
python3 main.py scan path/to/file_or_directory
```


## 🧩 Добавление нового правила

Правила расположены в:

```bash
cd src/rules
```


Нужный файл выбирается по типу проверки — secrets, crypto, injections и т.д.  
Структура правила — обычный Python-словарь.

### Пример secret-правила

```python
"my_access_key": {
    "pattern": r"AKIA[0-9A-Z]{16}",
    "severity": "CRITICAL",
    "message": "my Access Key ID found",
}
```
### Пример injection-правила
```python
'os.popen': {
    'severity': 'CRITICAL',
    'message': 'os.popen() executes shell commands',
    'recommendation': 'Avoid popen(); use subprocess with list args'
}
```

## Пример работы
Рассмотрим вот такой небезопасный файл 

```python

import hashlib
import subprocess

# 1. Hardcoded secrets (regex)
API_KEY = "sk_live_51H8xKj2eZvKYlo2CTEST123"
AWS_KEY = "AKIA1234567890ABCDEF"
password = "admin12345"

# 2. Weak crypto (AST)
def weak_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

def another_weak(data):
    return hashlib.sha1(data).digest()

# 3. Dangerous functions (AST)
def dangerous_eval(user_input):
    result = eval(user_input)
    return result

def dangerous_exec(code):
    exec(code)

# 4. Command injection (AST)
def run_command(filename):
    subprocess.run(f"cat {filename}", shell=True)

# 5. SQL injection via f-string (AST)
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# 6. JWT token (regex)
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

# 7. Database URL with credentials (regex)
DB_URL = "postgresql://admin:secretpass@localhost:5432/mydb"
```

### Вывод:
```
================================================================================
Security Scan Results
================================================================================

Total issues: 13
  Critical: 6
  High: 5
  Medium: 2
  Low: 0


/Users/andre/PycharmProjects/seclint/examples/ex_1.py
--------------------------------------------------------------------------------

[CRITICAL] hardcoded_secret
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:5
   Stripe Live Secret Key found
  Code: API_KEY = "sk_live_51H8xKj2eZvKYlo2CTEST123"

[HIGH] hardcoded_secret
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:5
   Generic API key found
  Code: API_KEY = "sk_live_51H8xKj2eZvKYlo2CTEST123"

[CRITICAL] hardcoded_secret
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:6
   AWS Access Key ID found
  Code: AWS_KEY = "AKIA1234567890ABCDEF"

[HIGH] hardcoded_secret
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:7
   Hardcoded password found
  Code: password = "admin12345"

[MEDIUM] weak_crypto
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:11
   MD5 is cryptographically broken
  Code: hashlib.md5(data.encode())
  Fix: Use SHA-256 or SHA-3

[MEDIUM] weak_crypto
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:14
   SHA-1 is deprecated
  Code: hashlib.sha1(data)
  Fix: Use SHA-256 or SHA-3

[CRITICAL] dangerous_function
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:18
   eval() executes arbitrary code
  Code: eval(user_input)
  Fix: Use ast.literal_eval() for safe evaluation

[CRITICAL] dangerous_function
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:22
   exec() executes arbitrary code
  Code: exec(code)
  Fix: Avoid exec(). Refactor logic

[HIGH] command_injection
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:26
   subprocess with shell=True is dangerous
  Code: subprocess.run(f"cat {filename}", shell=True)
  Fix: Use shell=False and pass args as list

[CRITICAL] sql_injection
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:30
   Potential SQL injection via f-string
  Code: f"SELECT * FROM users WHERE id = {user_id}"
  Fix: Use parameterized queries

[CRITICAL] hardcoded_secret
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:34
   Discord Bot Token found
  Code: token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_...

[HIGH] hardcoded_secret
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:34
   JWT token found
  Code: token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_...

[HIGH] hardcoded_secret
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:37
   Database URL with credentials
  Code: DB_URL = "postgresql://admin:secretpass@localhost:5432/mydb"

================================================================================
WARNING: Found critical/high severity issues
================================================================================

```