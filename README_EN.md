# Python Security Linter

---

## 🚀 Installation

```bash
git clone https://github.com/yourusername/python-security-linter.git
cd python-security-linter

# Optionally create a virtual environment
python3.13 -m venv .venv  # If you don't have python3.13, you need to install it
source .venv/bin/activate  # for Linux
```

## 🖥️ Usage

```bash
python3 main.py scan path/to/file_or_directory
```


## 🧩 Adding a New Rule

Rules are located in:

```bash
cd src/rules
```


The appropriate file is selected based on the check type — secrets, crypto, injections, etc.  
Rule structure is a regular Python dictionary.

### Example secret rule

```python
"my_access_key": {
    "pattern": r"AKIA[0-9A-Z]{16}",
    "severity": "CRITICAL",
    "message": "my Access Key ID found",
}
```
### Example injection rule
```python
'os.popen': {
    'severity': 'CRITICAL',
    'message': 'os.popen() executes shell commands',
    'recommendation': 'Avoid popen(); use subprocess with list args'
}
```

## Usage Example
Let's look at this insecure file

```python

import hashlib
import subprocess

# 1. Hardcoded secrets (should be found by regex)
API_KEY = "sk_live_51H8xKj2eZvKYlo2CTEST123"
AWS_KEY = "AKIA1234567890ABCDEF"
password = "admin12345"

# 2. Weak cryptography (should be found by AST)
def weak_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

def another_weak(data):
    return hashlib.sha1(data).digest()

# 3. Dangerous functions (should be found by AST)
def dangerous_eval(user_input):
    result = eval(user_input)  # CRITICAL
    return result

def dangerous_exec(code):
    exec(code)  # CRITICAL

# 4. Command injection (should be found by AST)
def run_command(filename):
    subprocess.run(f"cat {filename}", shell=True)  # HIGH

# 5. SQL injection via f-string (should be found by AST)
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # CRITICAL
    return query

# 6. JWT token (should be found by regex)
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

# 7. Database URL with credentials (should be found by regex)
DB_URL = "postgresql://admin:secretpass@localhost:5432/mydb"
```

### Output:
```bash
🔍 Scanning examples/ex_1.py...

================================================================================
🔒 Security Linter Results
================================================================================

Total issues found: 13
  🔴 Critical: 6
  🔴 High: 5
  🟡 Medium: 2
  🔵 Low: 0


📄 /Users/andre/PycharmProjects/seclint/examples/ex_1.py
--------------------------------------------------------------------------------

🔴 [CRITICAL] hardcoded_secret
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:8
   Stripe Live Secret Key found
   Code: API_KEY = "sk_live_51H8xKj2eZvKYlo2CTEST123"

🔴 [HIGH] hardcoded_secret
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:8
   Generic API key found
   Code: API_KEY = "sk_live_51H8xKj2eZvKYlo2CTEST123"

🔴 [CRITICAL] hardcoded_secret
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:9
   AWS Access Key ID found
   Code: AWS_KEY = "AKIA1234567890ABCDEF"

🔴 [HIGH] hardcoded_secret
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:10
   Hardcoded password found
   Code: password = "admin12345"

🟡 [MEDIUM] weak_crypto
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:14
   MD5 is cryptographically broken
   Code: hashlib.md5(data.encode())
   💡 Use SHA-256 or SHA-3

🟡 [MEDIUM] weak_crypto
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:17
   SHA-1 is deprecated
   Code: hashlib.sha1(data)
   💡 Use SHA-256 or SHA-3

🔴 [CRITICAL] dangerous_function
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:21
   eval() executes arbitrary code
   Code: eval(user_input)
   💡 Use ast.literal_eval() for safe evaluation

🔴 [CRITICAL] dangerous_function
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:25
   exec() executes arbitrary code
   Code: exec(code)
   💡 Avoid exec(). Refactor logic

🔴 [HIGH] command_injection
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:29
   subprocess with shell=True is dangerous
   Code: subprocess.run(f"cat {filename}", shell=True)
   💡 Use shell=False and pass args as list

🔴 [CRITICAL] sql_injection
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:33
   Potential SQL injection via f-string
   Code: f"SELECT * FROM users WHERE id = {user_id}"
   💡 Use parameterized queries

🔴 [CRITICAL] hardcoded_secret
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:37
   Discord Bot Token found
   Code: token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_...

🔴 [HIGH] hardcoded_secret
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:37
   JWT token found
   Code: token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_...

🔴 [HIGH] hardcoded_secret
   → /Users/andre/PycharmProjects/seclint/examples/ex_1.py:40
   Database URL with credentials
   Code: DB_URL = "postgresql://admin:secretpass@localhost:5432/mydb"

================================================================================
⚠️  Found critical/high severity issues - fix them ASAP!
================================================================================
```