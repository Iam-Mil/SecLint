"""
Тестовый файл с уязвимостями для проверки линтера
"""
import hashlib
import subprocess

# 1. Hardcoded secrets (должен найти regex)
API_KEY = "sk_live_51H8xKj2eZvKYlo2CTEST123"
AWS_KEY = "AKIA1234567890ABCDEF"
password = "admin12345"

# 2. Слабая криптография (должен найти AST)
def weak_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

def another_weak(data):
    return hashlib.sha1(data).digest()

# 3. Опасные функции (должен найти AST)
def dangerous_eval(user_input):
    result = eval(user_input)  # CRITICAL
    return result

def dangerous_exec(code):
    exec(code)  # CRITICAL

# 4. Command injection (должен найти AST)
def run_command(filename):
    subprocess.run(f"cat {filename}", shell=True)  # HIGH

# 5. SQL injection via f-string (должен найти AST)
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # CRITICAL
    return query

# 6. JWT token (должен найти regex)
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

# 7. Database URL with credentials (должен найти regex)
DB_URL = "postgresql://admin:secretpass@localhost:5432/mydb"