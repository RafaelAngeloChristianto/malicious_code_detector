#!/usr/bin/env python3
"""
test_file.py - Comprehensive test suite for malicious code detector

Contains examples of ALL vulnerability patterns detectable by the grammar-based parser.
These snippets are intentionally insecure for testing purposes only.
DO NOT run this file in production or sensitive environments.

Vulnerability Categories Tested:
1. SQL Injection (5 patterns)
2. Code Execution (3 patterns)
3. Command Injection (3 patterns)
4. Unsafe Deserialization (2 patterns)
5. Path Traversal (3 patterns)
6. Hard-coded Secrets (3 patterns)
7. Hard-coded IP Addresses (1 pattern)
8. Weak Cryptography (3 patterns)
9. Insecure Network Operations (2 patterns)
10. High Complexity Functions
"""

import base64
import os
import pickle
import subprocess
import hashlib
import random
import requests
from pathlib import Path

# ============================================
# 1. SQL INJECTION PATTERNS (5 tests)
# ============================================

# Test 1.1: SQL injection via concatenated query
def test_sql_concat():
    """VULN -> SQL_CALL CONCAT_ARG"""
    username = input("Username: ")
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    # Simulated cursor
    class FakeCursor:
        def execute(self, q):
            print(f"Executing: {q}")
    cursor = FakeCursor()
    cursor.execute(query)  # Vulnerable!

# Test 1.2: SQL injection via formatted string
def test_sql_format():
    """VULN -> SQL_CALL FORMAT_ARG"""
    user_id = input("User ID: ")
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    class FakeCursor:
        def execute(self, q):
            print(f"Executing: {q}")
    cursor = FakeCursor()
    cursor.execute(query)  # Vulnerable!

# Test 1.3: SQL injection via f-string
def test_sql_fstring():
    """VULN -> SQL_CALL FSTRING_ARG"""
    table = input("Table: ")
    query = f"SELECT * FROM {table}"
    class FakeCursor:
        def executemany(self, q, data):
            print(f"Executing many: {q}")
    cursor = FakeCursor()
    cursor.executemany(query, [])  # Vulnerable!


# ============================================
# 2. CODE EXECUTION PATTERNS (3 tests)
# ============================================

# Test 2.1: Dynamic code execution
def test_exec_dynamic():
    """VULN -> EXEC_CALL DYNAMIC_ARG"""
    user_code = input("Enter Python code: ")
    exec(user_code)  # Extremely dangerous!

# Test 2.2: Obfuscated code execution via base64
def test_exec_b64():
    """VULN -> EXEC_CALL B64_DECODE"""
    encoded_payload = "cHJpbnQoJ21hbGljaW91cyBjb2RlJyk="
    exec(base64.b64decode(encoded_payload))  # Obfuscated execution!

# Test 2.3: eval() with user-controlled input
def test_eval_user_input():
    """VULN -> EVAL_CALL USER_INPUT"""
    user_expr = input("Enter expression: ")
    result = eval(user_expr)  # Code injection risk!
    return result


# ============================================
# 3. COMMAND INJECTION PATTERNS (3 tests)
# ============================================

# Test 3.1: Command injection via shell=True with concatenation
def test_subprocess_shell_concat():
    """VULN -> SYSTEM_CALL SHELL_TRUE CONCAT_ARG"""
    filename = input("Filename: ")
    cmd = "cat " + filename
    subprocess.run(cmd, shell=True)  # Command injection!

# Test 3.2: OS command with formatted input
def test_os_system_format():
    """VULN -> OS_SYSTEM FORMAT_ARG"""
    directory = input("Directory: ")
    os.system("ls {}".format(directory))  # Command injection!

# Test 3.3: subprocess with shell=True
def test_subprocess_shell():
    """VULN -> SUBPROCESS SHELL_TRUE"""
    subprocess.call("rm -rf /tmp/*", shell=True)  # Dangerous shell usage!
    subprocess.Popen("echo hello", shell=True)  # Also vulnerable!


# ============================================
# 4. UNSAFE DESERIALIZATION PATTERNS (2 tests)
# ============================================

# Test 4.1: Unsafe deserialization from untrusted source
def test_pickle_untrusted():
    """VULN -> PICKLE_LOAD UNTRUSTED_SOURCE"""
    with open("/tmp/untrusted_data.pkl", "rb") as f:
        data = pickle.load(f)  # Arbitrary code execution risk!
    return data

# Test 4.2: Pickle load from user input
def test_pickle_user_input():
    """VULN -> PICKLE_LOAD USER_INPUT"""
    user_data = input("Enter pickled data: ")
    obj = pickle.loads(user_data.encode())  # RCE vulnerability!
    return obj


# ============================================
# 5. PATH TRAVERSAL PATTERNS (3 tests)
# ============================================

# Test 5.1: Path traversal via concatenation
def test_file_concat():
    """VULN -> FILE_OPEN CONCAT_PATH"""
    user_file = input("Filename: ")
    path = "/var/www/" + user_file
    with open(path, 'r') as f:  # Path traversal risk!
        content = f.read()
    return content

# Test 5.2: File access with user-controlled path
def test_file_user_input():
    """VULN -> FILE_OPEN USER_INPUT"""
    filename = input("Enter file to read: ")
    with open(filename, 'r') as f:  # Direct path injection!
        data = f.read()
    return data

# Test 5.3: Directory traversal pattern detected
def test_path_dotdot():
    """VULN -> PATH_OP DOTDOT"""
    malicious_path = "../../../etc/passwd"
    p = Path(malicious_path)  # Directory traversal attempt!
    with open(malicious_path) as f:  # Also vulnerable!
        secrets = f.read()
    return secrets


# ============================================
# 6. HARD-CODED SECRETS PATTERNS (3 tests)
# ============================================

# Test 6.1: Hard-coded API key or secret token
def test_secret_pattern():
    """VULN -> ASSIGN SECRET_PATTERN"""
    api_key = "sk_live_1234567890abcdefghijklmnop"  # Hard-coded API key!
    secret_key = "mysecretpassword123"  # Hard-coded secret!
    password = "admin123"  # Hard-coded password!
    return api_key, secret_key, password

# Test 6.2: Hard-coded AWS access key
def test_aws_key():
    """VULN -> ASSIGN AWS_KEY"""
    AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # Hard-coded AWS key!
    AWS_SECRET = "AKIATESTKEYABCDEFGH12345"  # Another AWS key!
    return AWS_ACCESS_KEY, AWS_SECRET

# Test 6.3: Suspicious hard-coded token or credential
def test_long_token():
    """VULN -> ASSIGN LONG_TOKEN"""
    auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"  # Long base64 token!
    bearer_token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"  # Suspicious token!
    jwt_secret = "VGVzdGxvbmdlbmNvZGVkdG9rZW5leGFtcGxlAAAAAAAAAAAAAAA"  # Base64 secret!
    return auth_token, bearer_token, jwt_secret


# ============================================
# 7. HARD-CODED IP ADDRESSES (1 test)
# ============================================

# Test 7.1: Hard-coded IP address detected
def test_hardcoded_ip():
    """VULN -> STRING_LITERAL IP_PATTERN"""
    server_ip = "192.168.1.100"  # Hard-coded IP!
    database_host = "10.0.0.5"  # Another hard-coded IP!
    api_endpoint = "https://172.16.0.1/api"  # IP in URL!
    backup_server = "172.31.255.255"  # Yet another IP!
    return server_ip, database_host, api_endpoint, backup_server


# ============================================
# 8. WEAK CRYPTOGRAPHY PATTERNS (3 tests)
# ============================================

# Test 8.1: Weak cryptographic hash algorithm (MD5/SHA1)
def test_weak_hash():
    """VULN -> HASH_CALL WEAK_ALGO"""
    data = b"sensitive information"
    weak_hash1 = hashlib.md5(data).hexdigest()  # MD5 is broken!
    weak_hash2 = hashlib.sha1(data).hexdigest()  # SHA1 is weak!
    weak_hash3 = hashlib.new('md5', data)  # MD5 via new()!
    weak_hash4 = hashlib.new('sha1', data)  # SHA1 via new()!
    return weak_hash1, weak_hash2, weak_hash3, weak_hash4

# Test 8.2: Insecure random for cryptographic token generation
def test_insecure_random_token():
    """VULN -> RANDOM_CALL TOKEN_GEN"""
    # Using random module for security-sensitive values
    token = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(32))  # Insecure!
    secret = str(random.randint(100000, 999999))  # Predictable secret!
    password = str(random.random() * 1000000)  # Weak password generation!
    session_key = random.choice(['key1', 'key2', 'key3'])  # Insecure key selection!
    return token, secret, password, session_key

# Test 8.3: Predictable random seed
def test_predictable_seed():
    """VULN -> RANDOM_SEED PREDICTABLE"""
    import time
    random.seed(12345)  # Hard-coded seed!
    value1 = random.random()
    
    random.seed(time.time())  # Time-based seed is predictable!
    value2 = random.random()
    
    random.seed(42)  # Another hard-coded seed!
    value3 = random.random()
    
    return value1, value2, value3


# ============================================
# 9. INSECURE NETWORK OPERATIONS (2 tests)
# ============================================

# Test 9.1: SSL certificate verification disabled
def test_requests_verify_false():
    """VULN -> REQUESTS_CALL VERIFY_FALSE"""
    response1 = requests.get("https://example.com", verify=False)  # No SSL verification!
    response2 = requests.post("https://api.example.com/data", verify=False)  # Also vulnerable!
    response3 = requests.request("GET", "https://test.com", verify=False)  # Generic request!
    return response1, response2, response3

# Test 9.2: Insecure HTTPS context
def test_urllib_no_verify():
    """VULN -> URLLIB_CALL NO_VERIFY"""
    import urllib.request
    import ssl
    context = ssl._create_unverified_context()
    response1 = urllib.request.urlopen("https://example.com", context=context)  # Insecure!
    response2 = urllib.request.urlopen("https://api.example.com", context=context)  # Also insecure!
    return response1, response2


# ============================================
# 10. HIGH COMPLEXITY FUNCTIONS
# ============================================

def extremely_complex_function(a, b, c, d, e):
    """Function with cyclomatic complexity >= 15 (ERROR level)"""
    result = 0
    
    if a > 0:  # +1
        if b > 0:  # +1
            if c > 0:  # +1
                if d > 0:  # +1
                    if e > 0:  # +1
                        result += 1
                    else:
                        result -= 1
                else:
                    result += 2
            else:
                result -= 2
        else:
            result += 3
    else:
        result = 0
    
    for i in range(10):  # +1
        if i % 2 == 0:  # +1
            result += i
        else:
            result -= i
    
    while result > 100:  # +1
        if result % 3 == 0:  # +1
            result //= 3
        elif result % 2 == 0:  # +1
            result //= 2
        else:
            result -= 1
    
    try:  # +1
        if result < 0:  # +1
            raise ValueError("Negative result")
        elif result > 1000:  # +1
            raise ValueError("Too large")
    except ValueError:
        result = 0
    
    if result and result > 5:  # +1 (BoolOp)
        return result
    else:
        return 0


def moderately_complex_function(x):
    """Function with cyclomatic complexity >= 8 (WARNING level)"""
    if x < 0:  # +1
        return -x
    elif x == 0:  # +1
        return 0
    elif x < 10:  # +1
        return x * 2
    else:
        return x
    
    for i in range(x):  # +1
        if i % 2:  # +1
            x += 1
        else:
            x -= 1
    
    while x > 100:  # +1
        x //= 2
    
    with open("/dev/null", "w") as f:  # +1
        if x > 0:  # +1
            f.write(str(x))
    
    return x


# ============================================
# ADDITIONAL COMBINED TESTS
# ============================================

def combined_vulnerabilities():
    """Multiple vulnerabilities in one function for stress testing"""
    # Hard-coded credentials (Test 6.1)
    api_key = "sk_test_abcdefghijklmnop123456"
    
    # Weak crypto (Test 8.1)
    password_hash = hashlib.md5(b"password123").hexdigest()
    
    # Command injection (Test 3.2)
    user_input = input("Command: ")
    os.system(user_input)
    
    # SQL injection (Test 1.1)
    username = input("Username: ")
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    
    # Insecure network (Test 9.1)
    requests.get("https://api.example.com", verify=False)
    
    # Hard-coded IP (Test 7.1)
    server = "192.168.1.50"
    
    # Path traversal (Test 5.3)
    with open("../../secret.txt") as f:
        secret = f.read()
    
    # Insecure random (Test 8.2)
    token = str(random.randint(1000, 9999))
    
    return api_key, password_hash, query, server, secret, token


def all_sql_injections():
    """Demonstrate all SQL injection patterns"""
    # Pattern 1: Concatenation
    user = input("User: ")
    q1 = "SELECT * FROM users WHERE name = '" + user + "'"
    
    # Pattern 2: Format
    uid = input("ID: ")
    q2 = "SELECT * FROM users WHERE id = {}".format(uid)
    
    # Pattern 3: F-string
    table = input("Table: ")
    q3 = f"DELETE FROM {table}"
    
    class Cursor:
        def execute(self, q): pass
        def executemany(self, q, d): pass
    
    c = Cursor()
    c.execute(q1)
    c.execute(q2)
    c.executemany(q3, [])
    
    return q1, q2, q3


def all_code_execution():
    """Demonstrate all code execution patterns"""
    # Pattern 1: exec with dynamic input
    code = input("Code: ")
    exec(code)
    
    # Pattern 2: exec with base64
    encoded = "cHJpbnQoImhpIik="
    exec(base64.b64decode(encoded))
    
    # Pattern 3: eval with user input
    expr = input("Expression: ")
    eval(expr)


def all_command_injection():
    """Demonstrate all command injection patterns"""
    # Pattern 1: subprocess with shell=True and concat
    file = input("File: ")
    cmd1 = "cat " + file
    subprocess.run(cmd1, shell=True)
    
    # Pattern 2: os.system with format
    dir = input("Dir: ")
    os.system("ls {}".format(dir))
    
    # Pattern 3: subprocess with shell=True
    subprocess.call("whoami", shell=True)


if __name__ == "__main__":
    print("=" * 70)
    print("MALICIOUS CODE DETECTOR - COMPREHENSIVE TEST FILE")
    print("=" * 70)
    print("\nThis file contains examples of ALL detectable vulnerabilities.")
    print("Run the detector with: python code_detector.py test_file.py")
    print("\nExpected findings by category:")
    print("  1. SQL Injection:           3-5 patterns")
    print("  2. Code Execution:          3+ patterns")
    print("  3. Command Injection:       3+ patterns")
    print("  4. Unsafe Deserialization:  2+ patterns")
    print("  5. Path Traversal:          3+ patterns")
    print("  6. Hard-coded Secrets:      5+ patterns")
    print("  7. Hard-coded IPs:          4+ occurrences")
    print("  8. Weak Cryptography:       10+ patterns")
    print("  9. Insecure Network:        5+ patterns")
    print(" 10. High Complexity:         2 functions")
    print("\n" + "=" * 70)
    print("TOTAL EXPECTED: 40+ vulnerabilities detected!")
    print("=" * 70)
    print("\nNote: This file intentionally contains vulnerable code for testing.")
    print("DO NOT use these patterns in production code!")
