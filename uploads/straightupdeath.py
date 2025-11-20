#!/usr/bin/env python3
"""
straightupdeath.py - collection of small examples demonstrating many insecurity/vulnerability patterns

These snippets are intentionally insecure and only exist as static examples for the detector.
Do NOT run this file in a sensitive environment.
"""

import base64
import os
import pickle
import marshal
import subprocess
import hashlib
import random
import tempfile
import requests
import yaml
import ctypes
import socket
try:
    import paramiko
except Exception:
    paramiko = None


# 1) exec/eval usage with user input
user_code = input("Enter code to run: ")
# Dangerous: directly executing user-provided code
exec(user_code)


# 2) eval of constructed string
name = input("name: ")
greeting = "'Hello, ' + name"
print(eval(greeting))


# 3) compile + exec and exec of base64 decoded string
compiled = compile("print('compiled')", "<string>", "exec")
exec(compiled)
enc = base64.b64encode(b"print('hello from b64')").decode()
exec(base64.b64decode(enc))


# 4) subprocess with shell=True and os.system
subprocess.run("ls -la", shell=True)
os.system("echo hello")
os.popen("uname -a")


# 5) pickle / marshal unsafe deserialization
data = pickle.dumps({'a':1})
obj = pickle.loads(data)
mal = marshal.dumps((1,2,3))
marshal.loads(mal)


# 6) Hard-coded secrets & tokens
API_KEY = "AKIAABCDEFGHIJKLMNOP"
PASSWORD = "supersecretpassword12345"
LONG_TOKEN = """VGVzdGxvbmdlbmNvZGVkdG9rZW5leGFtcGxlAAAAAAAAAAAAAAA"""


# 7) Hard-coded IP
HOST = "192.168.1.100:8080"


# 8) SQL string construction + execute
user_id = input("user id: ")
query = "SELECT * FROM users WHERE id = " + user_id
# pretend cursor
class FakeCursor:
    def execute(self, q):
        print("exec->", q)

cur = FakeCursor()
cur.execute(query)

# f-string SQL
del_q = f"DELETE FROM users WHERE id={user_id}"
cur.execute(del_q)


# 9) requests with verify=False
try:
    resp = requests.get("https://example.com", verify=False)
except Exception:
    resp = None


# 10) yaml.load (unsafe loader)
yaml_data = "!!python/object/apply:os.system [\"echo hacked\"]"
try:
    yaml.load(yaml_data, Loader=None)
except Exception:
    pass


# 11) Weak hashing
pw_hash = hashlib.md5(b"password").hexdigest()


# 12) Using random for token generation (insecure)
token = str(random.randint(0, 10**6))


# 13) tempfile.mktemp (insecure)
tmp = tempfile.mktemp()


# 14) Using assert for security logic
def check_admin(u):
    # pretend check
    return u == "admin"

user = input("user: ")
assert check_admin(user), "must be admin"


# 15) Path traversal examples
filename = input("file: ")
with open(filename, 'r') as fh:
    pass

with open('../etc/passwd', 'r') as fh:
    pass


# 16) eval/exec with globals/locals
code = "print('hi')"
eval(code, globals(), locals())


# 17) Removing files based on user input (dangerous)
rmf = input("file to remove: ")
try:
    os.remove(rmf)
except Exception:
    pass


# 18) Using ctypes to load arbitrary libraries
# Demonstration import only; do not run arbitrary load
try:
    ctypes.CDLL("/tmp/some.so")
except Exception:
    pass


# 19) Network socket usage
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(("10.0.0.1", 22))
except Exception:
    pass


# 20) Paramiko usage example (suspicious import)
try:
    if paramiko:
        ssh = paramiko.SSHClient()
except Exception:
    pass


# 21) OS command composition from variables
cmd = "rm -rf " + input("target: ")
subprocess.Popen(cmd, shell=True)


print("straightupdeath demo complete")
