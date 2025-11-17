🧠 Purpose

It’s a simple, explainable “Code Quality or Malicious Code Detector”.
It looks through Python files without running them and flags suspicious or dangerous patterns such as:

use of dangerous functions like eval() or exec()

possible hardcoded secrets (API keys, passwords)

risky commands like os.system() or subprocess(..., shell=True)

obfuscated or encoded code (e.g., exec(base64.b64decode(...)))

very complex functions (high cyclomatic complexity)

hardcoded IP addresses

suspicious module imports (like ctypes, socket, subprocess, paramiko)

⚙️ How it works

Input
Run it like this:
python code_detector.py <file_or_directory>
It scans:

A single Python file (if you give it one).

Or recursively scans all .py files in a directory.

Analysis types

AST-based analysis:
Uses Python’s built-in ast (Abstract Syntax Tree) to parse code safely and detect specific syntax patterns (like function calls to eval or os.system).

Regex/line-based heuristics:
Uses regular expressions to detect secrets, IPs, or obfuscation patterns in text lines.

Complexity analysis:
Estimates the complexity of each function based on branching statements (if, for, while, etc.).

Import checks:
Looks for suspicious imports often associated with malware or exploits.

Output

A human-readable report (printed to console).

A structured JSON report for programmatic use.

Example of output:
[!] Findings: 2 ERROR(s), 1 WARNING(s), 0 INFO(s)
ERROR   app.py:  14 EXEC_USAGE          - Use of eval detected.
WARNING app.py:   5 HARD_CODED_SECRET   - Possible hard-coded secret or token matched: password = "supersecret123"
...
🔍 What it scans

It only scans Python code — specifically files ending in .py.

It uses Python’s ast parser, which cannot parse or analyze other languages like:

C/C++

JavaScript

Java

HTML/CSS

Shell scripts

So if you point it at a directory with mixed codebases, it will skip anything that’s not a .py file.

🚫 Limitations

It’s static — it doesn’t execute the code, so it can’t detect runtime behavior.

It’s heuristic-based, meaning:

It might give false positives (mark safe code as suspicious).

It might miss cleverly hidden malicious code.

It’s Python-only — doesn’t support scanning for other programming languages.

✅ In summary
Feature	Description
Language	Scans only Python (.py) files
Type	Static analysis (no execution)
Checks for	eval, exec, os.system, pickle.loads, base64+exec, hardcoded secrets, IPs, suspicious imports, high complexity
Outputs	Console + JSON summary
Goal	Detect potentially malicious or unsafe code patterns in Python files