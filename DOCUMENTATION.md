# Malicious Code Detector - Complete Documentation

**Three-Phase Compiler for Python Security Analysis**

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Project Structure](#project-structure)
3. [Three-Phase Compiler Architecture](#three-phase-compiler-architecture)
4. [Installation & Setup](#installation--setup)
5. [Usage Guide](#usage-guide)
6. [Features & Capabilities](#features--capabilities)
7. [Technical Implementation](#technical-implementation)
8. [Limitations](#limitations)
9. [Academic Justification](#academic-justification)

---

## Project Overview

### Purpose

A **three-phase compiler** designed for static analysis of Python code to detect security vulnerabilities and code quality issues. The system:

- ✅ **Lexical Analysis** - Tokenizes Python source code
- ✅ **Syntax Analysis** - Parses code into Abstract Syntax Tree (AST)
- ✅ **Semantic Analysis** - Detects vulnerability patterns using formal grammars

### What It Detects

- ❌ Dangerous functions (`eval()`, `exec()`, `pickle.loads()`)
- 🔐 Hard-coded secrets (API keys, passwords, AWS keys)
- 💉 SQL injection patterns
- 🐚 Command injection risks (`os.system()`, `subprocess` with `shell=True`)
- 🔒 Weak cryptography (MD5, SHA1)
- 🎲 Insecure randomness for security tokens
- 🌐 SSL/TLS verification disabled
- 📁 Path traversal vulnerabilities
- 🧮 High cyclomatic complexity functions
- 🔓 Unsafe deserialization
- 🕵️ Obfuscated code (base64-encoded execution)

### Key Statistics

- **24 Vulnerability Grammar Productions**
- **60+ Token Types** recognized by lexer
- **10 Vulnerability Categories** detected
- **3 Severity Levels**: ERROR, WARNING, INFO

---

## Project Structure

```
malicious_code_detector/
├── Backend/
│   ├── code_detector.py    # Main compiler (3 phases)
│   └── lexer.py            # Phase 1: Lexical analyzer
│
├── Frontend/
│   ├── web_app.py          # Flask web application
│   ├── app.js              # Frontend JavaScript
│   ├── style.css           # Styling
│   └── index.html          # Web interface
│
├── TestingFiles/
│   ├── test_file.py        # Comprehensive test suite
│   └── simple_test.py      # Simple examples
│
├── DOCUMENTATION.md        # This file
└── requirements.txt        # Python dependencies
```

---

## Three-Phase Compiler Architecture

### Architecture Diagram

```
Source Code (.py)
      ↓
┌─────────────────────────────────┐
│  PHASE 1: LEXICAL ANALYSIS      │
│  (lexer.py)                     │
│  - Tokenization                 │
│  - Position tracking            │
│  - Token classification         │
└─────────────────────────────────┘
      ↓ [Tokens]
┌─────────────────────────────────┐
│  PHASE 2: SYNTAX ANALYSIS       │
│  (ast.parse)                    │
│  - AST construction             │
│  - Syntax validation            │
│  - Tree building                │
└─────────────────────────────────┘
      ↓ [AST]
┌─────────────────────────────────┐
│  PHASE 3: SEMANTIC ANALYSIS     │
│  (code_detector.py)             │
│  - Pattern detection            │
│  - Grammar-based parsing        │
│  - Vulnerability reporting      │
└─────────────────────────────────┘
      ↓
  [Vulnerability Report]
```

---

### Phase 1: Lexical Analysis

**File:** `Backend/lexer.py`

**Purpose:** Break down Python source code into a stream of tokens

**Token Types (60+):**
- Keywords (`def`, `class`, `import`, `if`, `for`, etc.)
- Identifiers (variable names, function names)
- Literals (strings, numbers)
- Operators (`+`, `-`, `*`, `/`, `==`, `!=`, etc.)
- Delimiters (`(`, `)`, `[`, `]`, `{`, `}`, `:`, `,`, etc.)
- Special (comments, newlines, EOF)

**Example Tokenization:**

```python
Input:  def hello(name):
        
Tokens: [
    Token(KEYWORD, 'def', 1:1),
    Token(IDENTIFIER, 'hello', 1:5),
    Token(LPAREN, '(', 1:10),
    Token(IDENTIFIER, 'name', 1:11),
    Token(RPAREN, ')', 1:15),
    Token(COLON, ':', 1:16)
]
```

**Statistics Collected:**
- Total tokens count
- Keywords, identifiers, strings, numbers
- Operators and delimiters
- Comments

---

### Phase 2: Syntax Analysis (Parsing)

**Implementation:** Python's built-in `ast.parse()`

**Purpose:** Convert token stream into Abstract Syntax Tree

**Why `ast.parse()`?**
- ✅ Python grammar is complex (100+ production rules)
- ✅ Industry-standard approach (used by Pylint, Black, Bandit)
- ✅ Handles all Python 3.x syntax correctly
- ✅ Allows focus on security analysis, not reimplementing Python parser
- ✅ Equivalent to using yacc/bison in traditional compilers

**AST Node Types:**
- `Module` - Top-level program
- `FunctionDef` - Function definitions
- `ClassDef` - Class definitions
- `Call` - Function/method calls
- `Assign` - Variable assignments
- `BinOp` - Binary operations (+, -, *, etc.)
- `Constant` - Literal values
- `Import`, `ImportFrom` - Import statements
- And 80+ more node types...

**Statistics Collected:**
- Total AST nodes
- Functions and classes defined
- Function calls count
- Import statements
- Node type distribution

---

### Phase 3: Semantic Analysis

**File:** `Backend/code_detector.py`

**Purpose:** Detect security vulnerabilities and code quality issues

**Components:**

#### 1. CodeVisitor (AST Traversal)
Uses the **Visitor Pattern** to walk the AST:

```python
class CodeVisitor(ast.NodeVisitor):
    def visit_Call(self, node):      # Analyze function calls
    def visit_Assign(self, node):    # Analyze assignments
    def visit_Constant(self, node):  # Analyze constants
    def visit_FunctionDef(self, node): # Analyze functions
    # ... 15+ visitor methods
```

**Extracts semantic information:**
- String concatenation patterns
- Function call arguments
- Hard-coded values
- Import usage
- Control flow complexity

#### 2. VulnerabilityParser (Grammar-Based Detection)

**Formal Grammar Productions** for vulnerability patterns:

```
# SQL Injection (5 patterns)
VULN → SQL_CALL CONCAT_ARG     (ERROR: SQL injection via concatenation)
VULN → SQL_CALL FORMAT_ARG     (ERROR: SQL injection via .format())
VULN → SQL_CALL FSTRING_ARG    (ERROR: SQL injection via f-string)

# Code Execution (3 patterns)
VULN → EXEC_CALL DYNAMIC_ARG   (ERROR: Dynamic code execution)
VULN → EXEC_CALL B64_DECODE    (ERROR: Obfuscated code execution)
VULN → EVAL_CALL USER_INPUT    (ERROR: eval() with user input)

# Command Injection (3 patterns)
VULN → SYSTEM_CALL SHELL_TRUE CONCAT_ARG  (ERROR: Command injection)
VULN → OS_SYSTEM FORMAT_ARG    (ERROR: OS command with formatted input)
VULN → SUBPROCESS SHELL_TRUE   (WARNING: subprocess with shell=True)

# ... 15 more patterns covering:
# - Deserialization, Path Traversal, Secrets, Cryptography, Network Security
```

**LR-Style Parsing:**
- **ACTION Table**: Maps (state, token) → (SHIFT/REDUCE, value)
- **GOTO Table**: Maps (state, non-terminal) → next_state
- **Parse Algorithm**: Standard LR parser with state stack

**Example Parse Trace:**

```
Detecting: cursor.execute("SELECT * FROM users WHERE id=" + user_id)

Tokens: ["execute", "concat", "$"]

Step 1: SHIFT  - State 0, consume "execute" → push state 1
Step 2: SHIFT  - State 1, consume "concat" → push state 2  
Step 3: REDUCE - Apply: VULN → SQL_CALL CONCAT_ARG
        Stack: [0, 1, 2] → [0, 200]
        VULNERABILITY DETECTED: SQL injection via concatenation
```

---

## Installation & Setup

### Prerequisites

- Python 3.8+
- pip package manager

### Install Dependencies

```bash
cd malicious_code_detector
pip install -r requirements.txt
```

### Dependencies

```
Flask>=2.0.0         # Web framework
Werkzeug>=2.0.0      # WSGI utilities
```

---

## Usage Guide

### Command-Line Interface

**Analyze a single file:**
```bash
python Backend/code_detector.py TestingFiles/simple_test.py
```

**Analyze a directory:**
```bash
python Backend/code_detector.py path/to/python/project
```

**Example Output:**

```
[PHASE 1] Lexical Analysis: simple_test.py
  > Tokenized 73 tokens: 3 keywords, 20 identifiers, 4 strings, 0 numbers

[PHASE 2] Syntax Analysis (Parsing): simple_test.py
  > Built AST with 61 nodes: 1 functions, 0 classes, 6 function calls

[PHASE 3] Semantic Analysis (Vulnerability Detection): simple_test.py
  > Found 1 issues: 1 errors, 0 warnings, 0 info

======================================================================
THREE-PHASE COMPILATION RESULTS
======================================================================
[!] Findings: 1 ERROR(s), 0 WARNING(s), 0 INFO(s)
======================================================================
ERROR   simple_test.py:  11 GRAMMAR_VULN - SQL injection via concatenated query
```

### Web Interface

**Start the web application:**
```bash
python Frontend/web_app.py
```

**Access:** http://localhost:5000

**Features:**
- 📤 File upload interface
- 📊 Visual vulnerability dashboard
- 🌳 Grammar parser trace visualization
- 📈 Statistics charts (severity distribution, vulnerability types)
- 💾 JSON export functionality
- 🎨 Severity-based color coding (ERROR=red, WARNING=orange, INFO=blue)

---

## Features & Capabilities

### Vulnerability Detection

#### 1. SQL Injection (5 patterns)
```python
# ❌ ERROR: String concatenation
query = "SELECT * FROM users WHERE id=" + user_id
cursor.execute(query)

# ❌ ERROR: String formatting
cursor.execute("SELECT * FROM users WHERE name='%s'" % username)

# ❌ ERROR: f-string interpolation
cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
```

#### 2. Code Execution (3 patterns)
```python
# ❌ ERROR: Dynamic code execution
exec(user_input)

# ❌ ERROR: Obfuscated execution
exec(base64.b64decode(encoded_payload))

# ❌ ERROR: eval with user input
result = eval(request.args.get('expression'))
```

#### 3. Command Injection (3 patterns)
```python
# ❌ ERROR: Command injection via shell=True
subprocess.run("ls " + user_path, shell=True)

# ⚠️ WARNING: subprocess with shell=True
subprocess.run(["echo", "hello"], shell=True)

# ❌ ERROR: os.system with formatted input
os.system(f"rm -rf {user_directory}")
```

#### 4. Hard-coded Secrets (3 patterns)
```python
# ❌ ERROR: API key pattern
API_KEY = "sk_live_abc123def456ghi789"

# ❌ ERROR: AWS credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# ⚠️ WARNING: Suspicious token
token = "dGhpc2lzYXNlY3JldHRva2Vu"  # Long base64-like string
```

#### 5. Unsafe Deserialization (2 patterns)
```python
# ❌ ERROR: Pickle from untrusted source
data = pickle.loads(request.data)

# ❌ ERROR: Pickle from file upload
obj = pickle.load(open('user_upload.pkl', 'rb'))
```

#### 6. Path Traversal (3 patterns)
```python
# ⚠️ WARNING: Path concatenation
file_path = base_dir + "/" + user_filename
open(file_path, 'r')

# ⚠️ WARNING: Directory traversal
open("../../etc/passwd", 'r')
```

#### 7. Weak Cryptography (3 patterns)
```python
# ❌ ERROR: MD5 usage
hash = hashlib.md5(password.encode()).hexdigest()

# ❌ ERROR: SHA1 usage
digest = hashlib.sha1(data).digest()

# ❌ ERROR: Insecure random for tokens
token = ''.join(random.choice(string.ascii_letters) for _ in range(32))
```

#### 8. Network Security (2 patterns)
```python
# ❌ ERROR: SSL verification disabled
response = requests.get(url, verify=False)

# ⚠️ WARNING: Unverified HTTPS context
urllib.request.urlopen(url, context=ssl._create_unverified_context())
```

### Code Quality Analysis

#### Cyclomatic Complexity
```python
# Measured by counting:
# - if/elif statements
# - for/while loops
# - try/except blocks
# - and/or operators
# - with statements

# ⚠️ WARNING: Complexity >= 8
# ❌ ERROR: Complexity >= 15
```

### Parse Tree Visualization

**Web interface shows:**
- Complete token sequence
- Step-by-step SHIFT/REDUCE actions
- State stack evolution
- Symbol stack changes
- Grammar production applied
- Visual parse trace table with color coding

---

## Technical Implementation

### Lexer Implementation

**Character-by-character scanning:**
```python
class PythonLexer:
    def tokenize(self):
        while pos < len(source):
            if char in '"\'':
                token = self.read_string()
            elif char.isdigit():
                token = self.read_number()
            elif char.isalpha():
                token = self.read_identifier()
            # ... handle operators, delimiters, comments
```

**Features:**
- Handles triple-quoted strings
- Recognizes all number formats (binary, octal, hex, float, complex)
- Tracks line and column positions
- Differentiates keywords from identifiers

### Parser Implementation

**Grammar Productions Array:**
```python
VULNERABILITY_GRAMMAR = [
    ("VULN", ["SQL_CALL", "CONCAT_ARG"], "ERROR", "SQL injection..."),
    ("VULN", ["EXEC_CALL", "DYNAMIC_ARG"], "ERROR", "Dynamic code..."),
    # ... 24 total productions
]
```

**ACTION Table Structure:**
```python
VULN_ACTION_TABLE = {
    0: {"execute": ("shift", 1), "eval": ("shift", 11), ...},
    1: {"concat": ("shift", 2), "$": ("reduce", 0)},
    # ... state transitions
}
```

**Parse Algorithm:**
```python
def parse_pattern(tokens):
    stack = [0]  # State stack
    for token in tokens:
        action = ACTION_TABLE[stack[-1]][token]
        if action[0] == "shift":
            stack.append(action[1])
        elif action[0] == "reduce":
            production = GRAMMAR[action[1]]
            # Apply production, update stack
```

### AST Visitor Pattern

```python
class CodeVisitor(ast.NodeVisitor):
    def visit_Call(self, node):
        # Extract function name
        func_name = self._get_call_name(node.func)
        
        # Build context
        context = {
            "func_name": func_name,
            "has_concat": self._node_has_concatenation(node),
            "has_format": self._node_has_format(node),
            # ... more context
        }
        
        # Tokenize for grammar parser
        tokens = self.grammar_parser.tokenize_pattern("Call", context)
        
        # Parse with grammar
        finding = self.grammar_parser.parse_pattern(tokens)
        
        if finding:
            self.findings.append(finding)
```

---

## Limitations

### Scope Limitations

✅ **What it CAN do:**
- Static analysis of Python source code
- Detect pattern-based vulnerabilities
- Analyze code without execution
- Parse and tokenize Python syntax

❌ **What it CANNOT do:**
- Analyze non-Python languages (C++, Java, JavaScript, etc.)
- Detect runtime-only vulnerabilities
- Trace data flow across multiple files
- Understand complex business logic
- Detect zero-day exploits
- Analyze encrypted/packed code

### Detection Limitations

**False Positives:**
```python
# May be flagged as SQL injection but is actually safe:
cursor.execute("SELECT * FROM " + table_name)  # table_name from whitelist
```

**False Negatives:**
```python
# May miss cleverly obfuscated code:
getattr(__builtins__, 'eval')(encoded_string.decode('rot13'))
```

### Language Support

- ✅ Python 3.x only
- ❌ No Python 2.x support
- ❌ No cross-language analysis

---

## Academic Justification

### Why This Is a Legitimate Compiler

**Traditional Compiler Phases:**
1. ✅ **Lexical Analysis** - Implemented in `lexer.py`
2. ✅ **Syntax Analysis** - Uses `ast.parse()` (like yacc/bison)
3. ✅ **Semantic Analysis** - Implemented in `code_detector.py`
4. ❌ Code Generation - Not needed (static analysis tool)
5. ❌ Optimization - Not needed (static analysis tool)

**We implement the first 3 critical phases!**

### Using `ast.parse()` Is Acceptable

**Comparison to industry tools:**
- **GCC**: Uses flex (lexer) + bison (parser)
- **Clang**: Uses custom lexer + hand-written recursive descent parser
- **Python tools**: Use `ast.parse()` (Pylint, Black, Bandit, MyPy)
- **Our tool**: Uses custom lexer + `ast.parse()` + custom semantic analysis

**Why it's valid:**
- ✅ Professional compilers use parser generators (not hand-written parsers)
- ✅ Python's grammar has 331 productions - reimplementing provides no educational value
- ✅ Our innovation is in **Phase 3: Security Pattern Detection**
- ✅ We demonstrate understanding of lexing, parsing, and semantic analysis

### Compiler Theory Concepts Demonstrated

1. **Lexical Analysis**
   - Regular expressions for tokens
   - Finite automaton implementation
   - Maximal munch principle
   - Position tracking

2. **Syntax Analysis**
   - Context-free grammars
   - Abstract Syntax Trees
   - Tree construction
   - Syntax validation

3. **Semantic Analysis**
   - Grammar-based pattern matching
   - LR parsing with ACTION/GOTO tables
   - SHIFT/REDUCE operations
   - Symbol table concepts (imports, variables)
   - Visitor pattern for tree traversal

4. **Formal Language Theory**
   - Production rules
   - Derivations
   - Parse trees
   - Language recognition

---

## Comparison Table

| Feature | General-Purpose Compiler | Our Security Compiler |
|---------|-------------------------|----------------------|
| **Phase 1** | Tokenize source | ✅ Tokenize + statistics |
| **Phase 2** | Parse to AST | ✅ Parse to AST (ast.parse) |
| **Phase 3** | Type check, symbols | ✅ **Security patterns** |
| **Phase 4** | Generate code | ❌ Not needed |
| **Input** | Source code | Python (.py) files |
| **Output** | Executable | **Vulnerability report** |
| **Goal** | Create runnable program | **Detect security issues** |

---

## Summary

This malicious code detector is a **complete three-phase compiler** specialized for Python security analysis:

1. **Lexer** (Phase 1) - Tokenizes Python source
2. **Parser** (Phase 2) - Builds AST representation  
3. **Semantic Analyzer** (Phase 3) - Detects vulnerabilities using formal grammars

The system demonstrates deep understanding of:
- Compiler construction principles
- Formal language theory
- Static program analysis
- Pattern recognition via grammars
- Software security concepts

**Result:** A robust, academically sound tool that applies compiler theory to the practical problem of automated security analysis.

---

## Credits

**Project Type:** Academic/Educational Compiler Project
**Language Analyzed:** Python 3.x
**Compiler Phases:** 3 (Lexical, Syntax, Semantic)
**Detection Method:** Grammar-based LR parsing
**Primary Use Case:** Static security analysis

---

**Last Updated:** December 8, 2025
