# Malicious Code Detector

**Three-Phase Compiler for Python Security Analysis**

## Quick Start

### Installation
```bash
pip install -r requirements.txt
```

### Command-Line Usage
```bash
# Analyze a file
python Backend/code_detector.py TestingFiles/simple_test.py

# Analyze a directory
python Backend/code_detector.py path/to/project
```

### Web Interface
```bash
# Start web server
python Frontend/web_app.py

# Open browser to http://localhost:5000
```

## Project Structure

```
malicious_code_detector/
├── Backend/              # Compiler implementation
│   ├── code_detector.py  # Three-phase compiler
│   └── lexer.py          # Lexical analyzer
├── Frontend/             # Web interface
│   ├── web_app.py        # Flask application
│   ├── app.js            # Frontend JavaScript
│   ├── style.css         # Styling
│   └── index.html        # Web interface
├── TestingFiles/         # Test cases
│   ├── test_file.py      # Comprehensive tests
│   └── simple_test.py    # Simple examples
├── DOCUMENTATION.md      # Complete documentation
└── requirements.txt      # Dependencies
```

## Three Phases

1. **Phase 1: Lexical Analysis** - Tokenize Python source (60+ token types)
2. **Phase 2: Syntax Analysis** - Parse into AST (using ast.parse)  
3. **Phase 3: Enhanced Semantic Analysis** - Comprehensive analysis including:
   - **Security Vulnerability Detection** (24 grammar patterns)
   - **Symbol Table Management** (track all variables, functions, classes)
   - **Scope Resolution** (global, function, class scopes)
   - **Type Inference** (infer types from assignments)
   - **Undefined Variable Detection** (catch usage before definition)
   - **Duplicate Definition Detection** (find redefinitions)
   - **Control Flow Analysis** (missing returns, unused code)
   - **Code Complexity Tracking** (cyclomatic complexity)

## What It Detects

### Security Vulnerabilities
- SQL Injection
- Code Execution (eval/exec)
- Command Injection
- Hard-coded Secrets & API Keys
- Unsafe Deserialization (pickle)
- Path Traversal
- Weak Cryptography (MD5/SHA1)
- Network Security Issues (SSL verification)
- Insecure Random Number Generation

### Traditional Semantic Issues
- Undefined Variables
- Duplicate Definitions (functions, classes)
- Unused Variables & Parameters
- Missing Return Statements
- High Complexity Functions
- Type Mismatches (with inference)

## Documentation

### Main Documentation Files
- **DOCUMENTATION.md** - Complete project documentation
- **PHASE3_ENHANCED.md** - Detailed Phase 3 semantic analysis guide
- **PHASE3_QUICKREF.md** - Quick reference for Phase 3 features

### Topics Covered
- Architecture & Design
- Implementation Details
- Symbol Tables & Scopes
- Type Inference System
- Security Vulnerability Detection
- Usage Examples & Testing
- Academic Justification
- Technical Specifications

## Example Output

```
[PHASE 1] Lexical Analysis: example.py
  > Tokenized 73 tokens: 3 keywords, 20 identifiers, 4 strings

[PHASE 2] Syntax Analysis (Parsing): example.py
  > Built AST with 61 nodes: 1 functions, 6 calls

[PHASE 3] Enhanced Semantic Analysis: example.py
  > Security vulnerabilities: 2 found
  > Semantic issues: 5 found
  > Symbols tracked: 45 across 12 scopes

PHASE 3: ENHANCED SEMANTIC ANALYSIS SUMMARY
============================================================
Total Findings: 7
  - Vulnerability Findings: 2
  - Semantic Findings: 5

Semantic Analysis:
  - Undefined Variables: 1
  - Duplicate Definitions: 0
  - Unused Variables: 3

======================================================================
DETAILED FINDINGS
======================================================================
ERROR   example.py:  11 GRAMMAR_VULN - SQL injection via concatenated query
ERROR   example.py:  15 UNDEFINED_VARIABLE - Variable 'x' used before definition
WARNING example.py:  20 UNUSED_PARAMETER - Parameter 'unused' is never used
```

## Requirements

- Python 3.8+
- Flask 2.0+
- Werkzeug 2.0+

---

**For complete documentation, see DOCUMENTATION.md**
