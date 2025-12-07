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

1. **Lexical Analysis** - Tokenize Python source (60+ token types)
2. **Syntax Analysis** - Parse into AST (using ast.parse)
3. **Semantic Analysis** - Detect vulnerabilities (24 grammar patterns)

## What It Detects

- SQL Injection
- Code Execution (eval/exec)
- Command Injection
- Hard-coded Secrets
- Unsafe Deserialization
- Path Traversal
- Weak Cryptography
- Network Security Issues
- High Complexity Functions

## Documentation

See **DOCUMENTATION.md** for complete details on:
- Architecture & Design
- Implementation Details
- Usage Examples
- Academic Justification
- Technical Specifications

## Example Output

```
[PHASE 1] Lexical Analysis: example.py
  > Tokenized 73 tokens: 3 keywords, 20 identifiers, 4 strings

[PHASE 2] Syntax Analysis (Parsing): example.py
  > Built AST with 61 nodes: 1 functions, 6 calls

[PHASE 3] Semantic Analysis (Vulnerability Detection): example.py
  > Found 1 issues: 1 errors, 0 warnings, 0 info

======================================================================
THREE-PHASE COMPILATION RESULTS
======================================================================
ERROR   example.py:  11 GRAMMAR_VULN - SQL injection via concatenated query
```

## Requirements

- Python 3.8+
- Flask 2.0+
- Werkzeug 2.0+

---

**For complete documentation, see DOCUMENTATION.md**
