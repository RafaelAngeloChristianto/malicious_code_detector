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

# Parse Tree Visualization Feature

## Overview
The malicious code detector now includes a **grammar-based parser trace visualization** that shows exactly how the LR parser detects vulnerabilities step-by-step.

## What It Shows

### 1. **Parse Trace Components**
Each detected vulnerability now includes a complete parse trace showing:
- **Tokens**: The input token sequence extracted from the code
- **Parse Steps**: Detailed table of each parser action
- **State Transitions**: How the parser moves through states
- **Stack Evolution**: How the state and symbol stacks change
- **Grammar Productions**: Which grammar rules are applied

### 2. **Parser Actions**

#### SHIFT Actions
- **Action**: `SHIFT`
- **What it does**: Consumes a token from input and pushes a new state onto the stack
- **Visualization**: Shows the lookahead token being consumed and the next state

#### REDUCE Actions
- **Action**: `REDUCE`
- **What it does**: Applies a grammar production rule, recognizing a pattern
- **Visualization**: Shows:
  - The production being applied (e.g., `VULN -> SQL_CALL CONCAT_ARG`)
  - Stack changes (before/after the reduction)
  - Symbol stack changes (before/after)
  - GOTO state transition after reduction

### 3. **Parse Table Columns**

| Column | Description |
|--------|-------------|
| **Step** | Sequential step number in the parse |
| **Action** | SHIFT or REDUCE |
| **State** | Current parser state before action |
| **Lookahead** | Token being examined (for SHIFT) |
| **Production / Next State** | Grammar rule applied (REDUCE) or state transition (SHIFT) |
| **Stack** | State stack contents (before/after for REDUCE) |
| **Symbols** | Symbol stack contents (before/after for REDUCE) |
| **Remaining Input** | Tokens not yet consumed |

### 4. **Color Coding**
- 🔵 **Blue (SHIFT)**: Token consumption and state push
- 🔴 **Pink (REDUCE)**: Grammar rule application
- 🟡 **Yellow**: Token sequences
- 🟢 **Green**: Section headers and borders

## How to Use

1. **Upload a Python file** with potential vulnerabilities
2. **Scroll down** to the "🌳 Grammar Parser Trace" section
3. **Review parse traces** for each vulnerability detected via grammar rules
4. **Understand the detection** by following the step-by-step parser actions
5. **Toggle visibility** using the "Toggle Parse Trees" button if needed

## Example Parse Trace

When the detector finds SQL injection via concatenation:

```
Tokens: ["execute", "concat", "$"]

Step 1: SHIFT
  - State 0, lookahead "execute"
  - Push state 1
  
Step 2: SHIFT
  - State 1, lookahead "concat"
  - Push state 2
  
Step 3: REDUCE
  - Apply production: VULN -> SQL_CALL CONCAT_ARG
  - Stack: [0, 1, 2] → [0, 200]
  - GOTO state 200
  - VULNERABILITY DETECTED!
```

## Technical Details

### Grammar-Based Detection
The parser uses formal grammar productions defined in `VULNERABILITY_GRAMMAR`:
- Each production has: LHS (left-hand side), RHS (right-hand side), severity, message
- Productions define vulnerability patterns formally
- LR-style parsing uses ACTION and GOTO tables

### Parser Implementation
- **ACTION Table**: Maps (state, token) → (SHIFT/REDUCE, value)
- **GOTO Table**: Maps (state, non-terminal) → next_state
- **Standard LR Algorithm**: Same approach as compiler parsers

### Data Captured
Each parse trace includes:
- Complete token sequence
- Every SHIFT and REDUCE action
- State stack at each step
- Symbol stack evolution
- Remaining input at each step
- Final production that detected the vulnerability

## Benefits

1. **Transparency**: See exactly how vulnerabilities are detected
2. **Education**: Learn about formal parsing and compiler theory
3. **Debugging**: Verify detection accuracy and understand false positives
4. **Trust**: Understand the formal grammar basis for detections
5. **Research**: Analyze parser behavior for improving detection rules

## Future Enhancements

Potential improvements:
- Interactive parse tree diagram (visual tree structure)
- Animation of parser steps
- Ability to step through parsing manually
- Export parse traces for documentation
- Comparison of multiple parse traces
- Visualization of ACTION/GOTO table lookups

## Learn More

To understand the grammar-based detection approach:
1. Review `VULNERABILITY_GRAMMAR` in `code_detector.py`
2. Study `VULN_ACTION_TABLE` and `VULN_GOTO_TABLE`
3. See `VulnerabilityParser.parse_pattern()` method
4. Compare with traditional regex-based detection approaches
