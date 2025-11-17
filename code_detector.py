#!/usr/bin/env python3
"""
code_detector.py - enhanced & fixed

- Uses ast.Constant (no ast.Str) to avoid deprecation warning.
- Adds robust SQL-string-construction detection (concatenation, f-strings,
  % formatting, .format()) and flags .execute(...) usages with non-constant SQL args.
- Maintains previous functionality: exec/pickle/obfuscation/secrets/complexity checks.
"""

import ast
import os
import re
import sys
import json
from typing import List, Dict, Any, Tuple

# ---------- Configurable thresholds ----------
COMPLEXITY_WARN = 8     # function complexity above this -> warn
COMPLEXITY_ERROR = 15   # function complexity above this -> error
HARDSECRET_MIN_LEN = 16 # min length to treat matched secret-like token as high-confidence

# ---------- Utility types ----------
SEVERITIES = ("INFO", "WARNING", "ERROR")

SQL_KEYWORDS_RE = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN|DROP|CREATE|ALTER|TRUNCATE)\b", re.IGNORECASE)

class CodeVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: List[Dict[str, Any]] = []
        self.current_function: str = "<module>"
        self.function_complexity: Dict[str, int] = {}
        self.imports: List[Tuple[str, str]] = []  # (full, localname)
        self.str_literals: List[str] = []
        self.call_names_seen: List[str] = []

    # Imports
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            mod = alias.name
            bound = alias.asname or alias.name.split(".")[0]
            self.imports.append((mod, bound))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            imported = f"{module}.{alias.name}" if module else alias.name
            bound = alias.asname or alias.name
            self.imports.append((imported, bound))
        self.generic_visit(node)

    # Handle string constants (py3.8+)
    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            self.str_literals.append(node.value)
        self.generic_visit(node)

    # Calls (exec, subprocess, execute, etc.)
    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node.func)
        if func_name:
            self.call_names_seen.append(func_name)

        # Build candidate names
        candidates = set()
        candidates.add(func_name)
        last_part = func_name.split(".")[-1] if func_name and "." in func_name else (func_name or "")
        if last_part:
            candidates.add(last_part)

        # resolve imports that may alias functions
        for imported_full, bound in getattr(self, "imports", []):
            if bound == last_part:
                if "." in imported_full:
                    candidates.add(imported_full)
                else:
                    candidates.add(f"{imported_full}.{last_part}")
            if bound == (func_name.split(".")[0] if "." in func_name else func_name):
                # attribute call on alias: alias.run -> realmodule.run
                if "." not in imported_full and "." in func_name:
                    remainder = func_name.split(".", 1)[1]
                    candidates.add(f"{imported_full}.{remainder}")

        # exec/eval/compile
        if any(c in ("eval", "exec", "compile", "execfile") for c in candidates):
            self._record("EXEC_USAGE",
                         f"Use of exec/eval/compile detected ({func_name}).",
                         node.lineno,
                         "ERROR" if any(c in ("exec", "eval") for c in candidates) else "WARNING")

        # subprocess with shell=True
        if any(c.startswith("subprocess.") or c in ("Popen", "run") for c in candidates):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._record("SUBPROCESS_SHELL",
                                 "subprocess called with shell=True (command injection risk).",
                                 node.lineno,
                                 "ERROR")

        # os.system / popen
        if any(c in ("os.system", "os.popen", "system", "popen") for c in candidates):
            self._record("OS_SYSTEM",
                         f"Call to {func_name} (platform command execution).",
                         node.lineno,
                         "WARNING")

        # pickle.load(s)
        if any(c.startswith("pickle.") and c.split(".")[-1] in ("load", "loads") for c in candidates):
            self._record("PICKLE_LOAD",
                         "Use of pickle.load(s) detected (unsafe when loading untrusted data).",
                         node.lineno,
                         "ERROR")

        # exec of base64-decoded content
        if "exec" in candidates and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Call):
                inner_name = self._get_call_name(arg.func)
                if inner_name and (inner_name.endswith("b64decode") or "base64" in inner_name):
                    self._record("OBF_EXEC_BASE64",
                                 "exec of base64-decoded string (possible obfuscation).",
                                 node.lineno,
                                 "ERROR")

        if func_name == "<unknown>":
            self._record("DYNAMIC_CALL",
                         "Call site with dynamic function expression (could hide dangerous call).",
                         node.lineno,
                         "INFO")

        # New: detect DB execute-like calls and SQL argument construction
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr.lower()
            if attr in ("execute", "executemany", "executescript"):
                # if there's a first arg
                if node.args:
                    first = node.args[0]
                    # if it's not a constant SQL string, but contains SQL keywords or looks constructed -> flag
                    if not self._is_constant_sql_string(first):
                        if self._node_contains_sql_keywords(first) or self._node_may_be_sql_construction(first):
                            self._record("SQL_INJECTION_RISK",
                                         f"Call to '{node.func.attr}' with non-constant/constructed SQL argument (possible SQL injection).",
                                         node.lineno,
                                         "ERROR")
        self.generic_visit(node)

    # Complexity and control flow
    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev = self.current_function
        self.current_function = node.name
        self.function_complexity[node.name] = 1
        self.generic_visit(node)
        self.current_function = prev

    def visit_If(self, node: ast.If):
        self._inc_complexity()
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        self._inc_complexity()
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor):
        self._inc_complexity()
        self.generic_visit(node)

    def visit_While(self, node: ast.While):
        self._inc_complexity()
        self.generic_visit(node)

    def visit_With(self, node: ast.With):
        self._inc_complexity()
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try):
        self._inc_complexity()
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp):
        self._inc_complexity()
        self.generic_visit(node)

    # Detect assignments that construct SQL-like strings
    def visit_Assign(self, node: ast.Assign):
        try:
            if node.value is not None:
                if self._node_may_be_sql_construction(node.value):
                    preview_targets = []
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            preview_targets.append(t.id)
                        elif isinstance(t, ast.Attribute):
                            preview_targets.append(t.attr)
                        else:
                            preview_targets.append("<complex-target>")
                    target_preview = ", ".join(preview_targets) or "<target>"
                    self._record("SQL_STRING_CONSTRUCTION",
                                 f"Assignment building SQL-like string into {target_preview} (concatenation/formatting detected).",
                                 node.lineno,
                                 "ERROR")
        except Exception:
            pass
        self.generic_visit(node)

    # f-strings
    def visit_JoinedStr(self, node: ast.JoinedStr):
        try:
            has_formatted = any(isinstance(v, ast.FormattedValue) for v in node.values)
            literal_parts = "".join([v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else "" for v in node.values])
            if has_formatted and SQL_KEYWORDS_RE.search(literal_parts):
                self._record("FSTRING_SQL_CONSTRUCTION",
                             "f-string contains SQL keywords and expression interpolation (possible SQL injection).",
                             node.lineno,
                             "ERROR")
        except Exception:
            pass
        self.generic_visit(node)

    # Helpers
    def _inc_complexity(self):
        if self.current_function not in self.function_complexity:
            self.function_complexity[self.current_function] = 1
        self.function_complexity[self.current_function] += 1

    def _get_call_name(self, func_node) -> str:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            parts = []
            cur = func_node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
                return ".".join(reversed(parts))
        return "<unknown>"

    def _node_is_constant_string(self, node) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        return False

    def _is_constant_sql_string(self, node) -> bool:
        if self._node_is_constant_string(node):
            text = node.value
            return bool(SQL_KEYWORDS_RE.search(text))
        return False

    def _extract_literal_from_node(self, node) -> str:
        if node is None:
            return ""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._extract_literal_from_node(node.left) + self._extract_literal_from_node(node.right)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return self._extract_literal_from_node(node.func.value)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            # left % right
            return self._extract_literal_from_node(node.left)
        return ""

    def _node_contains_sql_keywords(self, node) -> bool:
        lit = self._extract_literal_from_node(node)
        return bool(SQL_KEYWORDS_RE.search(lit))

    def _node_may_be_sql_construction(self, node) -> bool:
        # f-strings
        if isinstance(node, ast.JoinedStr):
            has_formatted = any(isinstance(v, ast.FormattedValue) for v in node.values)
            if has_formatted and self._node_contains_sql_keywords(node):
                return True

        # concatenation using +
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = node.left, node.right
            # if either side is a Name/Call/Attr/Subscript and any literal part contains SQL -> suspect
            if (isinstance(left, (ast.Name, ast.Call, ast.Attribute, ast.Subscript)) or
                isinstance(right, (ast.Name, ast.Call, ast.Attribute, ast.Subscript))):
                if self._node_contains_sql_keywords(node):
                    return True
            # or if either side is a formatted string or non-constant
            if (not self._node_is_constant_string(left) or not self._node_is_constant_string(right)) and self._node_contains_sql_keywords(node):
                return True

        # % formatting
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            if self._node_is_constant_string(node.left) and not self._node_is_constant_string(node.right):
                left_text = node.left.s if isinstance(node.left, ast.Constant) else ""
                if SQL_KEYWORDS_RE.search(left_text):
                    return True

        # format() usage
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            fmt = node.func.value
            if self._node_is_constant_string(fmt):
                fmt_text = fmt.value if isinstance(fmt, ast.Constant) else ""
                if SQL_KEYWORDS_RE.search(fmt_text):
                    for a in node.args:
                        if not self._node_is_constant_string(a):
                            return True

        return False

    def _record(self, code: str, message: str, lineno: int, severity: str = "WARNING"):
        if severity not in SEVERITIES:
            severity = "WARNING"
        self.findings.append({
            "file": self.filename,
            "lineno": lineno,
            "code": code,
            "message": message,
            "severity": severity
        })


# ---------- Regex / line heuristics ----------
SECRET_PATTERNS = [
    re.compile(r"(?:api[_-]?key|secret[_-]?key|aws[_-]?secret|token|passwd|password)\s*[:=]\s*['\"]([A-Za-z0-9\-_+=/]{8,})['\"]", re.IGNORECASE),
    re.compile(r"(?P<tok>AKIA[0-9A-Z]{16})"),
    re.compile(r"['\"]([A-Za-z0-9+/=]{20,})['\"]")
]

IP_PORT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b(?::\d{1,5})?")
OBFUSCATION_CALLS = [
    re.compile(r"base64\.b64decode"),
    re.compile(r"exec\("),
    re.compile(r"marshal\.loads"),
    re.compile(r"__import__\("),
]

# ---------- Detector ----------
class Detector:
    def __init__(self, path: str):
        self.path = path
        self.reports: List[Dict[str, Any]] = []

    def run(self):
        targets = []
        if os.path.isdir(self.path):
            for root, _, files in os.walk(self.path):
                for f in files:
                    if f.endswith(".py"):
                        targets.append(os.path.join(root, f))
        elif os.path.isfile(self.path) and self.path.endswith(".py"):
            targets = [self.path]
        else:
            print(f"[!] No Python files found at: {self.path}")
            return

        for fn in targets:
            try:
                with open(fn, "r", encoding="utf-8") as fh:
                    src = fh.read()
                self._analyze_file(fn, src)
            except Exception as e:
                self.reports.append({
                    "file": fn,
                    "error": str(e)
                })

        self._print_report()

    def _analyze_file(self, filename: str, source: str):
        # AST
        try:
            tree = ast.parse(source, filename=filename)
            visitor = CodeVisitor(filename)
            visitor.visit(tree)
            for f in visitor.findings:
                self.reports.append(f)

            # complexity
            for fname, comp in visitor.function_complexity.items():
                if comp >= COMPLEXITY_ERROR:
                    self.reports.append({
                        "file": filename,
                        "lineno": 0,
                        "code": "HIGH_COMPLEXITY",
                        "message": f"Function '{fname}' complexity={comp} (>= {COMPLEXITY_ERROR}).",
                        "severity": "ERROR"
                    })
                elif comp >= COMPLEXITY_WARN:
                    self.reports.append({
                        "file": filename,
                        "lineno": 0,
                        "code": "HIGH_COMPLEXITY",
                        "message": f"Function '{fname}' complexity={comp} (>= {COMPLEXITY_WARN}).",
                        "severity": "WARNING"
                    })
        except SyntaxError as se:
            self.reports.append({
                "file": filename,
                "lineno": se.lineno,
                "code": "SYNTAX_ERROR",
                "message": f"Syntax error while parsing: {se.msg}",
                "severity": "ERROR"
            })
            return

        # Line heuristics
        lines = source.splitlines()
        for i, line in enumerate(lines, start=1):
            for pat in SECRET_PATTERNS:
                m = pat.search(line)
                if m:
                    token = None
                    if m.groupdict():
                        if "tok" in m.groupdict():
                            token = m.group("tok")
                        else:
                            for name, val in m.groupdict().items():
                                if val:
                                    token = val
                                    break
                    if not token:
                        for g in m.groups():
                            if g:
                                token = g
                                break
                    severity = "ERROR" if token and len(token) >= HARDSECRET_MIN_LEN else "WARNING"
                    self.reports.append({
                        "file": filename,
                        "lineno": i,
                        "code": "HARD_CODED_SECRET",
                        "message": f"Possible hard-coded secret or token matched: {m.group(0).strip()[:120]}",
                        "severity": severity
                    })

            if IP_PORT_RE.search(line):
                self.reports.append({
                    "file": filename,
                    "lineno": i,
                    "code": "HARD_CODED_IP",
                    "message": f"Hard-coded IP or host pattern found in string/line: {line.strip()[:120]}",
                    "severity": "WARNING"
                })

            for op in OBFUSCATION_CALLS:
                if op.search(line):
                    self.reports.append({
                        "file": filename,
                        "lineno": i,
                        "code": "OBFUSCATION_PATTERN",
                        "message": f"Obfuscation-related pattern {op.pattern} found.",
                        "severity": "ERROR"
                    })

        # Imports heuristics
        suspicious_modules = {"ctypes", "socket", "subprocess", "pty", "pwn", "paramiko", "ftplib"}
        # Use visitor imports if available
        try:
            visitor_imports = visitor.imports
        except Exception:
            visitor_imports = []
        for mod, alias in visitor_imports:
            base = mod.split(".")[0]
            if base in suspicious_modules:
                self.reports.append({
                    "file": filename,
                    "lineno": 0,
                    "code": "SUSPICIOUS_IMPORT",
                    "message": f"Suspicious import '{mod}' detected (alias '{alias}').",
                    "severity": "WARNING"
                })

        # Encoded strings
        try:
            for s in visitor.str_literals:
                if len(s) >= 50 and re.fullmatch(r"[A-Za-z0-9+/= \n\r]{50,}", s):
                    self.reports.append({
                        "file": filename,
                        "lineno": 0,
                        "code": "LONG_ENCODED_STRING",
                        "message": f"Long string literal possibly containing encoded data or token (len={len(s)}).",
                        "severity": "WARNING"
                    })
        except Exception:
            pass

        # Two-pass obfuscation
        if any(op.search(source) for op in OBFUSCATION_CALLS) and "exec(" in source:
            self.reports.append({
                "file": filename,
                "lineno": 0,
                "code": "OBFUSCATION_COMBO",
                "message": "Detected base64/marshal/__import__ patterns and exec in source (possible obfuscation).",
                "severity": "ERROR"
            })

    def _print_report(self):
        if not self.reports:
            print("[+] No issues found.")
            return

        severity_rank = {"ERROR": 3, "WARNING": 2, "INFO": 1}
        sorted_reports = sorted(self.reports,
                                key=lambda r: (-severity_rank.get(r.get("severity", "INFO"), 1),
                                               r.get("file", ""),
                                               r.get("lineno", 0)))
        errors = sum(1 for r in sorted_reports if r.get("severity") == "ERROR")
        warns = sum(1 for r in sorted_reports if r.get("severity") == "WARNING")
        infos = sum(1 for r in sorted_reports if r.get("severity") == "INFO")
        print(f"[!] Findings: {errors} ERROR(s), {warns} WARNING(s), {infos} INFO(s)")

        for r in sorted_reports:
            f = r.get("file", "<unknown>")
            ln = r.get("lineno", 0)
            sev = r.get("severity", "INFO")
            code = r.get("code", "ISSUE")
            msg = r.get("message", "")
            print(f"{sev:7} {f}:{ln:4} {code:20} - {msg}")

        try:
            j = json.dumps(sorted_reports, indent=2)
            print("\n=== JSON REPORT ===")
            print(j)
        except Exception:
            pass


# ---------- CLI ----------
def main(argv):
    if len(argv) < 2:
        print("Usage: python code_detector.py <file_or_directory>")
        print("Example: python code_detector.py ./my_project")
        sys.exit(1)
    target = argv[1]
    det = Detector(target)
    det.run()

if __name__ == "__main__":
    main(sys.argv)
