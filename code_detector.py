#!/usr/bin/env python3
"""
code_detector.py - GRAMMAR-BASED PARSER for Vulnerability Detection

- Formal grammar productions defining vulnerability patterns
- LR-style parsing with ACTION/GOTO tables (dictionaries)
- Uses same algorithm as examplecode.py but for security analysis
- No regex pattern matching - pure grammar-based approach
"""

import ast
import os
import sys
import json
from typing import List, Dict, Any, Tuple, Optional

# ---------- Configurable thresholds ----------
COMPLEXITY_WARN = 8     # function complexity above this -> warn
COMPLEXITY_ERROR = 15   # function complexity above this -> error

# ---------- Utility types ----------
SEVERITIES = ("INFO", "WARNING", "ERROR")

# ============================================
# VULNERABILITY DETECTION GRAMMAR & TABLES
# ============================================
# Grammar productions for vulnerability patterns
# Format: (LHS, RHS_list, severity, message)
VULNERABILITY_GRAMMAR = [
    # SQL Injection patterns (0-4)
    ("VULN", ["SQL_CALL", "CONCAT_ARG"], "ERROR", "SQL injection via concatenated query"),
    ("VULN", ["SQL_CALL", "FORMAT_ARG"], "ERROR", "SQL injection via formatted string"),
    ("VULN", ["SQL_CALL", "FSTRING_ARG"], "ERROR", "SQL injection via f-string"),
    ("VULN", ["SQL_VAR", "CONCAT_OP", "USER_INPUT"], "ERROR", "SQL string concatenation with user input"),
    ("VULN", ["SQL_ASSIGN", "CONCAT_OP"], "ERROR", "SQL string construction via concatenation"),
    
    # Code execution patterns (5-7)
    ("VULN", ["EXEC_CALL", "DYNAMIC_ARG"], "ERROR", "Dynamic code execution detected"),
    ("VULN", ["EXEC_CALL", "B64_DECODE"], "ERROR", "Obfuscated code execution"),
    ("VULN", ["EVAL_CALL", "USER_INPUT"], "ERROR", "eval() with user-controlled input"),
    
    # Command injection patterns (8-10)
    ("VULN", ["SYSTEM_CALL", "SHELL_TRUE", "CONCAT_ARG"], "ERROR", "Command injection via shell=True"),
    ("VULN", ["OS_SYSTEM", "FORMAT_ARG"], "ERROR", "OS command with formatted input"),
    ("VULN", ["SUBPROCESS", "SHELL_TRUE"], "WARNING", "subprocess with shell=True"),
    
    # Deserialization patterns (11-12)
    ("VULN", ["PICKLE_LOAD", "UNTRUSTED_SOURCE"], "ERROR", "Unsafe deserialization"),
    ("VULN", ["PICKLE_LOAD", "USER_INPUT"], "ERROR", "Pickle load from user input"),
    
    # Path traversal patterns (13-15)
    ("VULN", ["FILE_OPEN", "CONCAT_PATH"], "WARNING", "Path traversal via concatenation"),
    ("VULN", ["FILE_OPEN", "USER_INPUT"], "WARNING", "File access with user-controlled path"),
    ("VULN", ["PATH_OP", "DOTDOT"], "WARNING", "Directory traversal pattern detected"),
    
    # Hard-coded secrets (16-18)
    ("VULN", ["ASSIGN", "SECRET_PATTERN"], "ERROR", "Hard-coded API key or secret token"),
    ("VULN", ["ASSIGN", "AWS_KEY"], "ERROR", "Hard-coded AWS access key"),
    ("VULN", ["ASSIGN", "LONG_TOKEN"], "WARNING", "Suspicious hard-coded token or credential"),
    
    # Hard-coded IP addresses (19)
    ("VULN", ["STRING_LITERAL", "IP_PATTERN"], "WARNING", "Hard-coded IP address detected"),
    
    # Insecure cryptography (20-22)
    ("VULN", ["HASH_CALL", "WEAK_ALGO"], "ERROR", "Weak cryptographic hash algorithm (MD5/SHA1)"),
    ("VULN", ["RANDOM_CALL", "TOKEN_GEN"], "ERROR", "Insecure random for cryptographic token generation"),
    ("VULN", ["RANDOM_SEED", "PREDICTABLE"], "WARNING", "Predictable random seed"),
    
    # Insecure network operations (23-24)
    ("VULN", ["REQUESTS_CALL", "VERIFY_FALSE"], "ERROR", "SSL certificate verification disabled"),
    ("VULN", ["URLLIB_CALL", "NO_VERIFY"], "WARNING", "Insecure HTTPS context"),
]

# ACTION table for vulnerability pattern recognition
# Maps (state, token) -> (action, next_state/production)
VULN_ACTION_TABLE = {
    0: {
        "execute": ("shift", 1),
        "executemany": ("shift", 1),
        "exec": ("shift", 10),
        "eval": ("shift", 11),
        "subprocess": ("shift", 20),
        "os.system": ("shift", 30),
        "pickle.load": ("shift", 40),
        "open": ("shift", 50),
        "Path": ("shift", 50),
        "assign": ("shift", 60),
        "string": ("shift", 70),
        "hashlib": ("shift", 80),
        "random": ("shift", 90),
        "requests": ("shift", 100),
        "urllib": ("shift", 110),
    },
    1: {  # After SQL execute method
        "concat": ("shift", 2),
        "format": ("shift", 3),
        "fstring": ("shift", 4),
        "$": ("reduce", 0),
    },
    2: {  # SQL + concatenation
        "$": ("reduce", 0),
    },
    3: {  # SQL + format
        "$": ("reduce", 1),
    },
    4: {  # SQL + f-string
        "$": ("reduce", 2),
    },
    10: {  # After exec
        "dynamic": ("shift", 12),
        "b64decode": ("shift", 13),
        "$": ("reduce", 5),
    },
    12: {  # exec + dynamic
        "$": ("reduce", 5),
    },
    13: {  # exec + base64
        "$": ("reduce", 6),
    },
    11: {  # After eval
        "user_input": ("shift", 14),
        "$": ("reduce", 7),
    },
    14: {
        "$": ("reduce", 7),
    },
    20: {  # subprocess
        "shell_true": ("shift", 21),
        "$": ("reduce", 10),
    },
    21: {
        "concat": ("shift", 22),
        "$": ("reduce", 10),
    },
    22: {
        "$": ("reduce", 8),
    },
    30: {  # os.system
        "format": ("shift", 31),
        "$": ("reduce", 9),
    },
    31: {
        "$": ("reduce", 9),
    },
    40: {  # pickle.load
        "untrusted": ("shift", 41),
        "user_input": ("shift", 42),
        "$": ("reduce", 11),
    },
    41: {
        "$": ("reduce", 11),
    },
    42: {
        "$": ("reduce", 12),
    },
    50: {  # file operations
        "concat": ("shift", 51),
        "user_input": ("shift", 52),
        "dotdot": ("shift", 53),
        "$": ("reduce", 13),
    },
    51: {
        "$": ("reduce", 13),
    },
    52: {
        "$": ("reduce", 14),
    },
    53: {
        "$": ("reduce", 15),
    },
    60: {  # assignments
        "secret_pattern": ("shift", 61),
        "aws_key": ("shift", 62),
        "long_token": ("shift", 63),
        "sql_concat": ("shift", 64),
        "$": ("reduce", 16),
    },
    61: {  # secret pattern
        "$": ("reduce", 16),
    },
    62: {  # AWS key
        "$": ("reduce", 17),
    },
    63: {  # long token
        "$": ("reduce", 18),
    },
    64: {  # SQL concatenation in assignment
        "$": ("reduce", 4),
    },
    70: {  # string literals
        "ip_pattern": ("shift", 71),
        "$": ("reduce", 19),
    },
    71: {
        "$": ("reduce", 19),
    },
    80: {  # hashlib calls
        "weak_algo": ("shift", 81),
        "$": ("reduce", 20),
    },
    81: {
        "$": ("reduce", 20),
    },
    90: {  # random module
        "token_gen": ("shift", 91),
        "seed": ("shift", 92),
        "$": ("reduce", 21),
    },
    91: {
        "$": ("reduce", 21),
    },
    92: {
        "predictable": ("shift", 93),
        "$": ("reduce", 22),
    },
    93: {
        "$": ("reduce", 22),
    },
    100: {  # requests module
        "verify_false": ("shift", 101),
        "$": ("reduce", 23),
    },
    101: {
        "$": ("reduce", 23),
    },
    110: {  # urllib module
        "no_verify": ("shift", 111),
        "$": ("reduce", 24),
    },
    111: {
        "$": ("reduce", 24),
    },
}

# GOTO table for non-terminals
VULN_GOTO_TABLE = {
    0: {"VULN": 100},
    # Add more GOTO states as needed
}

class VulnerabilityParser:
    """
    Grammar-based parser for detecting vulnerability patterns.
    Uses LR-style parsing with ACTION/GOTO tables.
    """
    
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        
    def tokenize_pattern(self, node_type: str, context: Dict[str, Any]) -> List[str]:
        """
        Convert AST node information into tokens for the parser.
        Returns list of tokens representing the vulnerability pattern.
        """
        tokens = []
        
        # Map node types to parser tokens
        if node_type == "Call":
            func_name = context.get("func_name", "")
            
            # SQL-related calls
            if "execute" in func_name.lower():
                tokens.append("execute" if "many" not in func_name else "executemany")
                
                # Check argument type
                if context.get("has_concat"):
                    tokens.append("concat")
                elif context.get("has_format"):
                    tokens.append("format")
                elif context.get("has_fstring"):
                    tokens.append("fstring")
                    
            # Code execution
            elif func_name == "exec":
                tokens.append("exec")
                if context.get("has_b64decode"):
                    tokens.append("b64decode")
                elif context.get("is_dynamic"):
                    tokens.append("dynamic")
                    
            elif func_name == "eval":
                tokens.append("eval")
                if context.get("has_user_input"):
                    tokens.append("user_input")
                    
            # Command execution
            elif "subprocess" in func_name:
                tokens.append("subprocess")
                if context.get("shell_true"):
                    tokens.append("shell_true")
                if context.get("has_concat"):
                    tokens.append("concat")
                    
            elif "system" in func_name:
                tokens.append("os.system")
                if context.get("has_format"):
                    tokens.append("format")
                    
            # Deserialization
            elif "pickle.load" in func_name:
                tokens.append("pickle.load")
                if context.get("untrusted_source"):
                    tokens.append("untrusted")
                elif context.get("has_user_input"):
                    tokens.append("user_input")
                    
            # File operations
            elif func_name in ("open", "Path"):
                tokens.append("open" if func_name == "open" else "Path")
                if context.get("has_concat"):
                    tokens.append("concat")
                elif context.get("has_user_input"):
                    tokens.append("user_input")
                elif context.get("has_dotdot"):
                    tokens.append("dotdot")
            
            # Cryptographic operations
            elif "hashlib" in func_name or func_name in ("md5", "sha1", "new"):
                tokens.append("hashlib")
                if context.get("weak_algo"):
                    tokens.append("weak_algo")
            
            # Random operations
            elif "random" in func_name:
                tokens.append("random")
                if context.get("token_gen"):
                    tokens.append("token_gen")
                elif context.get("has_seed"):
                    tokens.append("seed")
                    if context.get("predictable_seed"):
                        tokens.append("predictable")
            
            # Network requests
            elif "requests" in func_name or func_name in ("get", "post", "request"):
                tokens.append("requests")
                if context.get("verify_false"):
                    tokens.append("verify_false")
            
            elif "urllib" in func_name or "urlopen" in func_name:
                tokens.append("urllib")
                if context.get("no_verify"):
                    tokens.append("no_verify")
        
        elif node_type == "Assign":
            tokens.append("assign")
            if context.get("has_secret_pattern"):
                tokens.append("secret_pattern")
            elif context.get("has_aws_key"):
                tokens.append("aws_key")
            elif context.get("has_long_token"):
                tokens.append("long_token")
            elif context.get("has_sql_concat"):
                tokens.append("sql_concat")
        
        elif node_type == "Constant":
            tokens.append("string")
            if context.get("has_ip_pattern"):
                tokens.append("ip_pattern")
        
        # End-of-input marker
        if tokens:
            tokens.append("$")
        
        return tokens
    
    def parse_pattern(self, tokens: List[str], filename: str, lineno: int) -> Optional[Dict[str, Any]]:
        """
        Parse tokens using ACTION/GOTO tables to detect vulnerability patterns.
        Returns vulnerability finding if pattern matches, None otherwise.
        """
        if not tokens or len(tokens) < 2:
            return None
            
        stack = [0]
        idx = 0
        
        while idx < len(tokens):
            state = stack[-1]
            lookahead = tokens[idx]
            
            # Get action for current state and token
            state_actions = VULN_ACTION_TABLE.get(state, {})
            action = state_actions.get(lookahead)
            
            if action is None:
                return None  # No matching pattern
                
            action_type, value = action
            
            if action_type == "shift":
                stack.append(value)
                idx += 1
                
            elif action_type == "reduce":
                # Found a vulnerability pattern
                prod = VULNERABILITY_GRAMMAR[value]
                lhs, rhs, severity, message = prod
                
                return {
                    "file": filename,
                    "lineno": lineno,
                    "code": f"GRAMMAR_{lhs}",
                    "message": f"Grammar-based detection: {message}",
                    "severity": severity,
                    "pattern": " -> ".join(rhs),
                    "tokens": tokens[:-1]  # Exclude '$'
                }
                
        return None
    
    def analyze_node_with_grammar(self, node_type: str, context: Dict[str, Any], 
                                   filename: str, lineno: int) -> Optional[Dict[str, Any]]:
        """
        Main entry point: tokenize and parse a code pattern.
        """
        tokens = self.tokenize_pattern(node_type, context)
        if tokens:
            return self.parse_pattern(tokens, filename, lineno)
        return None

class CodeVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: List[Dict[str, Any]] = []
        self.current_function: str = "<module>"
        self.function_complexity: Dict[str, int] = {}
        self.imports: List[Tuple[str, str]] = []  # (full, localname)
        self.str_literals: List[str] = []
        self.call_names_seen: List[str] = []
        self.grammar_parser = VulnerabilityParser()  # Add grammar-based parser

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
            
            # Grammar-based detection for hard-coded secrets and IPs
            context = {
                "value": node.value,
                "has_ip_pattern": self._is_ip_pattern(node.value),
            }
            
            grammar_finding = self.grammar_parser.analyze_node_with_grammar(
                "Constant", context, self.filename, node.lineno
            )
            
            if grammar_finding:
                self.findings.append(grammar_finding)
        
        self.generic_visit(node)
    
    # Handle assignments for secret detection
    def visit_Assign(self, node: ast.Assign):
        if node.value and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                value_str = node.value.value
                
                context = {
                    "value": value_str,
                    "has_secret_pattern": self._is_secret_pattern(value_str),
                    "has_aws_key": self._is_aws_key(value_str),
                    "has_long_token": self._is_long_token(value_str),
                    "has_sql_concat": False,  # Handled in visit_Call
                }
                
                grammar_finding = self.grammar_parser.analyze_node_with_grammar(
                    "Assign", context, self.filename, node.lineno
                )
                
                if grammar_finding:
                    self.findings.append(grammar_finding)
        
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

        # ============================================
        # GRAMMAR-BASED PARSING FOR VULNERABILITY DETECTION
        # ============================================
        # Build context for grammar parser
        context = {
            "func_name": func_name,
            "has_concat": self._node_has_concatenation(node),
            "has_format": self._node_has_format(node),
            "has_fstring": self._node_has_fstring(node),
            "has_b64decode": self._has_b64decode_arg(node),
            "is_dynamic": not self._all_args_constant(node),
            "has_user_input": self._may_have_user_input(node),
            "shell_true": self._has_shell_true(node),
            "untrusted_source": self._is_untrusted_source(node),
            "has_dotdot": self._has_dotdot_in_path(node),
            "weak_algo": self._has_weak_hash_algo(node, func_name),
            "token_gen": self._is_token_generation(node, func_name),
            "has_seed": self._is_random_seed(func_name),
            "predictable_seed": self._has_predictable_seed(node),
            "verify_false": self._has_verify_false(node),
            "no_verify": self._has_no_ssl_verify(node),
        }
        
        # Use grammar-based parser to detect vulnerability patterns
        grammar_finding = self.grammar_parser.analyze_node_with_grammar(
            "Call", context, self.filename, node.lineno
        )
        
        if grammar_finding:
            self.findings.append(grammar_finding)

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

    # Note: Assignments and f-strings are now detected via grammar-based parser in visit_Call

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

    # ============================================
    # HELPER METHODS FOR GRAMMAR PARSER CONTEXT
    # ============================================
    
    def _node_has_concatenation(self, node: ast.Call) -> bool:
        """Check if call arguments involve string concatenation."""
        for arg in node.args:
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                return True
        return False
    
    def _node_has_format(self, node: ast.Call) -> bool:
        """Check if call arguments use .format() or % formatting."""
        for arg in node.args:
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                if arg.func.attr == "format":
                    return True
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                return True
        return False
    
    def _node_has_fstring(self, node: ast.Call) -> bool:
        """Check if call arguments use f-strings."""
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):
                return True
        return False
    
    def _has_b64decode_arg(self, node: ast.Call) -> bool:
        """Check if any argument is a base64 decode call."""
        for arg in node.args:
            if isinstance(arg, ast.Call):
                func_name = self._get_call_name(arg.func)
                if func_name and ("b64decode" in func_name or "base64" in func_name):
                    return True
        return False
    
    def _all_args_constant(self, node: ast.Call) -> bool:
        """Check if all arguments are constant values."""
        if not node.args:
            return True
        return all(isinstance(arg, ast.Constant) for arg in node.args)
    
    def _may_have_user_input(self, node: ast.Call) -> bool:
        """Heuristic: check if arguments might come from user input."""
        for arg in node.args:
            if isinstance(arg, ast.Call):
                func_name = self._get_call_name(arg.func)
                if func_name and any(x in func_name.lower() for x in ["input", "read", "get", "request", "argv"]):
                    return True
            if isinstance(arg, ast.Name) and any(x in arg.id.lower() for x in ["input", "user", "request", "data"]):
                return True
        return False
    
    def _has_shell_true(self, node: ast.Call) -> bool:
        """Check if shell=True is in keyword arguments."""
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False
    
    def _is_untrusted_source(self, node: ast.Call) -> bool:
        """Check if data source might be untrusted."""
        for arg in node.args:
            if isinstance(arg, ast.Call):
                func_name = self._get_call_name(arg.func)
                if func_name and any(x in func_name.lower() for x in ["open", "read", "request", "recv", "socket"]):
                    return True
        return False
    
    def _has_dotdot_in_path(self, node: ast.Call) -> bool:
        """Check if path arguments contain .. for directory traversal."""
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if ".." in arg.value:
                    return True
        return False
    
    def _has_weak_hash_algo(self, node: ast.Call, func_name: str) -> bool:
        """Check if using weak hashing algorithms (MD5, SHA1)."""
        # Check function name
        if any(weak in func_name.lower() for weak in ["md5", "sha1"]):
            return True
        
        # Check if hashlib.new() or hashlib.md5()/sha1() is called
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value.lower() in ("md5", "sha1"):
                    return True
        return False
    
    def _is_token_generation(self, node: ast.Call, func_name: str) -> bool:
        """Check if using random for token/secret generation."""
        # random.choice, random.randint for tokens/secrets/passwords
        if "random" in func_name.lower():
            # Check if variable names suggest token generation
            parent = getattr(node, "parent_assign", None)
            if parent:
                for target in getattr(parent, "targets", []):
                    if isinstance(target, ast.Name):
                        if any(x in target.id.lower() for x in ["token", "secret", "key", "password", "salt"]):
                            return True
        return False
    
    def _is_random_seed(self, func_name: str) -> bool:
        """Check if random.seed() is being called."""
        return "seed" in func_name.lower() and "random" in func_name.lower()
    
    def _has_predictable_seed(self, node: ast.Call) -> bool:
        """Check if random.seed() uses predictable value."""
        for arg in node.args:
            if isinstance(arg, ast.Constant):
                # Hard-coded seed value
                return True
            if isinstance(arg, ast.Call):
                func_name = self._get_call_name(arg.func)
                # time() or other predictable sources
                if func_name and "time" in func_name.lower():
                    return True
        return False
    
    def _has_verify_false(self, node: ast.Call) -> bool:
        """Check if requests has verify=False."""
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                return True
        return False
    
    def _has_no_ssl_verify(self, node: ast.Call) -> bool:
        """Check if urllib/urlopen has disabled SSL verification."""
        # Check for context= with unverified context
        for kw in node.keywords:
            if kw.arg == "context" and isinstance(kw.value, ast.Call):
                func_name = self._get_call_name(kw.value.func)
                if "unverified" in func_name.lower():
                    return True
        return False
    
    # Pattern detection for secrets and IPs
    def _is_secret_pattern(self, value: str) -> bool:
        """Check if string matches secret/API key patterns."""
        import re
        # Common secret patterns
        patterns = [
            r"(?:api[_-]?key|secret[_-]?key|password|passwd|token)\s*[:=]\s*['\"]?([A-Za-z0-9\-_+=/]{8,})",
        ]
        for pattern in patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False
    
    def _is_aws_key(self, value: str) -> bool:
        """Check if string is AWS access key."""
        import re
        return bool(re.match(r"AKIA[0-9A-Z]{16}", value))
    
    def _is_long_token(self, value: str) -> bool:
        """Check if string is suspiciously long base64-like token."""
        import re
        if len(value) >= 20:
            # Base64-like pattern
            return bool(re.fullmatch(r"[A-Za-z0-9+/=]{20,}", value))
        return False
    
    def _is_ip_pattern(self, value: str) -> bool:
        """Check if string contains IP address."""
        import re
        return bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value))

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
