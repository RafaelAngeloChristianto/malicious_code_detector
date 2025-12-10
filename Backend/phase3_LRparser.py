#!/usr/bin/env python3
"""
LR and AST Compiler for Detecting Malicious and Vulnerability Detector In Python Language

PHASE 3: SEMANTIC ANALYSIS (Vulnerability Detection)

This module analyzes the AST to detect security vulnerabilities and code quality issues
using formal grammar-based pattern matching with LR-style parsing.
"""

import ast
import re
from typing import List, Dict, Any, Tuple, Optional

# Configurable thresholds
COMPLEXITY_WARN = 8
COMPLEXITY_ERROR = 15

# Suspicious keywords for Phase 1 token pre-screening
SUSPICIOUS_KEYWORDS = {
    'eval', 'exec', 'compile',              # Code execution
    '__import__', 'importlib',              # Dynamic imports
    'subprocess', 'os.system', 'os.popen',  # Command execution
    'shell', 'Popen', 'call', 'run',        # Shell operations
    'pickle', 'loads', 'load',              # Deserialization
    'open', 'read', 'write',                # File operations
    'execute', 'executemany', 'cursor',     # SQL operations
    'query', 'SELECT', 'INSERT', 'UPDATE',  # SQL keywords
    'request', 'input', 'get', 'post',      # User input
    'password', 'secret', 'api_key', 'token', 'aws',  # Secrets
    'md5', 'sha1', 'hashlib',               # Weak crypto
    'random', 'randint', 'choice',          # Random operations
    'requests', 'urllib', 'verify',         # Network
    'ssl', 'https', 'certificate',          # SSL/TLS
    'base64', 'b64decode', 'decode',        # Encoding
    'Path', 'join', 'dirname',              # Path operations
}

# ============================================
# VULNERABILITY DETECTION GRAMMAR & TABLES
# ============================================

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
    
    # Insecure cryptography (19-21)
    ("VULN", ["HASH_CALL", "WEAK_ALGO"], "ERROR", "Weak cryptographic hash algorithm (MD5/SHA1)"),
    ("VULN", ["RANDOM_CALL", "TOKEN_GEN"], "ERROR", "Insecure random for cryptographic token generation"),
    ("VULN", ["RANDOM_SEED", "PREDICTABLE"], "WARNING", "Predictable random seed"),
    
    # Insecure network operations (22-23)
    ("VULN", ["REQUESTS_CALL", "VERIFY_FALSE"], "ERROR", "SSL certificate verification disabled"),
    ("VULN", ["URLLIB_CALL", "NO_VERIFY"], "WARNING", "Insecure HTTPS context"),
]

# ACTION table for LR parsing
VULN_ACTION_TABLE = {
    0: {"execute": ("shift", 1), "executemany": ("shift", 1), "exec": ("shift", 10), 
        "eval": ("shift", 11), "subprocess": ("shift", 20), "os.system": ("shift", 30),
        "pickle.load": ("shift", 40), "open": ("shift", 50), "Path": ("shift", 50),
        "assign": ("shift", 60), "string": ("shift", 70), "hashlib": ("shift", 80),
        "random": ("shift", 90), "requests": ("shift", 100), "urllib": ("shift", 110),
        "sql_var": ("shift", 5)},
    1: {"concat": ("shift", 2), "format": ("shift", 3), "fstring": ("shift", 4), "$": ("reduce", 0)},
    2: {"$": ("reduce", 0)},
    3: {"$": ("reduce", 1)},
    4: {"$": ("reduce", 2)},
    5: {"concat_op": ("shift", 6), "$": ("reduce", 3)},
    6: {"user_input": ("shift", 7), "$": ("reduce", 3)},
    7: {"$": ("reduce", 3)},
    10: {"dynamic": ("shift", 12), "b64decode": ("shift", 13), "$": ("reduce", 5)},
    12: {"$": ("reduce", 5)},
    13: {"$": ("reduce", 6)},
    11: {"user_input": ("shift", 14), "$": ("reduce", 7)},
    14: {"$": ("reduce", 7)},
    20: {"shell_true": ("shift", 21), "$": ("reduce", 10)},
    21: {"concat": ("shift", 22), "$": ("reduce", 10)},
    22: {"$": ("reduce", 8)},
    30: {"format": ("shift", 31), "$": ("reduce", 9)},
    31: {"$": ("reduce", 9)},
    40: {"untrusted": ("shift", 41), "user_input": ("shift", 42), "$": ("reduce", 11)},
    41: {"$": ("reduce", 11)},
    42: {"$": ("reduce", 12)},
    50: {"concat": ("shift", 51), "user_input": ("shift", 52), "dotdot": ("shift", 53), "$": ("reduce", 13)},
    51: {"$": ("reduce", 13)},
    52: {"$": ("reduce", 14)},
    53: {"$": ("reduce", 15)},
    60: {"secret_pattern": ("shift", 61), "aws_key": ("shift", 62), "long_token": ("shift", 63), 
        "sql_concat": ("shift", 64), "$": ("reduce", 16)},
    61: {"$": ("reduce", 16)},
    62: {"$": ("reduce", 17)},
    63: {"$": ("reduce", 18)},
    64: {"$": ("reduce", 4)},
    80: {"weak_algo": ("shift", 81), "$": ("reduce", 19)},
    81: {"$": ("reduce", 19)},
    90: {"token_gen": ("shift", 91), "seed": ("shift", 92), "$": ("reduce", 20)},
    91: {"$": ("reduce", 20)},
    92: {"predictable": ("shift", 93), "$": ("reduce", 21)},
    93: {"$": ("reduce", 21)},
    100: {"verify_false": ("shift", 101), "$": ("reduce", 22)},
    101: {"$": ("reduce", 22)},
    110: {"no_verify": ("shift", 111), "$": ("reduce", 23)},
    111: {"$": ("reduce", 23)},
}

# GOTO table for non-terminals
VULN_GOTO_TABLE = {
    0: {"VULN": 200}, 50: {"FILE_OPEN": 207, "PATH_OP": 208},
}


class VulnerabilityParser:
    """Grammar-based parser for vulnerability pattern detection"""
    
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.parse_traces: List[Dict[str, Any]] = []
    
    def tokenize_pattern(self, node_type: str, context: Dict[str, Any]) -> List[str]:
        """Convert AST node information into parser tokens"""
        tokens = []
        
        if node_type == "Call":
            func_name = context.get("func_name", "")
            
            # SQL-related calls
            if "execute" in func_name.lower():
                tokens.append("execute" if "many" not in func_name else "executemany")
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
        
        elif node_type == "BinOp":
            # SQL string concatenation with user input pattern
            if context.get("is_sql_var"):
                tokens.append("sql_var")
                if context.get("has_concat_op"):
                    tokens.append("concat_op")
                    if context.get("has_user_input"):
                        tokens.append("user_input")
        
        if tokens:
            tokens.append("$")
        
        return tokens
    
    def parse_pattern(self, tokens: List[str], filename: str, lineno: int) -> Optional[Dict[str, Any]]:
        """Parse tokens using LR-style ACTION/GOTO tables"""
        if not tokens or len(tokens) < 2:
            return None
        
        stack = [0]
        symbol_stack = []
        idx = 0
        parse_steps = []
        step_num = 0
        
        while idx < len(tokens):
            state = stack[-1]
            lookahead = tokens[idx]
            
            state_actions = VULN_ACTION_TABLE.get(state, {})
            action = state_actions.get(lookahead)
            
            if action is None:
                return None
            
            action_type, value = action
            
            if action_type == "shift":
                step_num += 1
                parse_steps.append({
                    "step": step_num, "action": "SHIFT", "state": state,
                    "lookahead": lookahead, "next_state": value,
                    "stack_before": list(stack), "symbols_before": list(symbol_stack),
                    "input_remaining": tokens[idx:]
                })
                
                stack.append(value)
                symbol_stack.append(lookahead)
                idx += 1
            
            elif action_type == "reduce":
                prod = VULNERABILITY_GRAMMAR[value]
                lhs, rhs, severity, message = prod
                
                step_num += 1
                reduce_step = {
                    "step": step_num, "action": "REDUCE", "state": state,
                    "production": f"{lhs} -> {' '.join(rhs)}", "production_num": value,
                    "stack_before": list(stack), "symbols_before": list(symbol_stack),
                    "input_remaining": tokens[idx:]
                }
                
                for _ in range(len(rhs)):
                    if stack:
                        stack.pop()
                    if symbol_stack:
                        symbol_stack.pop()
                
                goto_state = None
                if stack:
                    current_state = stack[-1]
                    goto_states = VULN_GOTO_TABLE.get(current_state, {})
                    next_state = goto_states.get(lhs)
                    
                    if next_state is not None:
                        goto_state = next_state
                        stack.append(next_state)
                        symbol_stack.append(lhs)
                
                reduce_step["goto_state"] = goto_state
                reduce_step["stack_after"] = list(stack)
                reduce_step["symbols_after"] = list(symbol_stack)
                parse_steps.append(reduce_step)
                
                parse_trace = {
                    "filename": filename, "lineno": lineno, "tokens": tokens[:-1],
                    "steps": parse_steps, "vulnerability": lhs, "pattern": " -> ".join(rhs),
                    "severity": severity, "message": message
                }
                self.parse_traces.append(parse_trace)
                
                return {
                    "file": filename, "lineno": lineno,
                    "code": f"GRAMMAR_{lhs}", "message": f"Grammar-based detection: {message}",
                    "severity": severity, "pattern": " -> ".join(rhs),
                    "tokens": tokens[:-1], "parse_stack": list(stack),
                    "parse_trace": parse_trace
                }
        
        return None
    
    def analyze_node_with_grammar(self, node_type: str, context: Dict[str, Any],
                                   filename: str, lineno: int) -> Optional[Dict[str, Any]]:
        """Main entry point for grammar-based analysis"""
        tokens = self.tokenize_pattern(node_type, context)
        if tokens:
            return self.parse_pattern(tokens, filename, lineno)
        return None


class SemanticAnalyzer(ast.NodeVisitor):
    """PHASE 3: Semantic Analyzer - Detects vulnerabilities via AST traversal with token pre-screening"""
    
    def __init__(self, filename: str, tokens: List = None):
        self.filename = filename
        self.tokens = tokens or []
        self.findings: List[Dict[str, Any]] = []
        self.current_function: str = "<module>"
        self.function_complexity: Dict[str, int] = {}
        self.imports: List[Tuple[str, str]] = []
        self.str_literals: List[str] = []
        self.call_names_seen: List[str] = []
        self.grammar_parser = VulnerabilityParser()
        
        # Pre-screening: Check if file has suspicious tokens
        self.suspicious_tokens = self._prescreen_tokens()
        self.skip_analysis = len(self.suspicious_tokens) == 0
    
    def _prescreen_tokens(self) -> List[str]:
        """Fast pre-screening: Check tokens for suspicious keywords (Phase 1 integration)"""
        if not self.tokens:
            return []
        
        suspicious = []
        for token in self.tokens:
            token_value = getattr(token, 'value', str(token))
            if token_value in SUSPICIOUS_KEYWORDS:
                suspicious.append(token_value)
        
        return suspicious
    
    def should_analyze(self) -> bool:
        """Determine if expensive AST analysis is needed based on token pre-screening"""
        return not self.skip_analysis
    
    # Import tracking
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
    
    # Constant tracking
    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            self.str_literals.append(node.value)
        self.generic_visit(node)
    
    # Assignment analysis
    def visit_Assign(self, node: ast.Assign):
        if node.value and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                value_str = node.value.value
                
                context = {
                    "value": value_str,
                    "has_secret_pattern": self._is_secret_pattern(value_str),
                    "has_aws_key": self._is_aws_key(value_str),
                    "has_long_token": self._is_long_token(value_str),
                    "has_sql_concat": False,
                }
                
                grammar_finding = self.grammar_parser.analyze_node_with_grammar(
                    "Assign", context, self.filename, node.lineno
                )
                
                if grammar_finding:
                    self.findings.append(grammar_finding)
        
        self.generic_visit(node)
    
    # BinOp analysis for SQL concatenation patterns
    def visit_BinOp(self, node: ast.BinOp):
        if isinstance(node.op, ast.Add):
            # Check if this looks like SQL string concatenation
            left_is_sql = False
            right_has_input = False
            
            # Check left side for SQL keywords
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"]
                left_is_sql = any(kw in node.left.value.upper() for kw in sql_keywords)
            
            # Check right side for user input indicators
            if isinstance(node.right, ast.Name):
                right_has_input = any(x in node.right.id.lower() for x in ["input", "user", "data", "request"])
            elif isinstance(node.right, ast.Call):
                func_name = self._get_call_name(node.right.func)
                right_has_input = "input" in func_name.lower() if func_name else False
            
            if left_is_sql and right_has_input:
                context = {
                    "is_sql_var": True,
                    "has_concat_op": True,
                    "has_user_input": True,
                }
                
                grammar_finding = self.grammar_parser.analyze_node_with_grammar(
                    "BinOp", context, self.filename, node.lineno
                )
                
                if grammar_finding:
                    self.findings.append(grammar_finding)
        
        self.generic_visit(node)
    
    # Call analysis
    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node.func)
        if func_name:
            self.call_names_seen.append(func_name)
        
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
        
        grammar_finding = self.grammar_parser.analyze_node_with_grammar(
            "Call", context, self.filename, node.lineno
        )
        
        if grammar_finding:
            self.findings.append(grammar_finding)
        
        self.generic_visit(node)
    
    # Complexity tracking
    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev = self.current_function
        self.current_function = node.name
        self.function_complexity[node.name] = 1
        self.generic_visit(node)
        
        # Check complexity thresholds and create findings
        comp = self.function_complexity[node.name]
        if comp >= COMPLEXITY_ERROR:
            self.findings.append({
                "file": self.filename,
                "lineno": node.lineno,
                "code": "HIGH_COMPLEXITY",
                "message": f"Function '{node.name}' complexity={comp} (>= {COMPLEXITY_ERROR}).",
                "severity": "ERROR"
            })
        elif comp >= COMPLEXITY_WARN:
            self.findings.append({
                "file": self.filename,
                "lineno": node.lineno,
                "code": "HIGH_COMPLEXITY",
                "message": f"Function '{node.name}' complexity={comp} (>= {COMPLEXITY_WARN}).",
                "severity": "WARNING"
            })
        
        self.current_function = prev
    
    def visit_If(self, node: ast.If):
        self._inc_complexity()
        self.generic_visit(node)
    
    def visit_For(self, node: ast.For):
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
    
    # Context detection helpers
    def _node_has_concatenation(self, node: ast.Call) -> bool:
        for arg in node.args:
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                return True
        return False
    
    def _node_has_format(self, node: ast.Call) -> bool:
        for arg in node.args:
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                if arg.func.attr == "format":
                    return True
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                return True
        return False
    
    def _node_has_fstring(self, node: ast.Call) -> bool:
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):
                return True
        return False
    
    def _has_b64decode_arg(self, node: ast.Call) -> bool:
        for arg in node.args:
            if isinstance(arg, ast.Call):
                func_name = self._get_call_name(arg.func)
                if func_name and ("b64decode" in func_name or "base64" in func_name):
                    return True
        return False
    
    def _all_args_constant(self, node: ast.Call) -> bool:
        if not node.args:
            return True
        return all(isinstance(arg, ast.Constant) for arg in node.args)
    
    def _may_have_user_input(self, node: ast.Call) -> bool:
        for arg in node.args:
            if isinstance(arg, ast.Call):
                func_name = self._get_call_name(arg.func)
                if func_name and any(x in func_name.lower() for x in ["input", "read", "get", "request", "argv"]):
                    return True
            if isinstance(arg, ast.Name) and any(x in arg.id.lower() for x in ["input", "user", "request", "data"]):
                return True
        return False
    
    def _has_shell_true(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False
    
    def _is_untrusted_source(self, node: ast.Call) -> bool:
        for arg in node.args:
            if isinstance(arg, ast.Call):
                func_name = self._get_call_name(arg.func)
                if func_name and any(x in func_name.lower() for x in ["open", "read", "request", "recv", "socket"]):
                    return True
        return False
    
    def _has_dotdot_in_path(self, node: ast.Call) -> bool:
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if ".." in arg.value:
                    return True
        return False
    
    def _has_weak_hash_algo(self, node: ast.Call, func_name: str) -> bool:
        if any(weak in func_name.lower() for weak in ["md5", "sha1"]):
            return True
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value.lower() in ("md5", "sha1"):
                    return True
        return False
    
    def _is_token_generation(self, node: ast.Call, func_name: str) -> bool:
        return "random" in func_name.lower()
    
    def _is_random_seed(self, func_name: str) -> bool:
        return "seed" in func_name.lower() and "random" in func_name.lower()
    
    def _has_predictable_seed(self, node: ast.Call) -> bool:
        for arg in node.args:
            if isinstance(arg, ast.Constant):
                return True
            if isinstance(arg, ast.Call):
                func_name = self._get_call_name(arg.func)
                if func_name and "time" in func_name.lower():
                    return True
        return False
    
    def _has_verify_false(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                return True
        return False
    
    def _has_no_ssl_verify(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "context" and isinstance(kw.value, ast.Call):
                func_name = self._get_call_name(kw.value.func)
                if "unverified" in func_name.lower():
                    return True
        return False
    
    def _is_secret_pattern(self, value: str) -> bool:
        patterns = [
            r"(?:api[_-]?key|secret[_-]?key|password|passwd|token)\s*[:=]\s*['\"]?([A-Za-z0-9\-_+=/]{8,})",
        ]
        for pattern in patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False
    
    def _is_aws_key(self, value: str) -> bool:
        return bool(re.match(r"AKIA[0-9A-Z]{16}", value))
    
    def _is_long_token(self, value: str) -> bool:
        if len(value) >= 20:
            return bool(re.fullmatch(r"[A-Za-z0-9+/=]{20,}", value))
        return False


if __name__ == '__main__':
    # Example usage
    sample_code = '''
import sqlite3

def vulnerable_query(user_input):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    
    return cursor.fetchall()
'''
    
    # Parse the code first (PHASE 2)
    tree = ast.parse(sample_code, filename="<example>")
    
    # Run semantic analysis (PHASE 3)
    analyzer = SemanticAnalyzer("<example>")
    analyzer.visit(tree)
    
    print("PHASE 3: SEMANTIC ANALYSIS")
    print("=" * 60)
    print(f"Vulnerabilities found: {len(analyzer.findings)}")
    print(f"Function complexity tracked: {len(analyzer.function_complexity)}")
    print(f"Imports found: {len(analyzer.imports)}")
    
    if analyzer.findings:
        print("\nFindings:")
        for finding in analyzer.findings:
            print(f"  Line {finding['lineno']}: {finding['severity']} - {finding['message']}")
