#!/usr/bin/env python3
"""
PHASE 4: LR PARSER (Grammar-Based Pattern Matching)

This module implements formal grammar-based vulnerability detection using LR parsing.
Uses ACTION/GOTO tables to recognize vulnerability patterns through context-free grammar productions.

Grammar G = (N, Σ, P, S):
- Non-terminals (N): Multiple hierarchical non-terminals with recursive structures
- Terminals (Σ): Actual code tokens (execute, eval, subprocess, etc.)
- Productions (P): 42 grammar rules with hierarchical composition and recursion
- Start symbol (S): VULN
"""

from typing import List, Dict, Any, Optional

# ============================================
# VULNERABILITY DETECTION GRAMMAR & TABLES
# ============================================

VULNERABILITY_GRAMMAR = [
    # Top-level vulnerability types (0-6)
    ("VULN", ["SQL_INJECTION"], "ERROR", "SQL injection vulnerability detected"),
    ("VULN", ["CODE_EXEC"], "ERROR", "Code execution vulnerability detected"),
    ("VULN", ["COMMAND_INJECT"], "ERROR", "Command injection vulnerability detected"),
    ("VULN", ["PATH_VULN"], "WARNING", "Path traversal vulnerability detected"),
    ("VULN", ["CRYPTO_VULN"], "ERROR", "Cryptographic vulnerability detected"),
    ("VULN", ["SECRET_VULN"], "ERROR", "Hard-coded secret detected"),
    ("VULN", ["NETWORK_VULN"], "ERROR", "Network security vulnerability detected"),
    
    # SQL Injection hierarchy (7-11)
    ("SQL_INJECTION", ["SQL_CALL", "UNSAFE_ARG"], "ERROR", "SQL injection via unsafe argument"),
    ("UNSAFE_ARG", ["CONCAT_EXPR"], "ERROR", "Concatenated SQL string"),
    ("UNSAFE_ARG", ["FORMAT_EXPR"], "ERROR", "Formatted SQL string"),
    ("CONCAT_EXPR", ["STRING_CONST", "CONCAT_OP", "USER_INPUT"], "ERROR", "String concatenation with user input"),
    ("CONCAT_EXPR", ["STRING_CONST", "CONCAT_OP", "CONCAT_EXPR"], "ERROR", "Recursive string concatenation"),
    
    # Code execution hierarchy (12-17)
    ("CODE_EXEC", ["EXEC_CALL", "EXEC_ARG"], "ERROR", "Code execution with unsafe argument"),
    ("EXEC_ARG", ["DYNAMIC_EXPR"], "ERROR", "Dynamic code expression"),
    ("EXEC_ARG", ["B64_EXPR"], "ERROR", "Base64 encoded execution"),
    ("EXEC_ARG", ["USER_INPUT"], "ERROR", "User-controlled code execution"),
    ("B64_EXPR", ["B64_DECODE", "EXPR"], "ERROR", "Base64 decoded expression"),
    ("DYNAMIC_EXPR", ["EXPR"], "ERROR", "Dynamic expression evaluation"),
    
    # Expression hierarchy (recursive) (18-21)
    ("EXPR", ["CONSTANT"], "INFO", "Constant expression"),
    ("EXPR", ["USER_INPUT"], "WARNING", "User input expression"),
    ("EXPR", ["EXPR", "BINOP", "EXPR"], "INFO", "Binary operation expression"),
    ("EXPR", ["FUNC_CALL", "ARG_LIST"], "INFO", "Function call expression"),
    
    # Command injection hierarchy (22-25)
    ("COMMAND_INJECT", ["SUBPROCESS_CALL", "UNSAFE_CMD"], "ERROR", "Command injection via subprocess"),
    ("UNSAFE_CMD", ["SHELL_TRUE", "CONCAT_EXPR"], "ERROR", "Shell=True with concatenation"),
    ("UNSAFE_CMD", ["CONCAT_EXPR"], "WARNING", "Command with concatenated arguments"),
    ("SUBPROCESS_CALL", ["SUBPROCESS_FUNC"], "INFO", "Subprocess function call"),
    
    # Path traversal hierarchy (26-29)
    ("PATH_VULN", ["FILE_OP", "UNSAFE_PATH"], "WARNING", "File operation with unsafe path"),
    ("UNSAFE_PATH", ["CONCAT_EXPR"], "WARNING", "Concatenated file path"),
    ("UNSAFE_PATH", ["DOTDOT_PATH"], "WARNING", "Directory traversal pattern"),
    ("UNSAFE_PATH", ["USER_INPUT"], "WARNING", "User-controlled file path"),
    
    # Cryptography hierarchy (30-33)
    ("CRYPTO_VULN", ["HASH_CALL", "WEAK_ALGO"], "ERROR", "Weak hash algorithm"),
    ("CRYPTO_VULN", ["RANDOM_CALL", "WEAK_RANDOM"], "ERROR", "Weak random generation"),
    ("WEAK_ALGO", ["MD5_ALGO"], "ERROR", "MD5 algorithm"),
    ("WEAK_ALGO", ["SHA1_ALGO"], "ERROR", "SHA1 algorithm"),
    
    # Secret detection hierarchy (34-37)
    ("SECRET_VULN", ["ASSIGN", "SECRET_VALUE"], "ERROR", "Hard-coded secret detected"),
    ("SECRET_VALUE", ["API_KEY"], "ERROR", "Hard-coded API key"),
    ("SECRET_VALUE", ["AWS_KEY"], "ERROR", "Hard-coded AWS access key"),
    ("SECRET_VALUE", ["TOKEN"], "WARNING", "Hard-coded token"),
    
    # Network security hierarchy (38-39)
    ("NETWORK_VULN", ["REQUESTS_CALL", "VERIFY_FALSE"], "ERROR", "SSL verification disabled"),
    ("NETWORK_VULN", ["URLLIB_CALL", "NO_VERIFY"], "WARNING", "Insecure HTTPS context"),
    
    # Argument list (recursive) (40-41)
    ("ARG_LIST", ["EXPR"], "INFO", "Single argument"),
    ("ARG_LIST", ["EXPR", "COMMA", "ARG_LIST"], "INFO", "Multiple arguments (recursive)"),
]

# ACTION table for LR parsing
VULN_ACTION_TABLE = {
    0: {"execute": ("shift", 1), "executemany": ("shift", 1), "exec": ("shift", 10), 
        "eval": ("shift", 11), "subprocess": ("shift", 20), "os.system": ("shift", 30),
        "pickle.load": ("shift", 40), "open": ("shift", 50), "Path": ("shift", 50),
        "assign": ("shift", 60), "string": ("shift", 70), "hashlib": ("shift", 80),
        "random": ("shift", 90), "requests": ("shift", 100), "urllib": ("shift", 110),
        "sql_var": ("shift", 5)},
    1: {"concat": ("shift", 2), "format": ("shift", 3), "fstring": ("shift", 4), "$": ("reduce", 7)},
    2: {"$": ("reduce", 8)},
    3: {"$": ("reduce", 9)},
    4: {"$": ("reduce", 9)},
    5: {"concat_op": ("shift", 6), "$": ("reduce", 10)},
    6: {"user_input": ("shift", 7), "$": ("reduce", 10)},
    7: {"$": ("reduce", 10)},
    10: {"dynamic": ("shift", 12), "b64decode": ("shift", 13), "$": ("reduce", 12)},
    12: {"$": ("reduce", 13)},
    13: {"$": ("reduce", 14)},
    11: {"user_input": ("shift", 14), "$": ("reduce", 12)},
    14: {"$": ("reduce", 15)},
    20: {"shell_true": ("shift", 21), "$": ("reduce", 22)},
    21: {"concat": ("shift", 22), "$": ("reduce", 22)},
    22: {"$": ("reduce", 23)},
    30: {"format": ("shift", 31), "$": ("reduce", 24)},
    31: {"$": ("reduce", 24)},
    40: {"untrusted": ("shift", 41), "user_input": ("shift", 42), "$": ("reduce", 12)},
    41: {"$": ("reduce", 12)},
    42: {"$": ("reduce", 12)},
    50: {"concat": ("shift", 51), "user_input": ("shift", 52), "dotdot": ("shift", 53), "$": ("reduce", 26)},
    51: {"$": ("reduce", 27)},
    52: {"$": ("reduce", 29)},
    53: {"$": ("reduce", 28)},
    60: {"secret_pattern": ("shift", 61), "aws_key": ("shift", 62), "long_token": ("shift", 63), 
        "sql_concat": ("shift", 64), "$": ("reduce", 34)},
    61: {"$": ("reduce", 35)},
    62: {"$": ("reduce", 36)},
    63: {"$": ("reduce", 37)},
    64: {"$": ("reduce", 4)},
    80: {"weak_algo": ("shift", 81), "$": ("reduce", 30)},
    81: {"$": ("reduce", 30)},
    90: {"token_gen": ("shift", 91), "seed": ("shift", 92), "$": ("reduce", 31)},
    91: {"$": ("reduce", 31)},
    92: {"predictable": ("shift", 93), "$": ("reduce", 31)},
    93: {"$": ("reduce", 31)},
    100: {"verify_false": ("shift", 101), "$": ("reduce", 38)},
    101: {"$": ("reduce", 38)},
    110: {"no_verify": ("shift", 111), "$": ("reduce", 39)},
    111: {"$": ("reduce", 39)},
}

# GOTO table for non-terminals (hierarchical grammar structure)
VULN_GOTO_TABLE = {
    # State 0: Initial state - can transition to top-level vulnerabilities
    0: {"VULN": 200, "SQL_INJECTION": 201, "CODE_EXEC": 202, "COMMAND_INJECT": 203,
        "PATH_VULN": 204, "CRYPTO_VULN": 205, "SECRET_VULN": 206, "NETWORK_VULN": 207},
    
    # State 1: After SQL function call (execute/executemany)
    1: {"UNSAFE_ARG": 208, "CONCAT_EXPR": 209, "FORMAT_EXPR": 210},
    
    # State 2-4: After concat/format/fstring tokens
    2: {"CONCAT_EXPR": 211},
    3: {"FORMAT_EXPR": 212},
    4: {"FORMAT_EXPR": 213},
    
    # State 10-11: After exec/eval function calls
    10: {"EXEC_ARG": 214, "DYNAMIC_EXPR": 215, "B64_EXPR": 216, "EXPR": 217},
    11: {"EXEC_ARG": 218, "USER_INPUT": 219},
    
    # State 20-21: After subprocess calls
    20: {"SUBPROCESS_CALL": 220, "UNSAFE_CMD": 221},
    21: {"UNSAFE_CMD": 222, "CONCAT_EXPR": 223},
    
    # State 30: After os.system
    30: {"UNSAFE_CMD": 224},
    
    # State 50: After file operations (open/Path)
    50: {"UNSAFE_PATH": 225, "CONCAT_EXPR": 226},
    
    # State 60: After assignment operator
    60: {"SECRET_VALUE": 227},
    
    # State 80: After hashlib calls
    80: {"WEAK_ALGO": 228},
    
    # State 90: After random calls
    90: {"WEAK_RANDOM": 229},
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
            
            # Pickle deserialization
            elif "pickle.load" in func_name or "loads" in func_name:
                tokens.append("pickle.load")
                if context.get("untrusted_source"):
                    tokens.append("untrusted")
            
            # File operations
            elif func_name in ["open", "Path"]:
                tokens.append(func_name)
                if context.get("has_concat"):
                    tokens.append("concat")
                elif context.get("has_dotdot"):
                    tokens.append("dotdot")
                elif context.get("user_controlled"):
                    tokens.append("user_input")
            
            # Cryptography
            elif "hashlib" in func_name or "md5" in func_name or "sha1" in func_name:
                tokens.append("hashlib")
                if context.get("weak_algorithm"):
                    tokens.append("weak_algo")
            
            # Random operations
            elif "random" in func_name:
                tokens.append("random")
                if context.get("is_token_generation"):
                    tokens.append("token_gen")
                elif context.get("has_predictable_seed"):
                    tokens.append("seed")
                    tokens.append("predictable")
            
            # Network requests
            elif "requests." in func_name:
                tokens.append("requests")
                if context.get("verify_false"):
                    tokens.append("verify_false")
            
            elif "urllib" in func_name:
                tokens.append("urllib")
                if context.get("no_ssl_verify"):
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
        
        return tokens
    
    def parse_pattern(self, tokens: List[str], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        LR parser for vulnerability detection
        Returns a finding if a vulnerability pattern is matched
        """
        if not tokens:
            return None
        
        # LR parsing state machine
        stack = [0]  # Initial state
        token_idx = 0
        parse_trace = []
        
        tokens_with_end = tokens + ["$"]
        
        while token_idx < len(tokens_with_end):
            current_state = stack[-1]
            current_token = tokens_with_end[token_idx]
            
            parse_trace.append({
                "state": current_state,
                "token": current_token,
                "stack": list(stack)
            })
            
            # Look up action in ACTION table
            if current_state not in VULN_ACTION_TABLE:
                break
            
            action_entry = VULN_ACTION_TABLE[current_state].get(current_token)
            if not action_entry:
                # Try wildcard or default action
                break
            
            action, value = action_entry
            
            if action == "shift":
                stack.append(current_token)
                stack.append(value)
                token_idx += 1
                parse_trace.append({
                    "action": "shift",
                    "next_state": value
                })
            
            elif action == "reduce":
                production_idx = value
                if production_idx >= len(VULNERABILITY_GRAMMAR):
                    break
                
                lhs, rhs, severity, message = VULNERABILITY_GRAMMAR[production_idx]
                
                # Pop symbols from stack (2 * len(rhs) because of state/symbol pairs)
                for _ in range(len(rhs) * 2):
                    if stack:
                        stack.pop()
                
                # Push non-terminal
                stack.append(lhs)
                
                # Look up GOTO
                if stack:
                    prev_state = stack[-2] if len(stack) >= 2 else 0
                    if prev_state in VULN_GOTO_TABLE and lhs in VULN_GOTO_TABLE[prev_state]:
                        goto_state = VULN_GOTO_TABLE[prev_state][lhs]
                        stack.append(goto_state)
                
                parse_trace.append({
                    "action": "reduce",
                    "production": f"{lhs} -> {' '.join(rhs)}",
                    "severity": severity,
                    "message": message
                })
                
                # If we reduced to VULN (start symbol), we found a vulnerability
                if lhs == "VULN":
                    finding = {
                        "file": context.get("file", "unknown"),
                        "lineno": context.get("lineno", 0),
                        "code": context.get("code", "VULNERABILITY"),
                        "message": message,
                        "severity": severity,
                        "pattern": " -> ".join(rhs),
                        "parse_trace": parse_trace,
                        "context": context
                    }
                    self.findings.append(finding)
                    return finding
        
        return None
    
    def analyze_node_with_grammar(self, node_type: str, context: Dict[str, Any], 
                                  filename: str = "unknown", lineno: int = 0) -> Optional[Dict[str, Any]]:
        """
        Analyze an AST node using the grammar-based parser
        Main entry point called by SemanticAnalyzer
        """
        # Update context with file info
        context["file"] = filename
        context["lineno"] = lineno
        
        tokens = self.tokenize_pattern(node_type, context)
        if tokens:
            return self.parse_pattern(tokens, context)
        return None
