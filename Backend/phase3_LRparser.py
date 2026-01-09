#!/usr/bin/env python3
"""
LR and AST Compiler for Detecting Malicious and Vulnerability Detector In Python Language

PHASE 3: SEMANTIC ANALYSIS (Enhanced)

This module performs comprehensive semantic analysis including:
1. Security vulnerability detection using formal grammar-based pattern matching with LR-style parsing
2. Traditional semantic analysis:
   - Symbol table management and scope tracking
   - Type inference and type checking
   - Undefined variable detection
   - Control flow analysis (unreachable code, missing returns)
   - Duplicate declaration detection
"""

import ast
import re
from typing import List, Dict, Any, Tuple, Optional, Set
from enum import Enum
from dataclasses import dataclass, field

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

# Common SQL syntax errors (typos and mistakes)
SQL_SYNTAX_ERRORS = {
    # Common misspellings of SELECT
    'SELCT': 'SELECT', 'SLECT': 'SELECT', 'SELEC': 'SELECT', 'SELET': 'SELECT',
    'SELEECT': 'SELECT', 'SELLECT': 'SELECT',
    # Common misspellings of FROM
    'FORM': 'FROM', 'FRON': 'FROM', 'FRUM': 'FROM', 'FOM': 'FROM',
    # Common misspellings of WHERE
    'WHER': 'WHERE', 'WHRE': 'WHERE', 'WERE': 'WHERE', 'WAERE': 'WHERE',
    # Common misspellings of INSERT
    'INSRT': 'INSERT', 'INSER': 'INSERT', 'INSET': 'INSERT', 'INSERTINTO': 'INSERT INTO',
    # Common misspellings of UPDATE  
    'UPDTE': 'UPDATE', 'UPDAE': 'UPDATE', 'UPDAT': 'UPDATE',
    # Common misspellings of DELETE
    'DELET': 'DELETE', 'DELLETE': 'DELETE', 'DELTE': 'DELETE',
    # Common misspellings of ORDER BY
    'ORDERBY': 'ORDER BY', 'ODER': 'ORDER', 'ORER': 'ORDER',
    # Common misspellings of GROUP BY
    'GROUPBY': 'GROUP BY', 'GROPU': 'GROUP', 'GRUP': 'GROUP',
    # Common misspellings of JOIN
    'JION': 'JOIN', 'JON': 'JOIN', 'JOJN': 'JOIN',
    # Common SQL mistakes
    'SELECET': 'SELECT', 'SEELCT': 'SELECT', 'SLELECT': 'SELECT',
}

# Correct SQL keywords for validation
VALID_SQL_KEYWORDS = {
    'SELECT', 'FROM', 'WHERE', 'INSERT', 'INTO', 'UPDATE', 'DELETE',
    'CREATE', 'ALTER', 'DROP', 'TABLE', 'INDEX', 'VIEW',
    'JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER', 'ON',
    'ORDER', 'BY', 'GROUP', 'HAVING', 'DISTINCT',
    'AND', 'OR', 'NOT', 'IN', 'BETWEEN', 'LIKE',
    'AS', 'SET', 'VALUES', 'LIMIT', 'OFFSET',
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

# ============================================
# SYMBOL TABLE & SCOPE MANAGEMENT
# ============================================

class ScopeType(Enum):
    """Types of scopes in Python"""
    GLOBAL = "global"
    FUNCTION = "function"
    CLASS = "class"
    COMPREHENSION = "comprehension"


class SymbolType(Enum):
    """Types of symbols that can be declared"""
    VARIABLE = "variable"
    FUNCTION = "function"
    CLASS = "class"
    PARAMETER = "parameter"
    IMPORT = "import"


@dataclass
class Symbol:
    """Represents a symbol in the symbol table"""
    name: str
    symbol_type: SymbolType
    inferred_type: Optional[str] = None
    declared_line: int = 0
    scope: str = "<unknown>"
    is_used: bool = False
    assignments: List[int] = field(default_factory=list)
    usages: List[int] = field(default_factory=list)


class Scope:
    """Represents a scope with its own symbol table"""
    
    def __init__(self, name: str, scope_type: ScopeType, parent: Optional['Scope'] = None):
        self.name = name
        self.scope_type = scope_type
        self.parent = parent
        self.symbols: Dict[str, Symbol] = {}
        self.children: List['Scope'] = []
    
    def define(self, symbol: Symbol) -> bool:
        """Define a symbol in this scope. Returns False if already defined."""
        if symbol.name in self.symbols:
            return False
        self.symbols[symbol.name] = symbol
        return True
    
    def lookup(self, name: str) -> Optional[Symbol]:
        """Look up a symbol in this scope only"""
        return self.symbols.get(name)
    
    def resolve(self, name: str) -> Optional[Symbol]:
        """Resolve a symbol by searching this scope and parent scopes"""
        symbol = self.lookup(name)
        if symbol:
            return symbol
        if self.parent:
            return self.parent.resolve(name)
        return None
    
    def get_all_symbols(self) -> Dict[str, Symbol]:
        """Get all symbols defined in this scope"""
        return self.symbols.copy()


class SymbolTable:
    """Manages symbol tables and scope hierarchy"""
    
    def __init__(self):
        self.global_scope = Scope("<global>", ScopeType.GLOBAL)
        self.current_scope = self.global_scope
        self.all_scopes: List[Scope] = [self.global_scope]
    
    def enter_scope(self, name: str, scope_type: ScopeType):
        """Enter a new scope"""
        new_scope = Scope(name, scope_type, self.current_scope)
        self.current_scope.children.append(new_scope)
        self.current_scope = new_scope
        self.all_scopes.append(new_scope)
    
    def exit_scope(self):
        """Exit current scope and return to parent"""
        if self.current_scope.parent:
            self.current_scope = self.current_scope.parent
    
    def define(self, symbol: Symbol) -> bool:
        """Define a symbol in the current scope"""
        return self.current_scope.define(symbol)
    
    def resolve(self, name: str) -> Optional[Symbol]:
        """Resolve a symbol starting from current scope"""
        return self.current_scope.resolve(name)
    
    def mark_used(self, name: str, lineno: int):
        """Mark a symbol as used"""
        symbol = self.resolve(name)
        if symbol:
            symbol.is_used = True
            symbol.usages.append(lineno)


# ============================================
# TYPE INFERENCE SYSTEM
# ============================================

class TypeInference:
    """Simple type inference system for Python"""
    
    @staticmethod
    def infer_from_value(node: ast.AST) -> Optional[str]:
        """Infer type from an AST node"""
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, int):
                return "int"
            elif isinstance(value, float):
                return "float"
            elif isinstance(value, str):
                return "str"
            elif isinstance(value, bool):
                return "bool"
            elif value is None:
                return "NoneType"
        elif isinstance(node, ast.List):
            return "list"
        elif isinstance(node, ast.Dict):
            return "dict"
        elif isinstance(node, ast.Set):
            return "set"
        elif isinstance(node, ast.Tuple):
            return "tuple"
        elif isinstance(node, ast.ListComp):
            return "list"
        elif isinstance(node, ast.DictComp):
            return "dict"
        elif isinstance(node, ast.SetComp):
            return "set"
        elif isinstance(node, ast.Lambda):
            return "function"
        elif isinstance(node, ast.Call):
            # Try to infer from common functions
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
                if func_name == "int":
                    return "int"
                elif func_name == "float":
                    return "float"
                elif func_name == "str":
                    return "str"
                elif func_name == "list":
                    return "list"
                elif func_name == "dict":
                    return "dict"
                elif func_name == "set":
                    return "set"
        elif isinstance(node, ast.BinOp):
            # Infer from binary operations
            if isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div)):
                return "numeric"
        return None
    
    @staticmethod
    def check_type_compatibility(expected: str, actual: str) -> bool:
        """Check if two types are compatible"""
        if expected == actual:
            return True
        if expected == "numeric" and actual in ("int", "float"):
            return True
        if actual == "numeric" and expected in ("int", "float"):
            return True
        return False


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
    """PHASE 3: Enhanced Semantic Analyzer
    
    Performs both security vulnerability detection and traditional semantic analysis:
    - Vulnerability detection via AST traversal with token pre-screening
    - Symbol table management and scope tracking
    - Type inference and checking
    - Undefined variable detection
    - Control flow analysis
    """
    
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
        
        # Traditional semantic analysis components
        self.symbol_table = SymbolTable()
        self.type_inference = TypeInference()
        self.has_return: Dict[str, bool] = {}  # Track if functions have return statements
        self.unreachable_code: List[Tuple[int, str]] = []  # Track unreachable code
        self.undefined_vars: List[Tuple[str, int]] = []  # Track undefined variables
        self.duplicate_defs: List[Tuple[str, int, int]] = []  # Track duplicate definitions
        
        # Add Python built-ins to global scope
        self._init_builtins()
    
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
    
    def _init_builtins(self):
        """Initialize symbol table with Python built-in names"""
        builtins = [
            'print', 'len', 'range', 'str', 'int', 'float', 'bool', 'list', 'dict', 'set', 'tuple',
            'abs', 'all', 'any', 'bin', 'chr', 'dir', 'enumerate', 'filter', 'hex', 'input',
            'isinstance', 'iter', 'map', 'max', 'min', 'next', 'open', 'ord', 'pow', 'reversed',
            'round', 'sorted', 'sum', 'type', 'zip', 'Exception', 'ValueError', 'TypeError',
            'KeyError', 'IndexError', 'AttributeError', 'ImportError', 'RuntimeError',
            'True', 'False', 'None', '__name__', '__file__'
        ]
        for builtin_name in builtins:
            symbol = Symbol(
                name=builtin_name,
                symbol_type=SymbolType.FUNCTION if builtin_name[0].islower() else SymbolType.VARIABLE,
                inferred_type="builtin",
                declared_line=0,
                scope="<builtin>"
            )
            self.symbol_table.define(symbol)
    
    def _report_semantic_error(self, code: str, message: str, lineno: int, severity: str = "ERROR"):
        """Helper to report semantic analysis findings"""
        self.findings.append({
            "file": self.filename,
            "lineno": lineno,
            "code": code,
            "message": message,
            "severity": severity
        })
    
    def _check_undefined_usage(self, name: str, lineno: int):
        """Check if a name is defined before use"""
        symbol = self.symbol_table.resolve(name)
        if symbol is None:
            self.undefined_vars.append((name, lineno))
            self._report_semantic_error(
                "UNDEFINED_VARIABLE",
                f"Variable '{name}' used before definition",
                lineno,
                "ERROR"
            )
        else:
            self.symbol_table.mark_used(name, lineno)
    
    def _check_type_mismatch(self, expected_type: str, actual_type: str, lineno: int, context: str):
        """Check for type mismatches"""
        if expected_type and actual_type:
            if not self.type_inference.check_type_compatibility(expected_type, actual_type):
                self._report_semantic_error(
                    "TYPE_MISMATCH",
                    f"Type mismatch in {context}: expected {expected_type}, got {actual_type}",
                    lineno,
                    "WARNING"
                )
    
    # Import tracking
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            mod = alias.name
            bound = alias.asname or alias.name.split(".")[0]
            self.imports.append((mod, bound))
            
            # Add to symbol table
            symbol = Symbol(
                name=bound,
                symbol_type=SymbolType.IMPORT,
                inferred_type="module",
                declared_line=node.lineno,
                scope=self.symbol_table.current_scope.name
            )
            if not self.symbol_table.define(symbol):
                existing = self.symbol_table.current_scope.lookup(bound)
                if existing:
                    self.duplicate_defs.append((bound, existing.declared_line, node.lineno))
                    self._report_semantic_error(
                        "DUPLICATE_IMPORT",
                        f"Import '{bound}' already defined at line {existing.declared_line}",
                        node.lineno,
                        "WARNING"
                    )
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            imported = f"{module}.{alias.name}" if module else alias.name
            bound = alias.asname or alias.name
            self.imports.append((imported, bound))
            
            # Add to symbol table
            symbol = Symbol(
                name=bound,
                symbol_type=SymbolType.IMPORT,
                inferred_type="module",
                declared_line=node.lineno,
                scope=self.symbol_table.current_scope.name
            )
            if not self.symbol_table.define(symbol):
                existing = self.symbol_table.current_scope.lookup(bound)
                if existing:
                    self.duplicate_defs.append((bound, existing.declared_line, node.lineno))
                    self._report_semantic_error(
                        "DUPLICATE_IMPORT",
                        f"Import '{bound}' already defined at line {existing.declared_line}",
                        node.lineno,
                        "WARNING"
                    )
        self.generic_visit(node)
    
    # Constant tracking
    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            self.str_literals.append(node.value)
            # Check for SQL syntax errors in string literals
            self._check_sql_syntax(node.value, node.lineno)
        self.generic_visit(node)
    
    # Assignment analysis
    def visit_Assign(self, node: ast.Assign):
        # Infer type from value
        inferred_type = self.type_inference.infer_from_value(node.value)
        
        # Process each target
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                
                # Check if already defined in current scope
                existing = self.symbol_table.current_scope.lookup(var_name)
                
                # Add to symbol table
                symbol = Symbol(
                    name=var_name,
                    symbol_type=SymbolType.VARIABLE,
                    inferred_type=inferred_type,
                    declared_line=node.lineno,
                    scope=self.symbol_table.current_scope.name
                )
                symbol.assignments.append(node.lineno)
                
                if not self.symbol_table.define(symbol):
                    # Variable redefinition in same scope
                    if existing:
                        # Update the existing symbol instead
                        existing.assignments.append(node.lineno)
                        if inferred_type:
                            existing.inferred_type = inferred_type
        
        # Security vulnerability detection
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
    
    # Complexity tracking and function scope management
    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Add function to symbol table
        func_symbol = Symbol(
            name=node.name,
            symbol_type=SymbolType.FUNCTION,
            inferred_type="function",
            declared_line=node.lineno,
            scope=self.symbol_table.current_scope.name
        )
        
        if not self.symbol_table.define(func_symbol):
            existing = self.symbol_table.current_scope.lookup(node.name)
            if existing:
                self.duplicate_defs.append((node.name, existing.declared_line, node.lineno))
                self._report_semantic_error(
                    "DUPLICATE_FUNCTION",
                    f"Function '{node.name}' already defined at line {existing.declared_line}",
                    node.lineno,
                    "ERROR"
                )
        
        # Enter function scope
        self.symbol_table.enter_scope(node.name, ScopeType.FUNCTION)
        
        # Add parameters to function scope
        for arg in node.args.args:
            param_symbol = Symbol(
                name=arg.arg,
                symbol_type=SymbolType.PARAMETER,
                inferred_type=None,  # Could extract from annotations
                declared_line=node.lineno,
                scope=node.name
            )
            self.symbol_table.define(param_symbol)
        
        # Track function complexity and returns
        prev = self.current_function
        self.current_function = node.name
        self.function_complexity[node.name] = 1
        self.has_return[node.name] = False
        
        # Visit function body
        self.generic_visit(node)
        
        # Check if function should have return statement
        if not self.has_return[node.name] and node.name not in ("__init__", "__del__", "setUp", "tearDown"):
            has_return_annotation = node.returns is not None
            
            # Check if function has parameters (suggests it computes something)
            has_params = len(node.args.args) > 0
            
            # Warn if:
            # 1. Has explicit return type annotation (not None), or
            # 2. Has parameters but no return (likely should return something)
            should_warn = False
            
            if has_return_annotation:
                # Has return annotation - only skip if explicitly -> None
                if isinstance(node.returns, ast.Constant) and node.returns.value is None:
                    should_warn = False
                else:
                    should_warn = True
            elif has_params and not node.name.startswith("_"):
                # Has parameters, not a private method, likely should return something
                # But only warn if function name doesn't suggest pure side effects
                procedure_keywords = ["print", "display", "show", "log", "write", "save", 
                                    "update", "delete", "remove", "clear", "reset", "init"]
                is_procedure_name = any(keyword in node.name.lower() for keyword in procedure_keywords)
                
                if not is_procedure_name:
                    should_warn = True
            
            if should_warn:
                self._report_semantic_error(
                    "MISSING_RETURN",
                    f"Function '{node.name}' may be missing return statement",
                    node.lineno,
                    "WARNING"
                )
        
        # Check complexity thresholds
        comp = self.function_complexity[node.name]
        if comp >= COMPLEXITY_ERROR:
            self._report_semantic_error(
                "HIGH_COMPLEXITY",
                f"Function '{node.name}' complexity={comp} (>= {COMPLEXITY_ERROR})",
                node.lineno,
                "ERROR"
            )
        elif comp >= COMPLEXITY_WARN:
            self._report_semantic_error(
                "HIGH_COMPLEXITY",
                f"Function '{node.name}' complexity={comp} (>= {COMPLEXITY_WARN})",
                node.lineno,
                "WARNING"
            )
        
        # Check for unused parameters
        for symbol in self.symbol_table.current_scope.get_all_symbols().values():
            if symbol.symbol_type == SymbolType.PARAMETER and not symbol.is_used:
                self._report_semantic_error(
                    "UNUSED_PARAMETER",
                    f"Parameter '{symbol.name}' is never used",
                    symbol.declared_line,
                    "WARNING"
                )
        
        # Exit function scope
        self.symbol_table.exit_scope()
        self.current_function = prev
    
    def visit_Return(self, node: ast.Return):
        """Track return statements in functions"""
        if self.current_function != "<module>":
            self.has_return[self.current_function] = True
        self.generic_visit(node)
    
    def visit_ClassDef(self, node: ast.ClassDef):
        """Track class definitions and manage class scope"""
        # Add class to symbol table
        class_symbol = Symbol(
            name=node.name,
            symbol_type=SymbolType.CLASS,
            inferred_type="class",
            declared_line=node.lineno,
            scope=self.symbol_table.current_scope.name
        )
        
        if not self.symbol_table.define(class_symbol):
            existing = self.symbol_table.current_scope.lookup(node.name)
            if existing:
                self.duplicate_defs.append((node.name, existing.declared_line, node.lineno))
                self._report_semantic_error(
                    "DUPLICATE_CLASS",
                    f"Class '{node.name}' already defined at line {existing.declared_line}",
                    node.lineno,
                    "ERROR"
                )
        
        # Enter class scope
        self.symbol_table.enter_scope(node.name, ScopeType.CLASS)
        self.generic_visit(node)
        self.symbol_table.exit_scope()
    
    def visit_Name(self, node: ast.Name):
        """Track variable usage and check for undefined variables"""
        if isinstance(node.ctx, ast.Load):
            # Variable is being read/used
            self._check_undefined_usage(node.id, node.lineno)
        # If it's Store context, it's handled in visit_Assign
        self.generic_visit(node)
    
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
    
    def _check_sql_syntax(self, sql_string: str, lineno: int):
        """Check for common SQL syntax errors in SQL query strings"""
        # Only check strings that look like SQL queries
        sql_upper = sql_string.upper()
        
        # Check if this looks like a SQL query
        has_sql_keyword = any(keyword in sql_upper for keyword in VALID_SQL_KEYWORDS)
        if not has_sql_keyword:
            return
        
        # Tokenize the SQL string (simple whitespace split)
        tokens = sql_upper.split()
        
        for token in tokens:
            # Remove common punctuation
            clean_token = token.strip('(),;\'"')
            
            if clean_token in SQL_SYNTAX_ERRORS:
                correct_keyword = SQL_SYNTAX_ERRORS[clean_token]
                self._report_semantic_error(
                    "SQL_SYNTAX_ERROR",
                    f"SQL syntax error: '{clean_token}' should be '{correct_keyword}'",
                    lineno,
                    "ERROR"
                )
            
            # Check for missing spaces in common SQL patterns
            elif 'SELECTFROM' in clean_token or 'SELECTALL' in clean_token:
                self._report_semantic_error(
                    "SQL_SYNTAX_ERROR",
                    f"SQL syntax error: Missing space in '{clean_token}' (should be 'SELECT FROM' or 'SELECT ALL')",
                    lineno,
                    "ERROR"
                )
            elif 'INSERTINTO' in clean_token:
                self._report_semantic_error(
                    "SQL_SYNTAX_ERROR",
                    f"SQL syntax error: Missing space in '{clean_token}' (should be 'INSERT INTO')",
                    lineno,
                    "ERROR"
                )
            elif 'DELETEFROM' in clean_token:
                self._report_semantic_error(
                    "SQL_SYNTAX_ERROR",
                    f"SQL syntax error: Missing space in '{clean_token}' (should be 'DELETE FROM')",
                    lineno,
                    "ERROR"
                )
            elif 'ORDERBY' in clean_token and clean_token != 'ORDERBY':
                self._report_semantic_error(
                    "SQL_SYNTAX_ERROR",
                    f"SQL syntax error: Missing space (should be 'ORDER BY')",
                    lineno,
                    "ERROR"
                )
            elif 'GROUPBY' in clean_token and clean_token != 'GROUPBY':
                self._report_semantic_error(
                    "SQL_SYNTAX_ERROR",
                    f"SQL syntax error: Missing space (should be 'GROUP BY')",
                    lineno,
                    "ERROR"
                )
    
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
    
    def get_semantic_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of semantic analysis"""
        # Count unused variables
        unused_vars = []
        for scope in self.symbol_table.all_scopes:
            for symbol in scope.get_all_symbols().values():
                if symbol.symbol_type == SymbolType.VARIABLE and not symbol.is_used:
                    unused_vars.append((symbol.name, symbol.declared_line, scope.name))
        
        return {
            "total_findings": len(self.findings),
            "vulnerability_findings": len([f for f in self.findings if f["code"].startswith("GRAMMAR_")]),
            "semantic_findings": len([f for f in self.findings if not f["code"].startswith("GRAMMAR_")]),
            "undefined_variables": len(self.undefined_vars),
            "duplicate_definitions": len(self.duplicate_defs),
            "unused_variables": len(unused_vars),
            "functions_analyzed": len(self.function_complexity),
            "high_complexity_functions": len([c for c in self.function_complexity.values() if c >= COMPLEXITY_WARN]),
            "scopes_created": len(self.symbol_table.all_scopes),
            "symbols_tracked": sum(len(s.symbols) for s in self.symbol_table.all_scopes),
            "imports": len(self.imports),
        }
    
    def print_semantic_summary(self):
        """Print human-readable semantic analysis summary"""
        summary = self.get_semantic_summary()
        
        print("\nPHASE 3: ENHANCED SEMANTIC ANALYSIS SUMMARY")
        print("=" * 60)
        print(f"Total Findings: {summary['total_findings']}")
        print(f"  - Vulnerability Findings: {summary['vulnerability_findings']}")
        print(f"  - Semantic Findings: {summary['semantic_findings']}")
        print(f"\nSemantic Analysis:")
        print(f"  - Undefined Variables: {summary['undefined_variables']}")
        print(f"  - Duplicate Definitions: {summary['duplicate_definitions']}")
        print(f"  - Unused Variables: {summary['unused_variables']}")
        print(f"\nCode Analysis:")
        print(f"  - Functions Analyzed: {summary['functions_analyzed']}")
        print(f"  - High Complexity Functions: {summary['high_complexity_functions']}")
        print(f"  - Scopes Created: {summary['scopes_created']}")
        print(f"  - Symbols Tracked: {summary['symbols_tracked']}")
        print(f"  - Imports: {summary['imports']}")


if __name__ == '__main__':
    # Example usage demonstrating both vulnerability and semantic analysis
    sample_code = '''
import sqlite3

def vulnerable_query(user_input, unused_param):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    
    # Using undefined variable
    result = undefined_var + 1
    
    # No return statement

class MyClass:
    def __init__(self):
        self.value = 42
    
    def complex_method(self):
        # High complexity
        if True:
            if True:
                if True:
                    if True:
                        if True:
                            if True:
                                if True:
                                    if True:
                                        if True:
                                            print("too complex")
        return self.value

# Unused variable
unused_variable = 123

# Using undefined
print(undefined_function())
'''
    
    # Parse the code first (PHASE 2)
    tree = ast.parse(sample_code, filename="<example>")
    
    # Run enhanced semantic analysis (PHASE 3)
    analyzer = SemanticAnalyzer("<example>")
    analyzer.visit(tree)
    
    # Print summary
    analyzer.print_semantic_summary()
    
    if analyzer.findings:
        print("\n" + "=" * 60)
        print("DETAILED FINDINGS:")
        print("=" * 60)
        for i, finding in enumerate(analyzer.findings, 1):
            print(f"\n{i}. [{finding['severity']}] {finding['code']}")
            print(f"   Line {finding['lineno']}: {finding['message']}")
