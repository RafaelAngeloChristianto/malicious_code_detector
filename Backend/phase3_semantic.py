#!/usr/bin/env python3
"""
LR and AST Compiler for Detecting Malicious and Vulnerability Detector In Python Language

PHASE 3: SEMANTIC ANALYSIS (Vulnerability Detection)

This module analyzes the AST to detect security vulnerabilities and code quality issues.
Performs deep analysis of code semantics, patterns, and security implications.
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
    'render_template', 'render', 'safe',    # Template rendering
    'xml', 'etree', 'parse',                # XML parsing
    'yaml', 'load',                         # YAML parsing
    'json', 'loads',                        # JSON parsing
    'ldap', 'search', 'filter',             # LDAP operations
    'session', 'cookie', 'set_cookie',      # Session management
    'authenticate', 'login', 'authorized',  # Authentication
    'csrf', 'token', 'form',                # CSRF protection
    'jwt', 'encode', 'decode',              # JWT handling
}

# SQL Keywords for syntax validation
SQL_KEYWORDS = {
    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'JOIN', 'INNER',
    'LEFT', 'RIGHT', 'OUTER', 'ON', 'AS', 'AND', 'OR', 'NOT', 'IN', 'LIKE',
    'BETWEEN', 'NULL', 'IS', 'ORDER', 'BY', 'GROUP', 'HAVING', 'LIMIT',
    'OFFSET', 'UNION', 'ALL', 'DISTINCT', 'COUNT', 'SUM', 'AVG', 'MAX', 'MIN',
    'CREATE', 'TABLE', 'DROP', 'ALTER', 'ADD', 'COLUMN', 'PRIMARY', 'KEY',
    'FOREIGN', 'REFERENCES', 'INDEX', 'INTO', 'VALUES', 'SET', 'DESCRIBE', 'DESC'
}

# Common SQL keyword typos
SQL_TYPO_MAP = {
    'SELCT': 'SELECT', 'SLECT': 'SELECT', 'SELEC': 'SELECT', 'SLEECT': 'SELECT',
    'SEELCT': 'SELECT', 'SELET': 'SELECT', 'SELLECT': 'SELECT',
    'INSRT': 'INSERT', 'INSER': 'INSERT', 'INSRET': 'INSERT',
    'UPDTE': 'UPDATE', 'UPDAT': 'UPDATE', 'UPDAET': 'UPDATE',
    'DLETE': 'DELETE', 'DELET': 'DELETE', 'DELEET': 'DELETE',
    'FORM': 'FROM', 'FRM': 'FROM', 'FRMO': 'FROM',
    'WHER': 'WHERE', 'WHRE': 'WHERE', 'WEHRE': 'WHERE',
    'JIN': 'JOIN', 'JION': 'JOIN', 'JOINN': 'JOIN',
    'INNR': 'INNER', 'INER': 'INNER',
    'ORDR': 'ORDER', 'ORDE': 'ORDER',
    'GROPU': 'GROUP', 'GRUP': 'GROUP',
    'CRETE': 'CREATE', 'CREAT': 'CREATE', 'CRAETE': 'CREATE',
    'TABEL': 'TABLE', 'TABL': 'TABLE', 'TBALE': 'TABLE',
}


class SQLSyntaxValidator:
    """Validates SQL syntax and detects common errors"""
    
    def __init__(self):
        self.errors: List[Dict[str, Any]] = []
    
    def validate_sql_string(self, sql_string: str, filename: str, lineno: int) -> List[Dict[str, Any]]:
        """Validate SQL syntax and detect typos"""
        if not sql_string or len(sql_string.strip()) < 3:
            return []
        
        findings = []
        
        # Extract potential SQL keywords (uppercase words)
        words = re.findall(r'\b[A-Z]{3,}\b', sql_string.upper())
        
        # Check for duplicate consecutive keywords
        duplicate_findings = self._check_duplicate_keywords(words, sql_string, filename, lineno)
        if duplicate_findings:
            findings.extend(duplicate_findings)
        
        # Check for invalid SQL patterns
        pattern_findings = self._check_invalid_patterns(words, sql_string, filename, lineno)
        if pattern_findings:
            findings.extend(pattern_findings)
        
        for word in words:
            # Check if it's a typo of a known SQL keyword
            if word in SQL_TYPO_MAP:
                correct_keyword = SQL_TYPO_MAP[word]
                
                # Add ERROR finding
                error = {
                    "file": filename,
                    "lineno": lineno,
                    "code": "SQL_SYNTAX_ERROR",
                    "message": f"SQL syntax error detected: '{word}' is incorrectly spelled",
                    "severity": "ERROR",
                    "sql_query": sql_string[:100],  # First 100 chars
                    "typo": word,
                    "correction": correct_keyword
                }
                self.errors.append(error)
                findings.append(error)
                
                # Add INFO finding with correction suggestion
                info = {
                    "file": filename,
                    "lineno": lineno,
                    "code": "SQL_SYNTAX_INFO",
                    "message": f"ℹ️ Did you mean '{correct_keyword}'? Found '{word}' which is not a valid SQL keyword. Correct spelling: '{correct_keyword}'",
                    "severity": "INFO",
                    "sql_query": sql_string[:100],
                    "typo": word,
                    "correction": correct_keyword
                }
                findings.append(info)
            
            # Check for keywords that look similar but aren't valid
            # (edit distance of 1-2 from valid keywords)
            elif word not in SQL_KEYWORDS and len(word) >= 4:
                for valid_keyword in SQL_KEYWORDS:
                    if self._similar(word, valid_keyword):
                        # Add ERROR finding
                        error = {
                            "file": filename,
                            "lineno": lineno,
                            "code": "SQL_SYNTAX_ERROR",
                            "message": f"SQL syntax error detected: '{word}' is not a recognized SQL keyword",
                            "severity": "ERROR",
                            "sql_query": sql_string[:100],
                            "typo": word,
                            "correction": valid_keyword
                        }
                        self.errors.append(error)
                        findings.append(error)
                        
                        # Add INFO finding with suggestion
                        info = {
                            "file": filename,
                            "lineno": lineno,
                            "code": "SQL_SYNTAX_INFO",
                            "message": f"ℹ️ Possible typo: '{word}' appears to be a misspelling of '{valid_keyword}'. Please check your SQL syntax.",
                            "severity": "INFO",
                            "sql_query": sql_string[:100],
                            "typo": word,
                            "correction": valid_keyword
                        }
                        findings.append(info)
                        break
        
        return findings
    
    def _check_duplicate_keywords(self, words: List[str], sql_string: str, filename: str, lineno: int) -> List[Dict[str, Any]]:
        """Check for duplicate consecutive keywords"""
        findings = []
        
        # Check for consecutive duplicate keywords
        for i in range(len(words) - 1):
            if words[i] == words[i + 1] and words[i] in SQL_KEYWORDS:
                error = {
                    "file": filename,
                    "lineno": lineno,
                    "code": "SQL_SYNTAX_ERROR",
                    "message": f"SQL syntax error: Duplicate keyword '{words[i]}' detected (consecutive duplicate keywords are invalid)",
                    "severity": "ERROR",
                    "sql_query": sql_string[:100],
                    "duplicate_keyword": words[i],
                }
                self.errors.append(error)
                findings.append(error)
                
                info = {
                    "file": filename,
                    "lineno": lineno,
                    "code": "SQL_SYNTAX_INFO",
                    "message": f"ℹ️ SQL has duplicate '{words[i]}' keywords. Remove the extra occurrences. Valid SQL should not have consecutive duplicate keywords.",
                    "severity": "INFO",
                    "sql_query": sql_string[:100],
                    "duplicate_keyword": words[i],
                }
                findings.append(info)
                break  # Only report first duplicate
        
        return findings
    
    def _check_invalid_patterns(self, words: List[str], sql_string: str, filename: str, lineno: int) -> List[Dict[str, Any]]:
        """Check for invalid SQL keyword patterns"""
        findings = []
        
        # Check for multiple statement keywords (SELECT, INSERT, UPDATE, DELETE) in same query
        statement_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE']
        found_statements = [w for w in words if w in statement_keywords]
        
        if len(found_statements) > 1 and len(set(found_statements)) > 1:
            error = {
                "file": filename,
                "lineno": lineno,
                "code": "SQL_SYNTAX_ERROR",
                "message": f"SQL syntax error: Multiple statement types detected ({', '.join(set(found_statements))}). A query should only have one statement type.",
                "severity": "ERROR",
                "sql_query": sql_string[:100],
                "mixed_statements": list(set(found_statements)),
            }
            self.errors.append(error)
            findings.append(error)
            
            info = {
                "file": filename,
                "lineno": lineno,
                "code": "SQL_SYNTAX_INFO",
                "message": f"ℹ️ SQL query contains multiple statement types. Separate them into different queries or use UNION if combining SELECT statements.",
                "severity": "INFO",
                "sql_query": sql_string[:100],
            }
            findings.append(info)
        
        return findings
    
    def _similar(self, word1: str, word2: str) -> bool:
        """Check if two words are similar (edit distance <= 2)"""
        if abs(len(word1) - len(word2)) > 2:
            return False
        
        # Levenshtein distance calculation
        distance = self._levenshtein_distance(word1, word2)
        return distance <= 2 and distance > 0
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]


class SemanticAnalyzer(ast.NodeVisitor):
    """PHASE 3: Semantic Analyzer - Detects vulnerabilities via AST traversal with token pre-screening"""
    
    def __init__(self, filename: str, tokens: List = None, grammar_parser=None):
        self.filename = filename
        self.tokens = tokens or []
        self.findings: List[Dict[str, Any]] = []
        self.current_function: str = "<module>"
        self.function_complexity: Dict[str, int] = {}
        self.imports: List[Tuple[str, str]] = []
        self.str_literals: List[str] = []
        self.call_names_seen: List[str] = []
        self.grammar_parser = grammar_parser  # Will be injected from Phase 4
        self.sql_validator = SQLSyntaxValidator()
        
        # Track variable assignments for SQL string tracking
        self.variable_values: Dict[str, Any] = {}
        
        # Track function decorators for authentication analysis
        self.function_decorators: Dict[str, List[str]] = {}
        
        # Track routes/endpoints
        self.routes: List[Dict[str, Any]] = []
        
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
    
    # ============================================
    # IMPORT TRACKING
    # ============================================
    
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
    
    # ============================================
    # CONSTANT TRACKING
    # ============================================
    
    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            self.str_literals.append(node.value)
        self.generic_visit(node)
    
    # ============================================
    # ASSIGNMENT ANALYSIS
    # ============================================
    
    def visit_Assign(self, node: ast.Assign):
        # Track variable values for SQL string analysis
        if node.value and len(node.targets) == 1:
            if isinstance(node.targets[0], ast.Name):
                var_name = node.targets[0].id
                # Store the AST node for later analysis
                self.variable_values[var_name] = node.value
                
                # Check for LDAP filter assignment with f-string or format
                if any(x in var_name.lower() for x in ['filter', 'ldap', 'search']):
                    if isinstance(node.value, ast.JoinedStr):  # f-string
                        self.findings.append({
                            "file": self.filename,
                            "lineno": node.lineno,
                            "code": "LDAP_INJECTION",
                            "message": f"LDAP injection risk: Variable '{var_name}' assigned with f-string (unescaped user input)",
                            "severity": "ERROR"
                        })
                        self.findings.append({
                            "file": self.filename,
                            "lineno": node.lineno,
                            "code": "LDAP_INFO",
                            "message": "ℹ️ Use parameterized LDAP queries or escape special characters: ( ) \\ * NUL",
                            "severity": "INFO"
                        })
                    elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                        self.findings.append({
                            "file": self.filename,
                            "lineno": node.lineno,
                            "code": "LDAP_INJECTION",
                            "message": f"LDAP injection risk: Variable '{var_name}' assigned with concatenation (unescaped user input)",
                            "severity": "ERROR"
                        })
                        self.findings.append({
                            "file": self.filename,
                            "lineno": node.lineno,
                            "code": "LDAP_INFO",
                            "message": "ℹ️ Use parameterized LDAP queries or escape special characters: ( ) \\ * NUL",
                            "severity": "INFO"
                        })
                
                # Check for NoSQL query dict with request/user input
                if any(x in var_name.lower() for x in ['query', 'filter', 'condition']):
                    if isinstance(node.value, ast.Dict):
                        # Check if dict values come from user input
                        for value in node.value.values:
                            if isinstance(value, ast.Call):
                                val_func_name = self._get_call_name(value.func)
                                if val_func_name and any(x in val_func_name.lower() for x in ['request.', '.get', 'input']):
                                    self.findings.append({
                                        "file": self.filename,
                                        "lineno": node.lineno,
                                        "code": "NOSQL_INJECTION",
                                        "message": f"NoSQL injection risk: Variable '{var_name}' assigned with user-controlled dict values",
                                        "severity": "ERROR"
                                    })
                                    self.findings.append({
                                        "file": self.filename,
                                        "lineno": node.lineno,
                                        "code": "NOSQL_INFO",
                                        "message": "ℹ️ Validate and sanitize user input. Use type checking and avoid passing raw request data to queries",
                                        "severity": "INFO"
                                    })
                                    break
                            elif isinstance(value, ast.Name):
                                # Check if the name suggests user input
                                if any(x in value.id.lower() for x in ['user', 'input', 'request', 'data', 'param']):
                                    self.findings.append({
                                        "file": self.filename,
                                        "lineno": node.lineno,
                                        "code": "NOSQL_INJECTION",
                                        "message": f"NoSQL injection risk: Variable '{var_name}' dict contains potentially user-controlled value '{value.id}'",
                                        "severity": "WARNING"
                                    })
                                    self.findings.append({
                                        "file": self.filename,
                                        "lineno": node.lineno,
                                        "code": "NOSQL_INFO",
                                        "message": "ℹ️ Validate and sanitize user input. Use type checking and avoid passing raw request data to queries",
                                        "severity": "INFO"
                                    })
                                    break
                
                # Check for weak random assignment to session/token variables
                if any(x in var_name.lower() for x in ['session', 'token', 'secret', 'key', 'password', 'auth']):
                    # Check if the value uses weak random
                    if isinstance(node.value, ast.Call):
                        # str(random.random()) pattern
                        if self._get_call_name(node.value.func) == 'str' and node.value.args:
                            first_arg = node.value.args[0]
                            if isinstance(first_arg, ast.Call):
                                inner_func = self._get_call_name(first_arg.func)
                                if inner_func and 'random.' in inner_func and 'secrets.' not in inner_func:
                                    self.findings.append({
                                        "file": self.filename,
                                        "lineno": node.lineno,
                                        "code": "WEAK_SESSION",
                                        "message": f"Weak session management: Variable '{var_name}' assigned with predictable random value",
                                        "severity": "ERROR"
                                    })
                                    self.findings.append({
                                        "file": self.filename,
                                        "lineno": node.lineno,
                                        "code": "WEAK_SESSION_INFO",
                                        "message": "ℹ️ Use secrets.token_urlsafe() or secrets.token_hex() for cryptographically secure random values",
                                        "severity": "INFO"
                                    })
        
        if node.value and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                value_str = node.value.value
                
                # Check for hardcoded secrets
                if self._is_secret_pattern(value_str):
                    context = {
                        "value": value_str,
                        "has_secret_pattern": True,
                        "has_aws_key": self._is_aws_key(value_str),
                        "has_long_token": self._is_long_token(value_str),
                        "has_sql_concat": False,
                    }
                    
                    if self.grammar_parser:
                        grammar_finding = self.grammar_parser.analyze_node_with_grammar(
                            "Assign", context, self.filename, node.lineno
                        )
                        
                        if grammar_finding:
                            self.findings.append(grammar_finding)
        
        self.generic_visit(node)
    
    # ============================================
    # BINOP ANALYSIS (SQL Concatenation)
    # ============================================
    
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
                
                if self.grammar_parser:
                    grammar_finding = self.grammar_parser.analyze_node_with_grammar(
                        "BinOp", context, self.filename, node.lineno
                    )
                    
                    if grammar_finding:
                        self.findings.append(grammar_finding)
        
        self.generic_visit(node)
    
    # ============================================
    # CALL ANALYSIS (Main vulnerability detection)
    # ============================================
    
    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node.func)
        if func_name:
            self.call_names_seen.append(func_name)
        
        # SQL syntax validation for execute/executemany calls
        if func_name and any(sql_func in func_name.lower() for sql_func in ['execute', 'executemany']):
            sql_string = self._extract_sql_string(node)
            if sql_string:
                sql_findings = self.sql_validator.validate_sql_string(
                    sql_string, self.filename, node.lineno
                )
                if sql_findings:
                    self.findings.extend(sql_findings)
        
        # ====================
        # RULES 11-25: New Vulnerability Checks
        # ====================
        
        # Rule 11: XSS - Unescaped output in templates
        self._check_xss_vulnerability(node, func_name)
        
        # Rule 12: LDAP Injection
        self._check_ldap_injection(node, func_name)
        
        # Rule 13: XXE - XML External Entity
        self._check_xxe_vulnerability(node, func_name)
        
        # Rule 14: Template Injection
        self._check_template_injection(node, func_name)
        
        # Rule 16: NoSQL Injection
        self._check_nosql_injection(node, func_name)
        
        # Rule 17: YAML Injection
        self._check_yaml_injection(node, func_name)
        
        # Rule 18: JSON Injection
        self._check_json_injection(node, func_name)
        
        # Rule 22: Weak Session Management
        self._check_weak_session(node, func_name)
        
        # Rule 23: Insecure Cookie Settings
        self._check_insecure_cookies(node, func_name)
        
        # Rule 24: Hardcoded JWT Secrets
        self._check_jwt_secrets(node, func_name)
        
        # Grammar-based analysis (existing vulnerabilities)
        if self.grammar_parser:
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
    
    # ============================================
    # FUNCTION DEFINITION ANALYSIS
    # ============================================
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev = self.current_function
        self.current_function = node.name
        self.function_complexity[node.name] = 1
        
        # Track decorators
        decorators = [self._get_decorator_name(dec) for dec in node.decorator_list]
        self.function_decorators[node.name] = decorators
        
        # Rule 21: Missing Authentication Checks
        self._check_missing_auth(node, decorators)
        
        # Rule 25: Missing CSRF Protection
        self._check_missing_csrf(node, decorators)
        
        self.generic_visit(node)
        
        # Check complexity thresholds
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
    
    # ============================================
    # COMPLEXITY TRACKING
    # ============================================
    
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
    
    # ============================================
    # NEW RULES 11-25: VULNERABILITY CHECKS
    # ============================================
    
    def _check_xss_vulnerability(self, node: ast.Call, func_name: str):
        """Rule 11: Detect XSS vulnerabilities in template rendering"""
        if not func_name:
            return
        
        # Check for unsafe template rendering
        if any(x in func_name.lower() for x in ['render_template', 'render', 'render_to_string']):
            # Check if template argument uses concatenation or f-string with user input
            if node.args:
                first_arg = node.args[0]
                # Check for concatenation in the template string
                if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                    self.findings.append({
                        "file": self.filename,
                        "lineno": node.lineno,
                        "code": "XSS_VULNERABILITY",
                        "message": "XSS risk: Template rendering with concatenated user input (unescaped HTML)",
                        "severity": "ERROR"
                    })
                    self.findings.append({
                        "file": self.filename,
                        "lineno": node.lineno,
                        "code": "XSS_INFO",
                        "message": "ℹ️ Use template variables with autoescaping enabled instead of string concatenation",
                        "severity": "INFO"
                    })
                # Check for f-string in template
                elif isinstance(first_arg, ast.JoinedStr):
                    self.findings.append({
                        "file": self.filename,
                        "lineno": node.lineno,
                        "code": "XSS_VULNERABILITY",
                        "message": "XSS risk: Template rendering with f-string interpolation (unescaped HTML)",
                        "severity": "ERROR"
                    })
                    self.findings.append({
                        "file": self.filename,
                        "lineno": node.lineno,
                        "code": "XSS_INFO",
                        "message": "ℹ️ Use template variables with {{ }} syntax instead of f-strings for user content",
                        "severity": "INFO"
                    })
            
            # Check if safe=False or no autoescaping
            for kw in node.keywords:
                if kw.arg == 'autoescape' and isinstance(kw.value, ast.Constant):
                    if kw.value.value is False:
                        self.findings.append({
                            "file": self.filename,
                            "lineno": node.lineno,
                            "code": "XSS_VULNERABILITY",
                            "message": "XSS risk: Template rendering with autoescape=False allows unescaped HTML",
                            "severity": "ERROR"
                        })
                        self.findings.append({
                            "file": self.filename,
                            "lineno": node.lineno,
                            "code": "XSS_INFO",
                            "message": "ℹ️ Enable autoescaping or use |escape filter to prevent XSS attacks",
                            "severity": "INFO"
                        })
        
        # Check for dangerous methods like mark_safe
        if 'mark_safe' in func_name or 'Markup' in func_name:
            if self._may_have_user_input(node):
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "XSS_VULNERABILITY",
                    "message": "XSS risk: Using mark_safe() or Markup() with user-controlled input",
                    "severity": "ERROR"
                })
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "XSS_INFO",
                    "message": "ℹ️ Sanitize and validate user input before marking as safe. Consider using bleach.clean()",
                    "severity": "INFO"
                })
    
    def _check_ldap_injection(self, node: ast.Call, func_name: str):
        """Rule 12: Detect LDAP injection vulnerabilities"""
        if not func_name:
            return
        
        # Check for LDAP search operations (including conn.search_s pattern)
        if any(x in func_name.lower() for x in ['ldap.search', 'search_s', 'search_st', '.search_s', '.search_st']):
            # Check if any argument uses f-string, concatenation, or formatting
            has_unsafe_pattern = False
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):  # f-string
                    has_unsafe_pattern = True
                    break
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):  # concatenation
                    has_unsafe_pattern = True
                    break
                if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                    if arg.func.attr == "format":  # .format()
                        has_unsafe_pattern = True
                        break
            
            if has_unsafe_pattern:
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "LDAP_INJECTION",
                    "message": "LDAP injection risk: LDAP filter constructed with string concatenation or formatting",
                    "severity": "ERROR"
                })
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "LDAP_INFO",
                    "message": "ℹ️ Use parameterized LDAP queries or escape special characters: ( ) \\ * NUL",
                    "severity": "INFO"
                })
    
    def _check_xxe_vulnerability(self, node: ast.Call, func_name: str):
        """Rule 13: Detect XML External Entity (XXE) vulnerabilities"""
        if not func_name:
            return
        
        # Check for unsafe XML parsing
        if any(x in func_name.lower() for x in ['etree.parse', 'xml.parse', 'xmlparse', 'fromstring']):
            # Check if external entities are not disabled
            has_safe_parser = False
            for kw in node.keywords:
                if kw.arg in ['forbid_dtd', 'forbid_entities', 'forbid_external']:
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        has_safe_parser = True
            
            if not has_safe_parser:
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "XXE_VULNERABILITY",
                    "message": "XXE vulnerability: XML parsing without disabling external entities\n💡 Use defusedxml library or set parser options: forbid_dtd=True, forbid_entities=True",
                    "severity": "ERROR"
                })
    
    def _check_template_injection(self, node: ast.Call, func_name: str):
        """Rule 14: Detect template injection vulnerabilities"""
        if not func_name:
            return
        
        # Check for Jinja2 Template() constructor with user input or concatenation
        if func_name == 'Template' or 'Template' in func_name:
            if node.args:
                first_arg = node.args[0]
                # Check for user input or dynamic string construction
                if self._may_have_user_input(node) or \
                   isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add) or \
                   isinstance(first_arg, ast.JoinedStr):
                    self.findings.append({
                        "file": self.filename,
                        "lineno": node.lineno,
                        "code": "TEMPLATE_INJECTION",
                        "message": "Template injection risk: Creating Jinja2 Template with user-controlled or concatenated string",
                        "severity": "ERROR"
                    })
                    self.findings.append({
                        "file": self.filename,
                        "lineno": node.lineno,
                        "code": "TEMPLATE_INFO",
                        "message": "ℹ️ Never create templates from user input. Use predefined template files with safe variable substitution",
                        "severity": "INFO"
                    })
        
        # Check for Jinja2 template from string with user input
        if any(x in func_name.lower() for x in ['template.from_string', 'environment.from_string']):
            if self._may_have_user_input(node):
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "TEMPLATE_INJECTION",
                    "message": "Template injection risk: Creating template from user-controlled string",
                    "severity": "ERROR"
                })
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "TEMPLATE_INFO",
                    "message": "ℹ️ Never create templates from user input. Use predefined templates with safe variable substitution",
                    "severity": "INFO"
                })
        
        # Check for Python string formatting used as template
        if func_name == 'format' and self._in_rendering_context():
            self.findings.append({
                "file": self.filename,
                "lineno": node.lineno,
                "code": "TEMPLATE_INJECTION",
                "message": "Template injection risk: Using string.format() for template rendering",
                "severity": "WARNING"
            })
    
    def _check_nosql_injection(self, node: ast.Call, func_name: str):
        """Rule 16: Detect NoSQL injection vulnerabilities"""
        if not func_name:
            return
        
        # MongoDB operations
        if any(x in func_name.lower() for x in ['find', 'find_one', 'update', 'remove', 'delete', '.find(', '.find_one(']):
            # Check for dict argument with user input values
            has_unsafe_query = False
            for arg in node.args:
                if isinstance(arg, ast.Dict):
                    # Check if dict values come from user input
                    for value in arg.values:
                        if isinstance(value, ast.Call):
                            val_func_name = self._get_call_name(value.func)
                            if val_func_name and any(x in val_func_name.lower() for x in ['request.', '.get(', 'input']):
                                has_unsafe_query = True
                                break
                        elif isinstance(value, ast.Attribute):
                            # Check for request.args.get pattern
                            if 'request' in self._get_call_name(value).lower():
                                has_unsafe_query = True
                                break
                    if has_unsafe_query:
                        break
            
            # Also check for traditional concatenation/formatting
            if has_unsafe_query or self._node_has_concatenation(node) or self._node_has_format(node):
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "NOSQL_INJECTION",
                    "message": "NoSQL injection risk: Query with user-controlled input can be manipulated",
                    "severity": "ERROR"
                })
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "NOSQL_INFO",
                    "message": "ℹ️ Validate and sanitize user input. Use type checking and avoid passing raw request data to queries",
                    "severity": "INFO"
                })
    
    def _check_yaml_injection(self, node: ast.Call, func_name: str):
        """Rule 17: Detect YAML injection/deserialization vulnerabilities"""
        if not func_name:
            return
        
        # Check for unsafe yaml.load
        if 'yaml.load' in func_name.lower() or func_name == 'load':
            # Check if SafeLoader is used
            has_safe_loader = False
            for arg in node.args:
                if isinstance(arg, ast.Attribute) and 'SafeLoader' in self._get_call_name(arg):
                    has_safe_loader = True
            
            for kw in node.keywords:
                if kw.arg == 'Loader' and isinstance(kw.value, ast.Attribute):
                    if 'SafeLoader' in self._get_call_name(kw.value):
                        has_safe_loader = True
            
            if not has_safe_loader:
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "YAML_INJECTION",
                    "message": "YAML injection risk: Using yaml.load() without SafeLoader allows arbitrary code execution\n💡 Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) instead",
                    "severity": "ERROR"
                })
    
    def _check_json_injection(self, node: ast.Call, func_name: str):
        """Rule 18: Detect unsafe JSON operations"""
        if not func_name:
            return
        
        # Check for json.loads with user input (potential for large payloads)
        if 'json.loads' in func_name.lower():
            if self._may_have_user_input(node):
                # This is more of a DOS risk, but can be injection vector
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "JSON_DOS_RISK",
                    "message": "JSON parsing risk: No size limit on user-provided JSON data (DOS potential)\n💡 Validate JSON size before parsing. Set limits on request body size",
                    "severity": "WARNING"
                })
    
    def _check_weak_session(self, node: ast.Call, func_name: str):
        """Rule 22: Detect weak session management"""
        if not func_name:
            return
        
        # Check for session ID generation with weak randomness
        if any(x in func_name.lower() for x in ['session', 'sessionid', 'session_id']):
            if self._uses_weak_random(node):
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "WEAK_SESSION",
                    "message": "Weak session management: Session ID generated with predictable randomness",
                    "severity": "ERROR"
                })
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "WEAK_SESSION_INFO",
                    "message": "ℹ️ Use secrets.token_urlsafe() or secrets.token_hex() for session ID generation",
                    "severity": "INFO"
                })
        
        # Check for str(random.random()) or similar direct weak random usage
        if func_name == 'str' and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Call):
                inner_func = self._get_call_name(first_arg.func)
                if inner_func and 'random.' in inner_func and 'secrets.' not in inner_func:
                    # Check if this is in a session/token context
                    if self._in_session_token_context():
                        self.findings.append({
                            "file": self.filename,
                            "lineno": node.lineno,
                            "code": "WEAK_SESSION",
                            "message": "Weak session management: Using random module instead of secrets for session/token generation",
                            "severity": "ERROR"
                        })
                        self.findings.append({
                            "file": self.filename,
                            "lineno": node.lineno,
                            "code": "WEAK_SESSION_INFO",
                            "message": "ℹ️ Use secrets.token_urlsafe() or secrets.token_hex() for cryptographically secure random values",
                            "severity": "INFO"
                        })
    
    def _check_insecure_cookies(self, node: ast.Call, func_name: str):
        """Rule 23: Detect insecure cookie settings"""
        if not func_name:
            return
        
        if 'set_cookie' in func_name.lower():
            has_secure = False
            has_httponly = False
            has_samesite = False
            
            for kw in node.keywords:
                if kw.arg == 'secure' and isinstance(kw.value, ast.Constant):
                    if kw.value.value is True:
                        has_secure = True
                if kw.arg == 'httponly' and isinstance(kw.value, ast.Constant):
                    if kw.value.value is True:
                        has_httponly = True
                if kw.arg == 'samesite':
                    has_samesite = True
            
            if not has_secure:
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "INSECURE_COOKIE",
                    "message": "Insecure cookie: Missing 'secure' flag (cookie can be sent over HTTP)\n💡 Set secure=True to ensure cookie is only sent over HTTPS",
                    "severity": "WARNING"
                })
            
            if not has_httponly:
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "INSECURE_COOKIE",
                    "message": "Insecure cookie: Missing 'httponly' flag (vulnerable to XSS)\n💡 Set httponly=True to prevent JavaScript access to cookie",
                    "severity": "WARNING"
                })
            
            if not has_samesite:
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "INSECURE_COOKIE",
                    "message": "Insecure cookie: Missing 'samesite' attribute (vulnerable to CSRF)\n💡 Set samesite='Lax' or 'Strict' to prevent CSRF attacks",
                    "severity": "WARNING"
                })
    
    def _check_jwt_secrets(self, node: ast.Call, func_name: str):
        """Rule 24: Detect hardcoded JWT secrets"""
        if not func_name:
            return
        
        # Check for jwt.encode/decode or just encode if jwt module is detected
        is_jwt_call = ('jwt.encode' in func_name.lower() or 'jwt.decode' in func_name.lower() or
                       (func_name.lower() in ['encode', 'decode'] and self._has_jwt_import()))
        
        if is_jwt_call:
            # Check if secret is hardcoded (second argument)
            if len(node.args) >= 2:
                secret_arg = node.args[1]
                secret_value = None
                
                # Get secret value - either as constant or from variable tracking
                if isinstance(secret_arg, ast.Constant):
                    secret_value = secret_arg.value
                elif isinstance(secret_arg, ast.Name) and secret_arg.id in self.variable_values:
                    # Look up variable value
                    var_node = self.variable_values[secret_arg.id]
                    if isinstance(var_node, ast.Constant):
                        secret_value = var_node.value
                
                # Check if secret is weak or hardcoded
                if secret_value and isinstance(secret_value, str):
                    if len(secret_value) < 32 or secret_value.lower() in ['secret', 'key', 'password']:
                        self.findings.append({
                            "file": self.filename,
                            "lineno": node.lineno,
                            "code": "HARDCODED_JWT_SECRET",
                            "message": "Hardcoded JWT secret: Weak or hardcoded JWT signing key detected\n💡 Use environment variables or secret management system. Generate strong keys with secrets.token_hex(32)",
                            "severity": "ERROR"
                        })
    
    def _has_jwt_import(self) -> bool:
        """Check if jwt module is imported"""
        return any('jwt' in imp.lower() for imp in [mod for mod, bound in self.imports] + [bound for mod, bound in self.imports])
    
    def _check_missing_auth(self, node: ast.FunctionDef, decorators: List[str]):
        """Rule 21: Check for routes missing authentication"""
        # Check if function is a route handler
        is_route = any(dec in ['route', 'get', 'post', 'put', 'delete', 'app.route'] for dec in decorators)
        
        if is_route:
            # Check if authentication decorator is present
            has_auth = any(auth in dec.lower() for dec in decorators 
                          for auth in ['login_required', 'auth', 'authenticate', 'require_auth', 'protected'])
            
            # Check if route path suggests it should be protected
            route_needs_auth = any(keyword in node.name.lower() 
                                  for keyword in ['admin', 'dashboard', 'profile', 'settings', 'delete', 'update'])
            
            if route_needs_auth and not has_auth:
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "MISSING_AUTHENTICATION",
                    "message": f"Missing authentication: Route '{node.name}' appears sensitive but has no authentication decorator\n💡 Add @login_required or equivalent authentication decorator to protect this route",
                    "severity": "WARNING"
                })
    
    def _check_missing_csrf(self, node: ast.FunctionDef, decorators: List[str]):
        """Rule 25: Check for POST/PUT/DELETE routes missing CSRF protection"""
        # Check if function is a state-changing route
        is_state_changing = any(dec.lower() in ['post', 'put', 'delete', 'patch'] for dec in decorators)
        
        if is_state_changing:
            # Check if CSRF exemption is present (which is a red flag)
            has_csrf_exempt = any('csrf_exempt' in dec.lower() for dec in decorators)
            
            if has_csrf_exempt:
                self.findings.append({
                    "file": self.filename,
                    "lineno": node.lineno,
                    "code": "MISSING_CSRF",
                    "message": f"CSRF protection disabled: Route '{node.name}' has @csrf_exempt decorator\n💡 Remove @csrf_exempt and ensure CSRF tokens are validated on state-changing requests",
                    "severity": "ERROR"
                })
    
    # ============================================
    # HELPER METHODS
    # ============================================
    
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
    
    def _get_decorator_name(self, decorator) -> str:
        """Extract decorator name from AST node"""
        if isinstance(decorator, ast.Name):
            return decorator.id
        if isinstance(decorator, ast.Attribute):
            return self._get_call_name(decorator)
        if isinstance(decorator, ast.Call):
            return self._get_call_name(decorator.func)
        return ""
    
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
    
    def _uses_weak_random(self, node: ast.Call) -> bool:
        """Check if weak random is used in this call"""
        for arg in node.args:
            if isinstance(arg, ast.Call):
                func_name = self._get_call_name(arg.func)
                if func_name and 'random.' in func_name and 'secrets.' not in func_name:
                    return True
        return False
    
    def _in_rendering_context(self) -> bool:
        """Check if we're in a template rendering context"""
        return any('render' in name.lower() for name in self.call_names_seen[-5:])
    
    def _in_session_token_context(self) -> bool:
        """Check if we're in a session or token generation context"""
        # Check recent function names and variable assignments
        recent_context = ' '.join(self.call_names_seen[-10:]).lower()
        return any(x in recent_context for x in ['session', 'token', 'auth', 'secret', 'key'])
    
    def _extract_sql_string(self, node: ast.Call) -> Optional[str]:
        """Extract SQL string from execute/executemany call arguments"""
        if not node.args:
            return None
        
        first_arg = node.args[0]
        
        # Variable reference - look up the stored value
        if isinstance(first_arg, ast.Name):
            var_name = first_arg.id
            if var_name in self.variable_values:
                # Recursively extract from the stored value
                stored_value = self.variable_values[var_name]
                return self._extract_sql_from_expr(stored_value)
        
        # Direct extraction
        return self._extract_sql_from_expr(first_arg)
    
    def _extract_sql_from_expr(self, expr) -> Optional[str]:
        """Extract SQL string from an expression node"""
        # Direct string constant
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return expr.value
        
        # String concatenation (BinOp with Add)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            sql_parts = self._extract_string_from_binop(expr)
            if sql_parts:
                return ''.join(sql_parts)  # Don't add spaces - preserve original
        
        # f-string (JoinedStr)
        if isinstance(expr, ast.JoinedStr):
            sql_parts = []
            for value in expr.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    sql_parts.append(value.value)
            if sql_parts:
                return ''.join(sql_parts)
        
        # .format() call
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
            if expr.func.attr == 'format' and isinstance(expr.func.value, ast.Constant):
                if isinstance(expr.func.value.value, str):
                    return expr.func.value.value
        
        return None
    
    def _extract_string_from_binop(self, node: ast.BinOp) -> List[str]:
        """Recursively extract string constants from binary operations"""
        parts = []
        
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            parts.append(node.left.value)
        elif isinstance(node.left, ast.BinOp):
            parts.extend(self._extract_string_from_binop(node.left))
        
        if isinstance(node.right, ast.Constant) and isinstance(node.right.value, str):
            parts.append(node.right.value)
        elif isinstance(node.right, ast.BinOp):
            parts.extend(self._extract_string_from_binop(node.right))
        
        return parts
