#!/usr/bin/env python3
"""
LR and AST Compiler for Detecting Malicious and Vulnerability Detector In Python Language

code_detector.py - FOUR-PHASE COMPILER for Vulnerability Detection

This is the main orchestrator that coordinates the four compilation phases:
PHASE 1: LEXICAL ANALYSIS (phase1_lexer.py) - Tokenize Python source code
PHASE 2: SYNTAX ANALYSIS (phase2_ASTparser.py) - Build Abstract Syntax Tree
PHASE 3: SEMANTIC ANALYSIS (phase3_semantic.py) - Detect vulnerabilities via AST traversal
PHASE 4: GRAMMAR ANALYSIS (phase4_LRparser.py) - Formal grammar pattern matching

The four phases are separated into individual modules for proper compiler architecture.
"""

import os
import sys
import json
from typing import List, Dict, Any

# Import the four compilation phases
from phase1_lexer import PythonLexer, Token, TokenType
from phase2_ASTparser import PythonParser
from phase3_semantic import SemanticAnalyzer
from phase4_LRparser import VulnerabilityParser

# ---------- Utility types ----------
SEVERITIES = ("INFO", "WARNING", "ERROR")

class CompilerPhases:
    """
    Manages the four phases of compilation:
    1. Lexical Analysis (Tokenization)
    2. Syntax Analysis (Parsing to AST)
    3. Semantic Analysis (Vulnerability Detection via AST)
    4. Grammar Analysis (LR Parser Pattern Matching)
    """
    
    def __init__(self, source: str, filename: str):
        self.source = source
        self.filename = filename
        self.tokens: List[Token] = []
        self.ast_tree = None
        self.grammar_parser = None
        self.phase_stats = {
            "lexical": {},
            "syntax": {},
            "semantic": {},
            "grammar": {}
        }
    
    def phase1_lexical_analysis(self) -> List[Token]:
        """
        PHASE 1: LEXICAL ANALYSIS
        Tokenize the source code into a stream of tokens.
        """
        lexer = PythonLexer(self.source)
        self.tokens = lexer.tokenize()
        
        # Gather statistics
        self.phase_stats["lexical"] = {
            "total_tokens": len(self.tokens),
            "keywords": len([t for t in self.tokens if t.type == TokenType.KEYWORD]),
            "identifiers": len([t for t in self.tokens if t.type == TokenType.IDENTIFIER]),
            "strings": len([t for t in self.tokens if t.type == TokenType.STRING]),
            "numbers": len([t for t in self.tokens if t.type == TokenType.NUMBER]),
            "operators": len([t for t in self.tokens if t.type.name.endswith('ASSIGN') or t.type in {
                TokenType.PLUS, TokenType.MINUS, TokenType.STAR, TokenType.SLASH,
                TokenType.EQ, TokenType.NE, TokenType.LT, TokenType.GT
            }]),
            "comments": len([t for t in self.tokens if t.type == TokenType.COMMENT]),
        }
        
        return self.tokens
    
    def phase2_syntax_analysis(self):
        """
        PHASE 2: SYNTAX ANALYSIS (PARSING)
        Parse tokens into Abstract Syntax Tree (AST).
        Uses Python's built-in parser for robust syntax handling.
        """
        try:
            parser = PythonParser(self.source, self.filename)
            self.ast_tree = parser.parse()
            
            # Get statistics from parser
            self.phase_stats["syntax"] = parser.get_statistics()
            
            return self.ast_tree
            
        except SyntaxError as e:
            self.phase_stats["syntax"] = {
                "error": str(e),
                "line": e.lineno,
                "offset": e.offset
            }
            raise
    
    def phase3_semantic_analysis(self) -> List[Dict[str, Any]]:
        """
        PHASE 3: SEMANTIC ANALYSIS
        Analyze AST for vulnerability patterns and code quality issues.
        
        HYBRID APPROACH:
        - Uses Phase 1 tokens for fast pre-screening
        - Only analyzes files with suspicious keywords
        - Improves performance by early rejection of safe files
        - Injects Phase 4 grammar parser for formal pattern matching
        """
        if self.ast_tree is None:
            raise ValueError("Must run phase2_syntax_analysis before semantic analysis")
        
        # Initialize Phase 4 grammar parser
        self.grammar_parser = VulnerabilityParser()
        
        # Pass tokens from Phase 1 for pre-screening and grammar parser from Phase 4
        analyzer = SemanticAnalyzer(self.filename, tokens=self.tokens, grammar_parser=self.grammar_parser)
        
        # Check if file warrants full analysis
        if not analyzer.should_analyze():
            # File has no suspicious tokens - skip expensive AST traversal
            self.phase_stats["semantic"] = {
                "prescreened": True,
                "suspicious_tokens": 0,
                "vulnerabilities_found": 0,
                "errors": 0,
                "warnings": 0,
                "info": 0,
                "functions_analyzed": 0,
                "imports_found": 0,
                "analysis_skipped": "No suspicious tokens detected"
            }
            self.phase_stats["grammar"] = {
                "patterns_matched": 0,
                "grammar_rules_applied": 0
            }
            return []
        
        # Suspicious tokens found - perform full AST analysis
        analyzer.visit(self.ast_tree)
        
        # Gather semantic analysis statistics
        self.phase_stats["semantic"] = {
            "prescreened": True,
            "suspicious_tokens": len(analyzer.suspicious_tokens),
            "vulnerabilities_found": len(analyzer.findings),
            "errors": len([f for f in analyzer.findings if f.get('severity') == 'ERROR']),
            "warnings": len([f for f in analyzer.findings if f.get('severity') == 'WARNING']),
            "info": len([f for f in analyzer.findings if f.get('severity') == 'INFO']),
            "functions_analyzed": len(analyzer.function_complexity),
            "imports_found": len(analyzer.imports),
        }
        
        # Gather grammar parser statistics (Phase 4)
        self.phase_stats["grammar"] = {
            "patterns_matched": len(self.grammar_parser.findings),
            "grammar_rules_applied": len(self.grammar_parser.parse_traces),
        }
        
        return analyzer.findings
    
    def get_phase_report(self) -> Dict[str, Any]:
        """
        Get a comprehensive report of all four compilation phases.
        """
        return {
            "filename": self.filename,
            "phases": {
                "phase1_lexical_analysis": self.phase_stats["lexical"],
                "phase2_syntax_analysis": self.phase_stats["syntax"],
                "phase3_semantic_analysis": self.phase_stats["semantic"],
                "phase4_grammar_analysis": self.phase_stats["grammar"],
            }
        }


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
        """
        Run three-phase compilation analysis on a Python file.
        """
        try:
            # Initialize three-phase compiler
            compiler = CompilerPhases(source, filename)
            
            # ============================================
            # PHASE 1: LEXICAL ANALYSIS
            # ============================================
            print(f"\n[PHASE 1] Lexical Analysis: {filename}")
            tokens = compiler.phase1_lexical_analysis()
            lex_stats = compiler.phase_stats["lexical"]
            print(f"  > Tokenized {lex_stats['total_tokens']} tokens: "
                  f"{lex_stats['keywords']} keywords, {lex_stats['identifiers']} identifiers, "
                  f"{lex_stats['strings']} strings, {lex_stats['numbers']} numbers")
            
            # ============================================
            # PHASE 2: SYNTAX ANALYSIS (PARSING)
            # ============================================
            print(f"[PHASE 2] Syntax Analysis (Parsing): {filename}")
            ast_tree = compiler.phase2_syntax_analysis()
            syn_stats = compiler.phase_stats["syntax"]
            print(f"  > Built AST with {syn_stats['total_nodes']} nodes: "
                  f"{syn_stats['functions']} functions, {syn_stats['classes']} classes, "
                  f"{syn_stats['calls']} function calls")
            
            # ============================================
            # PHASE 3: SEMANTIC ANALYSIS
            # ============================================
            print(f"[PHASE 3] Semantic Analysis (Vulnerability Detection): {filename}")
            findings = compiler.phase3_semantic_analysis()
            sem_stats = compiler.phase_stats["semantic"]
            print(f"  > Found {sem_stats['vulnerabilities_found']} issues: "
                  f"{sem_stats['errors']} errors, {sem_stats['warnings']} warnings, "
                  f"{sem_stats['info']} info\n")
            
            # Add findings to reports
            for f in findings:
                self.reports.append(f)
            
        except SyntaxError as se:
            print(f"[PHASE 2] Syntax Error in {filename} at line {se.lineno}")
            self.reports.append({
                "file": filename,
                "lineno": se.lineno,
                "code": "SYNTAX_ERROR",
                "message": f"Syntax error while parsing: {se.msg}",
                "severity": "ERROR",
                "phase": "PHASE_2_SYNTAX"
            })
            return

    def _print_report(self):
        if not self.reports:
            print("\n" + "="*70)
            print("[+] COMPILATION COMPLETE: No issues found.")
            print("="*70)
            return

        severity_rank = {"ERROR": 3, "WARNING": 2, "INFO": 1}
        sorted_reports = sorted(self.reports,
                                key=lambda r: (-severity_rank.get(r.get("severity", "INFO"), 1),
                                               r.get("file", ""),
                                               r.get("lineno", 0)))
        errors = sum(1 for r in sorted_reports if r.get("severity") == "ERROR")
        warns = sum(1 for r in sorted_reports if r.get("severity") == "WARNING")
        infos = sum(1 for r in sorted_reports if r.get("severity") == "INFO")
        
        print("\n" + "="*70)
        print("FOUR-PHASE COMPILATION RESULTS")
        print("="*70)
        print(f"[!] Findings: {errors} ERROR(s), {warns} WARNING(s), {infos} INFO(s)")
        print("="*70)

        for r in sorted_reports:
            f = r.get("file", "<unknown>")
            ln = r.get("lineno", 0)
            sev = r.get("severity", "INFO")
            code = r.get("code", "ISSUE")
            msg = r.get("message", "")
            # Remove unicode characters that might cause encoding issues
            msg = msg.encode('ascii', 'ignore').decode('ascii')
            print(f"{sev:7} {f}:{ln:4} {code:20} - {msg}")

        try:
            j = json.dumps(sorted_reports, indent=2)
            print("\n=== JSON REPORT ===")
            print(j)
        except Exception:
            pass
    
    def _record_finding(self, filename: str, lineno: int, code: str, message: str, severity: str):
        """Helper method to record a finding"""
        self.reports.append({
            "file": filename,
            "lineno": lineno,
            "code": code,
            "message": message,
            "severity": severity
        })


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
